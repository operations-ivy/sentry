"""The UPnP watch against a fake router: an IGD description and SOAP control
over real HTTP, and an SSDP responder on loopback."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from overwatch import upnp as U
from overwatch.hub import Hub
from overwatch.metrics import render, upnp_registry
from overwatch.scanner import make_server, state

from .helpers import get_json, serve

SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:2"
DESC = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceList><device><deviceList><device>
<serviceList><service><serviceType>{SERVICE}</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList>
</device></deviceList></device></deviceList></device></root>"""


def entry(m):
    return (
        f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
        f'<u:GetGenericPortMappingEntryResponse xmlns:u="{SERVICE}">'
        f"<NewRemoteHost></NewRemoteHost><NewExternalPort>{m[1]}</NewExternalPort><NewProtocol>{m[0]}</NewProtocol>"
        f"<NewInternalPort>{m[3]}</NewInternalPort><NewInternalClient>{m[2]}</NewInternalClient>"
        f"<NewEnabled>1</NewEnabled><NewPortMappingDescription>{m[4]}</NewPortMappingDescription>"
        f"<NewLeaseDuration>{m[5]}</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"
    )


def fault(code, text):
    return (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>'
        "<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>"
        f'<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode>'
        f"<errorDescription>{text}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
    ).encode()


class FakeRouter:
    """The router's HTTP side: /rootDesc.xml and its SOAP control URL."""

    def __init__(self):
        self.table = []  # (proto, external, client, internal, description, lease)
        self.down = False
        router = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if router.down:
                    return self.send_error(503)
                self._send(200, DESC.encode(), "text/xml")

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"])).decode()
                assert self.headers["SOAPAction"] == f'"{SERVICE}#GetGenericPortMappingEntry"'
                i = int(body.split("<NewPortMappingIndex>")[1].split("<")[0])
                if router.down:  # ActionFailed, as a struggling router answers
                    return self._send(500, fault(501, "ActionFailed"), "text/xml")
                if i >= len(router.table):  # the end of the table, as the real router answers
                    return self._send(500, fault(713, "SpecifiedArrayIndexInvalid"), "text/xml")
                self._send(200, entry(router.table[i]).encode(), "text/xml")

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.base, self.stop = serve(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        self.location = self.base + "/rootDesc.xml"


@pytest.fixture
def router():
    r = FakeRouter()
    yield r
    r.stop()


def gateway(router):
    g = U.Gateway("127.0.0.1", timeout=2)
    g.connect(router.location)
    return g


def test_reads_the_table(router):
    router.table = [("UDP", 3074, "192.168.1.50", 3074, "Xbox", 0), ("TCP", 8080, "192.168.1.66", 80, "cam", 3600)]
    maps = gateway(router).mappings()
    assert [m.key for m in maps] == ["UDP/3074", "TCP/8080"]
    assert maps[1].client == "192.168.1.66" and maps[1].internal_port == 80 and maps[1].lease == 3600
    assert maps[0].enabled and maps[0].description == "Xbox"


def test_empty_table(router):
    assert gateway(router).mappings() == []


def test_new_forward_alerts_and_allowed_ones_dont():
    w = U.UpnpWatch(U.parse_allow("UDP/3074@192.168.1.50"))
    xbox = U.Mapping(3074, "UDP", "192.168.1.50", 3074, "Xbox", True, 0)
    assert w.update([xbox], now=100) == []
    assert w.get(now=100)["alerts"] == []
    cam = U.Mapping(8080, "TCP", "192.168.1.66", 80, "cam", True, 0)
    assert w.update([xbox, cam], now=160) == [cam]
    st = w.get(now=160)
    assert st["unexpected"] == 1 and len(st["mappings"]) == 2
    assert "opened: internet TCP 8080 → 192.168.1.66:80" in st["alerts"][0]["detail"]
    assert w.opened == 1
    # Still open next poll: no second alert.
    assert w.update([xbox, cam], now=220) == []
    assert len(w.get(now=220)["alerts"]) == 1
    # Alerts age out of the page after 30 minutes; the forward stays unexpected.
    assert w.get(now=160 + 1801)["alerts"] == [] and w.get(now=2000)["unexpected"] == 1


def test_forwards_already_open_at_start_alert_as_found():
    w = U.UpnpWatch([])
    cam = U.Mapping(8080, "TCP", "192.168.1.66", 80, "", True, 0)
    w.update([cam], now=10)
    assert w.get(now=10)["alerts"][0]["detail"].startswith("found open:")
    assert w.opened == 0  # not opened while watching


def test_the_same_port_moved_to_another_device_alerts_again():
    w = U.UpnpWatch([])
    w.update([U.Mapping(8080, "TCP", "192.168.1.66", 80, "", True, 0)], now=1)
    fresh = w.update([U.Mapping(8080, "TCP", "192.168.1.99", 80, "", True, 0)], now=2)
    assert [m.client for m in fresh] == ["192.168.1.99"]


def test_allow_rules():
    rules = U.parse_allow(" udp/3074@192.168.1.50, TCP/*@192.168.1.60 ")
    assert U.allowed(U.Mapping(3074, "UDP", "192.168.1.50", 3074, "", True, 0), rules)
    assert not U.allowed(U.Mapping(3074, "UDP", "192.168.1.51", 3074, "", True, 0), rules)
    assert U.allowed(U.Mapping(1234, "TCP", "192.168.1.60", 1, "", True, 0), rules)
    assert U.parse_allow("") == []
    with pytest.raises(ValueError):
        U.parse_allow("3074")


def ssdp_responder(location, reply_from="127.0.0.1"):
    """Answers one M-SEARCH on loopback; returns (port, thread)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((reply_from, 0))
    sock.settimeout(3)

    def run():
        try:
            _, addr = sock.recvfrom(2048)
            sock.sendto(f"HTTP/1.1 200 OK\r\nST: x\r\nLOCATION: {location}\r\n\r\n".encode(), addr)
        except TimeoutError:
            pass
        finally:
            sock.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return sock.getsockname()[1], t


def test_discovery_believes_the_router(router):
    port, _ = ssdp_responder(router.location)
    g = U.Gateway("127.0.0.1", timeout=2, ssdp_port=port)
    assert g.discover() == router.location


def test_discovery_refuses_a_location_off_the_router():
    # Something answering for the router, but pointing elsewhere: refused.
    port, _ = ssdp_responder("http://10.9.9.9:5000/rootDesc.xml")
    g = U.Gateway("127.0.0.1", timeout=1, ssdp_port=port)
    with pytest.raises(OSError):
        g.discover()


def test_router_down_says_so_and_recovers(router):
    w = U.UpnpWatch([])
    g = gateway(router)
    router.table = [("TCP", 8080, "192.168.1.66", 80, "cam", 0)]
    w.update(g.mappings())
    router.down = True
    # A failing router is a failure, not an empty table.
    with pytest.raises(U.urllib.error.HTTPError):
        g.mappings()
    w.failed("router not answering UPnP")
    st = state(w)
    assert not st["scanning"] and st["error"] == "router not answering UPnP"
    assert len(st["mappings"]) == 1  # the last table stays on the page
    router.down = False
    w.update(gateway(router).mappings())
    assert state(w)["scanning"]


def test_http_and_metrics(router):
    w, hub = U.UpnpWatch(U.parse_allow("UDP/3074")), Hub()
    w.update(
        [
            U.Mapping(3074, "UDP", "192.168.1.50", 3074, "Xbox", True, 0),
            U.Mapping(22, "TCP", "192.168.1.66", 22, "", True, 0),
        ]
    )
    base, stop = serve(make_server(w, hub, "127.0.0.1", 0, registry=upnp_registry))
    try:
        code, body = get_json(base + "/api/state")
        assert code == 200 and body["unexpected"] == 1 and body["scanning"]
        text = render(upnp_registry(w, hub)).decode()
        assert "overwatch_upnp_mappings 2.0" in text
        assert "overwatch_upnp_unexpected 1.0" in text
        assert "overwatch_upnp_reachable 1.0" in text
        assert "192.168" not in text  # counts only
    finally:
        stop()

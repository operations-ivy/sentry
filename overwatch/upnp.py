"""The UPnP watch: the router's port forwards, as UPnP has set them up.

UPnP (IGD) lets any device on the LAN ask the router to forward an internet
port to it, with no password and no prompt. That's how game consoles and some
apps get through the router, and how malware on one device could open the
house to the internet without anyone noticing. This lists the router's UPnP
port mappings every minute and raises an alert for each one that appears
and isn't on the allowed list (OVERWATCH_UPNP_ALLOW).

The router is found the way UPnP clients find it (SSDP, multicast to the LAN,
hence the host network), but only an answer from the router's own address,
pointing at the router's own address, is believed: another device answering
as the "router" with an empty list can't hide a forward.

The page shows each forward in full (external port, the device and port it
reaches, its description): it's LAN-only, like the router's own pages, and
that's what's needed to act on one. Metrics are counts only.

    GET /api/stream, /api/state, /health, /ready, /metrics   as the scanner's
"""

from __future__ import annotations

import fnmatch
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass

import brick_observe

from . import tracing

log = brick_observe.get_logger(__name__)

SSDP = ("239.255.255.250", 1900)
IGD_TYPES = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
)
DEVICE_NS = "{urn:schemas-upnp-org:device-1-0}"
MAX_MAPPINGS = 256  # the router's table is small; a runaway list stops here
END_OF_TABLE = re.compile(rb"<errorCode>\s*713\s*</errorCode>")


@dataclass(frozen=True)
class Mapping:
    external_port: int
    protocol: str
    client: str
    internal_port: int
    description: str
    enabled: bool
    lease: int  # seconds left; 0 is permanent

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.external_port}"

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "external_port": self.external_port,
            "protocol": self.protocol,
            "client": self.client,
            "internal_port": self.internal_port,
            "description": self.description,
            "enabled": self.enabled,
            "lease": self.lease,
        }


def parse_allow(text: str) -> list[tuple[str, str, str]]:
    """OVERWATCH_UPNP_ALLOW: comma-separated PROTO/PORT[@CLIENT] entries, each
    part a glob: "UDP/3074@192.168.1.50" (a console), "TCP/*@192.168.1.60".
    Empty: nothing is allowed, every forward alerts."""
    rules = []
    for item in (text or "").split(","):
        item = item.strip()
        if not item:
            continue
        rule, _, client = item.partition("@")
        proto, _, port = rule.partition("/")
        if not proto or not port:
            raise ValueError(f"OVERWATCH_UPNP_ALLOW: {item!r} isn't PROTO/PORT[@CLIENT]")
        rules.append((proto.upper(), port, client or "*"))
    return rules


def allowed(m: Mapping, rules: list[tuple[str, str, str]]) -> bool:
    def match(rule: tuple[str, str, str]) -> bool:
        proto, port, client = rule
        values = (m.protocol, str(m.external_port), m.client)
        return all(fnmatch.fnmatchcase(v, pattern) for v, pattern in zip(values, (proto, port, client)))

    return any(match(r) for r in rules)


class Gateway:
    """The router's IGD: found by SSDP, then asked over SOAP."""

    def __init__(self, router: str, timeout: float = 5, ssdp_port: int = 1900):
        self.router, self.timeout, self.ssdp_port = router, timeout, ssdp_port
        self.control: str | None = None
        self.service: str | None = None

    def discover(self) -> str:
        """The router's description URL. Asks the LAN, and the router directly
        too, and believes only the router."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(self.timeout)
        try:
            for st in IGD_TYPES:
                msg = (
                    f'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
                    f"MX: 2\r\nST: {st}\r\n\r\n"
                ).encode()
                try:
                    sock.sendto(msg, SSDP)
                except OSError:  # no multicast route; the direct ask still goes
                    pass
                sock.sendto(msg, (self.router, self.ssdp_port))
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                try:
                    data, (addr, _) = sock.recvfrom(4096)
                except TimeoutError:
                    break
                location = location_from(data)
                if addr == self.router and location and urllib.parse.urlsplit(location).hostname == self.router:
                    return location
        finally:
            sock.close()
        raise OSError(f"no UPnP gateway answered from {self.router}")

    def connect(self, location: str | None = None) -> None:
        location = location or self.discover()
        with urllib.request.urlopen(location, timeout=self.timeout) as r:
            desc = r.read()
        self.service, path = wan_service(desc)
        self.control = urllib.parse.urljoin(location, path)
        if urllib.parse.urlsplit(self.control).hostname != self.router:
            raise OSError("the gateway's control URL isn't on the router")

    def call(self, action: str, args: str = "") -> str:
        body = (
            '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{self.service}">{args}</u:{action}></s:Body></s:Envelope>'
        ).encode()
        req = urllib.request.Request(
            self.control,
            body,
            {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{self.service}#{action}"'},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    def mappings(self) -> list[Mapping]:
        """Every mapping, by index until the router says there are no more: the
        first index past the end gets UPnP error 713 (a SOAP fault, HTTP 500)."""
        if not self.control:
            self.connect()
        out = []
        for i in range(MAX_MAPPINGS):
            try:
                xml = self.call("GetGenericPortMappingEntry", f"<NewPortMappingIndex>{i}</NewPortMappingIndex>")
            except urllib.error.HTTPError as e:
                # Only UPnP error 713 (SpecifiedArrayIndexInvalid) is the end of
                # the table; any other fault is a failure, never "no forwards".
                if e.code == 500 and END_OF_TABLE.search(e.read() or b""):
                    break
                raise
            out.append(mapping_from(xml))
        return out


def location_from(data: bytes) -> str | None:
    m = re.search(rb"(?im)^location:\s*(\S+)", data)
    return m.group(1).decode() if m else None


def wan_service(desc: bytes) -> tuple[str, str]:
    """(service type, control path) of the description's WAN connection."""
    root = ET.fromstring(desc)
    for svc in root.iter(f"{DEVICE_NS}service"):
        stype = svc.findtext(f"{DEVICE_NS}serviceType") or ""
        if "WANIPConnection" in stype or "WANPPPConnection" in stype:
            return stype, svc.findtext(f"{DEVICE_NS}controlURL") or ""
    raise OSError("the gateway has no WAN connection service")


def _field(xml: str, name: str) -> str:
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S)
    return m.group(1).strip() if m else ""


def mapping_from(xml: str) -> Mapping:
    def number(name: str) -> int:
        try:
            return int(_field(xml, name) or 0)
        except ValueError:
            return 0

    return Mapping(
        external_port=number("NewExternalPort"),
        protocol=_field(xml, "NewProtocol").upper(),
        client=_field(xml, "NewInternalClient"),
        internal_port=number("NewInternalPort"),
        description=_field(xml, "NewPortMappingDescription"),
        enabled=_field(xml, "NewEnabled") in ("1", "true"),
        lease=number("NewLeaseDuration"),
    )


class UpnpWatch:
    """What the router's UPnP table holds, and what changed."""

    def __init__(self, allow: list[tuple[str, str, str]] | None = None, alert_seconds: float = 1800):
        self.allow = allow or []
        self.alert_seconds = alert_seconds
        self.mappings: dict[str, Mapping] = {}
        self.first: dict[str, float] = {}  # when each mapping was first seen
        self.alerts: list[dict] = []
        self.alert_counts: Counter = Counter()
        self.opened = 0  # mappings that appeared after the first poll
        self.polls: Counter = Counter()
        self.scanning = False  # the last poll got the table
        self.polled = False
        self.error = ""
        self._lock = threading.Lock()

    def update(self, mappings: list[Mapping], now: float | None = None) -> list[Mapping]:
        """A fresh table from the router; returns the new unexpected mappings."""
        now = time.time() if now is None else now
        fresh = []
        with self._lock:
            current = {m.key: m for m in mappings}
            for key, m in current.items():
                old = self.mappings.get(key)
                if old is None or (old.client, old.internal_port) != (m.client, m.internal_port):
                    self.first[key] = now
                    if self.polled:
                        self.opened += 1
                    if not allowed(m, self.allow):
                        fresh.append(m)
                        when = "found open" if not self.polled else "opened"
                        self.alert_counts["unexpected"] += 1
                        with brick_observe.span("overwatch alert", **{"overwatch.kind": "upnp"}):
                            self.alerts.append(
                                {
                                    "kind": "upnp",
                                    "label": "UPnP port forward",
                                    "confidence": "high",
                                    "at": now,
                                    "detail": f"{when}: internet {m.protocol} {m.external_port} → "
                                    f"{m.client}:{m.internal_port}" + (f" “{m.description}”" if m.description else ""),
                                    **tracing.carried(),
                                }
                            )
                            log.info(
                                "overwatch upnp alert",
                                mapping=m.key,
                                description=m.description,
                                client=m.client,
                                internal_port=m.internal_port,
                            )
            for key in set(self.mappings) - set(current):
                self.first.pop(key, None)
            self.mappings = current
            self.polled, self.scanning, self.error = True, True, ""
            self.polls["ok"] += 1
        return fresh

    def failed(self, error: str) -> None:
        with self._lock:
            self.scanning, self.error = False, error
            self.polls["error"] += 1

    def unexpected(self) -> list[Mapping]:
        return [m for m in self.mappings.values() if not allowed(m, self.allow)]

    def panel(self, st: dict) -> dict:
        """This feed in the page's common shape (panel.py)."""
        from . import panel
        return panel.upnp(st)

    def get(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self._lock:
            self.alerts = [a for a in self.alerts if now - a["at"] < self.alert_seconds]
            return {
                "error": self.error,
                "polled": self.polled,
                "allowed_rules": len(self.allow),
                "mappings": [
                    {**m.as_dict(), "allowed": allowed(m, self.allow), "since": self.first.get(k)}
                    for k, m in sorted(self.mappings.items())
                ],
                "unexpected": len(self.unexpected()),
                "alerts": list(self.alerts),
            }


def poll_forever(watch: UpnpWatch, hub, gateway: Gateway, interval: float = 60) -> None:
    """Ask the router every `interval` seconds. If it doesn't answer (rebooting,
    a new port after a reboot), find it again next time."""
    from .scanner import state

    while True:
        try:
            with brick_observe.span("upnp poll"):
                watch.update(gateway.mappings())
        except Exception as e:  # router rebooting, UPnP turned off, network blip
            if watch.scanning or not watch.error:
                log.warning("upnp poll failed", error=str(e))
            watch.failed("router not answering UPnP")
            gateway.control = None  # rediscover: its port changes when it reboots
        hub.publish(state(watch))
        end = time.monotonic() + interval
        while time.monotonic() < end:  # alerts age out on the page
            time.sleep(1)
            hub.publish(state(watch))


def main(host: str, port: int, router: str, allow: str, interval: float = 60) -> None:
    from .hub import Hub
    from .metrics import upnp_registry
    from .scanner import make_server

    rules = parse_allow(allow)
    watch, hub = UpnpWatch(rules), Hub()
    log.info("upnp watch listening", host=host, port=port, router=router, allowed=len(rules))
    threading.Thread(target=poll_forever, args=(watch, hub, Gateway(router), interval), daemon=True).start()
    make_server(watch, hub, host, port, registry=upnp_registry).serve_forever()

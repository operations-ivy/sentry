"""The scanner: listens to Bluetooth LE through the host's BlueZ (over the
D-Bus system socket, so the container needs no privileges) and pushes what it
hears to the web pods the moment it changes.

There is one scanner, pinned to the node whose radio should listen: it is a
place, not a replica. Its learned normals live in memory, so a restart
learns the house again.

    GET /api/stream  Server-Sent Events: the state now, then every change
    GET /api/state   the state now (counts per kind, alerts, learning, error)
    GET /health      the process is up
    GET /ready       BlueZ is scanning
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import brick_observe

from . import metrics, tracing
from .hub import Hub, stream
from .watch import Watch, classify, describe

log = brick_observe.get_logger(__name__)


def address_type(device) -> str:
    """public or random (a rotating, private address), from BlueZ's properties."""
    try:
        return str(device.details["props"].get("AddressType", ""))
    except (AttributeError, KeyError, TypeError):
        return ""


def state(watch) -> dict:
    """What a watch publishes: its own fields, plus `panel`, the same feed in
    the common shape the page renders (panel.py)."""
    st = {"scanning": watch.scanning, **watch.get()}
    if hasattr(watch, "panel"):
        st["panel"] = watch.panel(st)
    return st


def scan_forever(watch: Watch, hub: Hub, retry_seconds: float = 30) -> None:
    """Scan forever (a daemon thread), publishing on every advert that changes
    what the page shows and on a one-second tick for the clock-driven changes
    (devices leaving, alerts, the learning countdown). Without an adapter or
    bluetoothd, say so in the state and keep retrying."""
    from bleak import BleakScanner

    def on_advert(device, adv) -> None:
        mfr, services, sdata = dict(adv.manufacturer_data), list(adv.service_uuids), dict(adv.service_data)
        atype = address_type(device)
        kind = classify(adv.local_name, mfr, services, sdata, device.address, atype)
        if kind:
            details = describe(kind, adv.local_name, mfr, services, sdata, adv.tx_power)
            watch.advert(device.address, kind, adv.rssi, details=details, address_type=atype)
            hub.publish(state(watch))

    async def scan() -> None:
        async with BleakScanner(on_advert):
            watch.error, watch.scanning = "", True
            log.info("scanning")
            while True:
                watch.tick()
                hub.publish(state(watch))
                await asyncio.sleep(1)

    while True:
        try:
            asyncio.run(scan())
        except Exception as e:  # no adapter, bluetoothd restarting, socket missing
            watch.error, watch.scanning = "no Bluetooth", False
            watch.failures += 1
            hub.publish(state(watch))
            log.warning("scan failed", error=str(e))
        time.sleep(retry_seconds)


def make_server(
    watch, hub: Hub, host: str, port: int, heartbeat: float = 5, registry=metrics.ble_registry
) -> ThreadingHTTPServer:
    """The scanner's server; the Wi-Fi watch's too, with its own `registry`."""
    reg = registry(watch, hub)

    class Handler(brick_observe.httpserver.Observed, BaseHTTPRequestHandler):
        routes = {"/api/state", "/api/stream"}
        skip = tracing.NOT_TRACED
        metrics_registry = reg

        def do_GET(self):
            if self.path == "/api/stream":
                hub.publish(state(watch))  # never an empty first event
                self._stream()
            elif self.path == "/api/state":
                body = {"now": time.time(), **state(watch)}
                self._send(200, json.dumps(body).encode(), "application/json")
            elif self.path == "/health":
                self._send(200, b"ok\n")
            elif self.path == "/ready":
                self._send(*((200, b"scanning\n") if watch.scanning else (503, b"not scanning\n")))
            elif self.path == "/metrics":
                self._send(200, metrics.render(reg), metrics.CONTENT_TYPE_LATEST)
            else:
                self._send(404, b"not found\n")

        def _stream(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            def write(chunk: bytes) -> None:
                self.wfile.write(chunk)
                self.wfile.flush()

            try:
                stream(hub, write, heartbeat)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the listener went away

        def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((host, port), Handler)


def main(host: str, port: int, learn_seconds: float) -> None:
    watch, hub = Watch(learn_seconds=learn_seconds), Hub()
    threading.Thread(target=scan_forever, args=(watch, hub), daemon=True).start()
    log.info("scanner listening", host=host, port=port)
    make_server(watch, hub, host, port).serve_forever()

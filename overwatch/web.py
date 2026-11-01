"""The web pods: the page at overwatch.brick.nozdormu.cloud and its stream.

They hold no radio and no state of their own: each one keeps a Server-Sent
Events connection to every feed (OVERWATCH_FEEDS: the Bluetooth scanner, the
Wi-Fi and UPnP watches, whatever else is added) and passes every change on
to its browsers the moment it arrives, so any replica gives the same page.
Every feed's state carries a `panel` in one shape (panel.py) that the page
renders, so a new feed needs no change here or in the page.
Ready once the first state has arrived, so a rollout keeps the old pods
serving until a new one has something to show. After that a pod stays ready
if the scanner goes away, and the page says so.

    GET /            the page
    GET /api/stream  Server-Sent Events: {feeds: [{name, error, state}, ...]} now, then each change
    GET /api/state   the same, once, plus `now`
    GET /health      the process is up
    GET /ready       has heard from the scanner at least once
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import brick_observe

from . import metrics, tracing
from .hub import Hub, events, stream

log = brick_observe.get_logger(__name__)
PAGE = (Path(__file__).parent / "static" / "index.html").read_bytes()


class Upstream:
    """The scanner's stream, relayed into `hub`. The scanner sends a heartbeat
    every few seconds, so silence for `timeout` means it's gone."""

    def __init__(self, url: str, hub: Hub, timeout: float = 15, retry: float = 1, on_change=None, name="scanner"):
        self.url, self.hub, self.timeout, self.retry = url.rstrip("/") + "/api/stream", hub, timeout, retry
        self.name = name
        self.scanner: dict | None = None
        self.error = ""
        self.ready = False
        self.drops = 0  # times the stream ended or failed
        self.relayed: set[str] = set()  # alerts already traced
        self.on_change = on_change or (lambda: hub.publish(self.state()))
        self.on_change()

    def state(self) -> dict:
        return {"error": self.error, "scanner": self.scanner}

    def follow_once(self) -> None:
        """Follow the stream until it ends or fails."""
        try:
            with urllib.request.urlopen(self.url, timeout=self.timeout) as r:
                for data in events(r):
                    if data is None:
                        continue  # heartbeat
                    self.scanner = json.loads(data)
                    self.relayed = tracing.relayed(self.name, self.scanner, self.relayed, self.hub.clients)
                    if self.error:
                        log.info("feed back", feed=self.name)
                    self.error, self.ready = "", True
                    self.on_change()
        except Exception as e:  # scanner restarting, moved, or not up yet
            if not self.error:
                log.warning("feed unreachable", feed=self.name, error=str(e))
        self.error = f"{self.name} unreachable"
        self.drops += 1
        self.on_change()

    def run(self) -> None:
        while True:
            self.follow_once()
            time.sleep(self.retry)


def parse_feeds(spec: str) -> list[tuple[str, str]]:
    """OVERWATCH_FEEDS: `name=url,name=url`, in page order. The first is
    required: the pods are ready once it has been heard."""
    feeds = []
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        name, sep, url = part.partition("=")
        if not sep or not name.strip() or not url.strip():
            raise ValueError(f"OVERWATCH_FEEDS entry {part!r} isn't name=url")
        feeds.append((name.strip(), url.strip()))
    if not feeds:
        raise ValueError("OVERWATCH_FEEDS names no feeds")
    if len({n for n, _ in feeds}) != len(feeds):
        raise ValueError("OVERWATCH_FEEDS names a feed twice")
    return feeds


class Relay:
    """Every feed as one state, in order. Ready on the first (required) feed
    alone: the others may run nowhere (the Wi-Fi watch follows its dongle)."""

    def __init__(self, feeds: list[tuple[str, str]], hub: Hub, **kw):
        self.hub, self.feeds = hub, None  # nothing published until every feed exists
        built = [Upstream(url, hub, on_change=self.publish, name=name, **kw) for name, url in feeds]
        self.feeds = built
        self.publish()

    @property
    def required(self) -> Upstream:
        return self.feeds[0]

    @property
    def ready(self) -> bool:
        return self.required.ready

    def feed(self, name: str) -> Upstream | None:
        return next((f for f in self.feeds if f.name == name), None)

    def publish(self) -> None:
        if not self.feeds:
            return  # still starting
        self.hub.publish({"feeds": [{"name": f.name, "error": f.error, "state": f.scanner} for f in self.feeds]})

    def run(self) -> None:
        for feed in self.feeds[1:]:
            threading.Thread(target=feed.run, daemon=True).start()
        self.required.run()


def make_server(upstream, hub: Hub, host: str, port: int, heartbeat: float = 5) -> ThreadingHTTPServer:
    reg = metrics.web_registry(upstream, hub) if isinstance(upstream, Relay) else None

    class Handler(brick_observe.httpserver.Observed, BaseHTTPRequestHandler):
        routes = {"/", "/index.html", "/api/state", "/api/stream"}
        skip = tracing.NOT_TRACED
        metrics_registry = reg

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif self.path == "/api/stream":
                self._stream()
            elif self.path == "/api/state":
                body = {"now": time.time(), **json.loads(hub.latest())}
                self._send(200, json.dumps(body).encode(), "application/json")
            elif self.path == "/health":
                self._send(200, b"ok\n")
            elif self.path == "/ready":
                self._send(*((200, b"ready\n") if upstream.ready else (503, b"no scanner data yet\n")))
            elif self.path == "/metrics" and reg is not None:
                self._send(200, metrics.render(reg), metrics.CONTENT_TYPE_LATEST)
            else:
                self._send(404, b"not found\n")

        def _stream(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            # Tell any buffering proxy to pass each event straight through.
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def write(chunk: bytes) -> None:
                self.wfile.write(chunk)
                self.wfile.flush()

            try:
                stream(hub, write, heartbeat)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the browser went away

        def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((host, port), Handler)


def main(host: str, port: int, feeds: list[tuple[str, str]]) -> None:
    hub = Hub()
    relay = Relay(feeds, hub)
    threading.Thread(target=relay.run, daemon=True).start()
    log.info("web listening", host=host, port=port, feeds=[f.name for f in relay.feeds])
    make_server(relay, hub, host, port).serve_forever()

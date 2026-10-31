"""Alerts in Tempo: a watch's span, then a span on each web pod that relays it.

An alert travels inside the state snapshots, so it carries its own `traceparent`
and the relay joins the same trace. Spans hold a feed and a kind, never an
address or BSSID (the same rule as metrics.py).
"""

from __future__ import annotations

import time

import brick_observe
from opentelemetry import propagate, trace

log = brick_observe.get_logger(__name__)
tracer = trace.get_tracer(__name__)
# A stream lasts as long as its listener: a span that long would say nothing.
NOT_TRACED = brick_observe.httpserver.SKIP | {"/api/stream"}


def carried() -> dict[str, str]:
    """The current span's `traceparent` for an alert, if there's a span."""
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    return {"traceparent": carrier["traceparent"]} if "traceparent" in carrier else {}


def relayed(feed: str, state: dict, seen: set[str], listeners: int) -> set[str]:
    """A span for each alert in `state` not in `seen`; returns what to pass as
    `seen` next time. Alerts stay in the snapshots for 30 minutes."""
    now = set()
    for alert in state.get("alerts") or []:
        parent = alert.get("traceparent")
        if not parent:
            continue
        now.add(parent)
        if parent in seen:
            continue
        with tracer.start_as_current_span(
            "relay alert",
            context=propagate.extract({"traceparent": parent}),
            attributes={"overwatch.feed": feed, "overwatch.kind": alert.get("kind", ""), "overwatch.listeners": listeners},
        ):
            log.info("alert relayed", feed=feed, kind=alert.get("kind"), delay_seconds=round(time.time() - alert["at"], 3))
    return now

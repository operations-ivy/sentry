"""Prometheus metrics at /metrics on each half: what it hears, what it alerts
on, and how it's doing. Read from the watches' own state when Prometheus
scrapes, so each half reports only its own (the scanner no Wi-Fi, the web
pods no radio).

Counts only, never addresses or BSSIDs: the page hashes those for the same
reason.
"""

from __future__ import annotations

from collections import Counter

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from prometheus_client.core import CollectorRegistry, CounterMetricFamily, GaugeMetricFamily

__all__ = [
    "CONTENT_TYPE_LATEST",
    "ble_registry",
    "render",
    "upnp_registry",
    "web_registry",
    "wifi_registry",
]


class _Ble:
    def __init__(self, watch):
        self.watch = watch

    def collect(self):
        w = self.watch
        state = w.get()
        yield GaugeMetricFamily("overwatch_ble_scanning", "1 while BlueZ is scanning.", value=int(w.scanning))
        yield GaugeMetricFamily(
            "overwatch_ble_learning_seconds",
            "Seconds of learning the house's normal counts left.",
            value=state["learning"],
        )
        nearby = GaugeMetricFamily("overwatch_ble_devices", "Devices of each kind nearby now.", labels=["kind"])
        normal = GaugeMetricFamily(
            "overwatch_ble_normal_devices", "The learned normal count of each kind.", labels=["kind"]
        )
        closest = GaugeMetricFamily(
            "overwatch_ble_closest_rssi_dbm", "The strongest signal of each kind nearby.", labels=["kind"]
        )
        seen = {k["kind"]: k for k in state["kinds"]}
        for kind in sorted(set(seen) | set(w.normal)):
            k = seen.get(kind)
            nearby.add_metric([kind], k["count"] if k else 0)
            normal.add_metric([kind], w.normal.get(kind, 0))
            if k:
                closest.add_metric([kind], k["closest"])
        yield nearby
        yield normal
        yield closest
        yield _counter("overwatch_ble_adverts", "Adverts heard from a known kind of device.", "kind", w.advert_counts)
        yield _counter(
            "overwatch_ble_alerts",
            "Alerts raised: more of a kind nearby than normal, for a while.",
            "kind",
            w.alert_counts,
        )
        yield CounterMetricFamily(
            "overwatch_ble_scan_failures", "Times scanning failed (no adapter or bluetoothd).", value=w.failures
        )


class _Wifi:
    def __init__(self, watch):
        self.watch = watch

    def collect(self):
        w = self.watch
        state = w.get()
        yield GaugeMetricFamily(
            "overwatch_wifi_capturing", "1 while the dongle is capturing in monitor mode.", value=int(w.scanning)
        )
        yield GaugeMetricFamily("overwatch_wifi_channel", "The channel the dongle is on now.", value=state["channel"])
        yield GaugeMetricFamily("overwatch_wifi_access_points", "Access points heard lately.", value=state["aps"])
        threats = GaugeMetricFamily("overwatch_wifi_threats", "Threats going on now.", labels=["kind"])
        by_kind = Counter(t["kind"] for t in state["threats"])
        for kind in sorted(set(by_kind) | {"deauth", "twin", "karma"}):
            threats.add_metric([kind], by_kind.get(kind, 0))
        yield threats
        yield _counter("overwatch_wifi_frames", "Management frames heard, by subtype.", "subtype", w.frame_counts)
        yield _counter(
            "overwatch_wifi_alerts", "Alerts raised: deauth floods, evil twins, karma.", "kind", w.alert_counts
        )
        yield CounterMetricFamily(
            "overwatch_wifi_capture_failures", "Times capturing failed (no dongle, unplugged).", value=w.failures
        )


class _Upnp:
    def __init__(self, watch):
        self.watch = watch

    def collect(self):
        w = self.watch
        state = w.get()
        yield GaugeMetricFamily(
            "overwatch_upnp_reachable",
            "1 while the router answers UPnP (the last poll got its table).",
            value=int(w.scanning),
        )
        yield GaugeMetricFamily(
            "overwatch_upnp_mappings", "UPnP port forwards on the router now.", value=len(state["mappings"])
        )
        yield GaugeMetricFamily(
            "overwatch_upnp_unexpected",
            "UPnP port forwards now that aren't on the allowed list.",
            value=state["unexpected"],
        )
        yield CounterMetricFamily(
            "overwatch_upnp_opened", "UPnP port forwards that appeared while watching.", value=w.opened
        )
        yield _counter("overwatch_upnp_alerts", "Alerts raised: unexpected UPnP forwards.", "kind", w.alert_counts)
        yield _counter("overwatch_upnp_polls", "Polls of the router's UPnP table, by result.", "result", w.polls)


class _Web:
    def __init__(self, relay, hub):
        self.relay, self.hub = relay, hub

    def collect(self):
        up = GaugeMetricFamily(
            "overwatch_web_upstream_up", "1 while the feed's stream is connected.", labels=["upstream"]
        )
        reconnects = CounterMetricFamily(
            "overwatch_web_upstream_reconnects", "Times the feed's stream ended.", labels=["upstream"]
        )
        for u in self.relay.feeds:
            up.add_metric([u.name], int(u.ready and not u.error))
            reconnects.add_metric([u.name], u.drops)
        yield up
        yield reconnects


class _Hub:
    def __init__(self, hub):
        self.hub = hub

    def collect(self):
        yield GaugeMetricFamily(
            "overwatch_stream_clients", "Server-Sent Events listeners connected now.", value=self.hub.clients
        )
        yield CounterMetricFamily(
            "overwatch_state_changes", "Times the state handed to listeners changed.", value=self.hub.version
        )


def _counter(name: str, doc: str, label: str, counts: Counter) -> CounterMetricFamily:
    m = CounterMetricFamily(name, doc, labels=[label])
    for key, n in sorted(dict(counts).items()):
        m.add_metric([key], n)
    return m


def _registry(*collectors) -> CollectorRegistry:
    r = CollectorRegistry(auto_describe=False)
    for c in collectors:
        r.register(c)
    return r


def ble_registry(watch, hub) -> CollectorRegistry:
    return _registry(_Ble(watch), _Hub(hub))


def wifi_registry(watch, hub) -> CollectorRegistry:
    return _registry(_Wifi(watch), _Hub(hub))


def upnp_registry(watch, hub) -> CollectorRegistry:
    return _registry(_Upnp(watch), _Hub(hub))


def web_registry(relay, hub) -> CollectorRegistry:
    return _registry(_Web(relay, hub), _Hub(hub))


def render(registry: CollectorRegistry) -> bytes:
    return generate_latest(registry)

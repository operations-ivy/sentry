"""What the scanner hears: which Bluetooth LE adverts are trackers or
surveillance gadgets, and whether there are more of a kind than usual.

Signatures come from the Bluetooth SIG's assigned numbers, the IEEE OUI
registry and published protocol specs; which ones to look for follows
SquachWatch-CYD's list, but no data is copied from it. Each has a confidence:
only high and medium ones raise alerts.

Privacy: device addresses never leave this process. Each one is hashed with a
per-start salt, and only counts and signal strengths per kind leave it.
Nothing is written to disk.

Households are full of trackers, so the first `learn_seconds` learn the
normal count of each kind; an alert is a kind above its normal count for
`linger_seconds`. Alerts count only devices heard in the last
`present_seconds`; the view keeps counting one for `gone_seconds`.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

import brick_observe

from . import tracing

log = brick_observe.get_logger(__name__)


def uuid16(n: int) -> str:
    return f"0000{n:04x}-0000-1000-8000-00805f9b34fb"


@dataclass(frozen=True)
class Kind:
    key: str
    label: str
    confidence: str  # high, medium, low


KINDS = {
    k.key: k
    for k in (
        Kind("findmy", "Apple Find My tag", "high"),
        Kind("smarttag", "Samsung SmartTag", "high"),
        Kind("tile", "Tile tracker", "high"),
        Kind("googletag", "Google Find My tag", "medium"),
        Kind("axon", "Axon device (body camera?)", "high"),
        Kind("drone", "Remote ID drone", "high"),
        Kind("meta", "Meta device (glasses?)", "medium"),
        Kind("spectacles", "Snap device (Spectacles?)", "medium"),
        Kind("flipper", "Flipper Zero", "high"),
        Kind("flipperish", "Flipper-like service", "low"),
        Kind("skimmer", "Serial BT module (skimmer?)", "low"),
        Kind("ibeacon", "iBeacon (shop beacon?)", "low"),
    )
}

TRACKERS = ("findmy", "smarttag", "tile", "googletag")  # the rest are gadgets
APPLE, FINDMY_TYPE, IBEACON = 0x004C, 0x12, b"\x02\x15"  # iBeacon: Apple's spec, type 0x02, length 0x15
# Company identifiers (Bluetooth SIG): Meta, Meta Platforms Technologies and
# Luxottica (Ray-Ban and Oakley Meta glasses); Snap; Flipper Devices.
META_COMPANIES, SNAP, FLIPPER = (0x01AB, 0x058E, 0x0D53), 0x03C2, 0x0E29
AXON_OUI = "00:25:DF"  # IEEE MA-L: Axon Enterprise, Inc.
REMOTE_ID, REMOTE_ID_APP = 0xFFFA, 0x0D  # ASTM F3411 Remote ID over BLE: service data, app code 0x0D
SKIMMER_NAMES = ("HC-05", "HC-06", "HC-08", "BT04-A", "RNBT-")


def classify(
    name: str | None,
    manufacturer: dict[int, bytes],
    services: list[str],
    service_data: dict[str, bytes],
    address: str = "",
    address_type: str = "",
) -> str | None:
    """The kind of one advert, or None for everything else. A maker's OUI only
    means something in a public address: random ones can start with anything."""
    name = name or ""
    services = [s.lower() for s in services] + [s.lower() for s in service_data]
    apple = manufacturer.get(APPLE)
    if apple and apple[0] == FINDMY_TYPE:
        return "findmy"  # Find My offline finding: an AirTag, or an Apple device away from its owner
    if uuid16(0xFD5A) in services:
        return "smarttag"
    if uuid16(0xFEED) in services or uuid16(0xFEEC) in services:
        return "tile"
    fmdn = service_data.get(uuid16(0xFEAA)) or b""
    if fmdn[:1] in (b"\x40", b"\x41"):
        return "googletag"  # Eddystone frame types Google's Find My Device network uses
    if address_type == "public" and address.upper().startswith(AXON_OUI):
        return "axon"
    if (service_data.get(uuid16(REMOTE_ID)) or b"")[:1] == bytes([REMOTE_ID_APP]):
        return "drone"
    if uuid16(0xFD5F) in services or any(c in manufacturer for c in META_COMPANIES):
        return "meta"
    if SNAP in manufacturer:
        return "spectacles"
    if name.startswith("Flipper ") or FLIPPER in manufacturer:
        return "flipper"
    if any(uuid16(n) in services for n in (0x3081, 0x3082, 0x3083)):
        return "flipperish"
    if name.startswith(SKIMMER_NAMES):
        return "skimmer"
    if apple and apple[:2] == IBEACON and len(apple) >= 23:
        return "ibeacon"
    return None


# Company identifiers (Bluetooth SIG assigned numbers) and 16-bit service UUIDs
# the details panel names; anything else shows as hex.
COMPANIES = {
    0x004C: "Apple",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x01AB: "Meta",
    0x058E: "Meta Platforms Technologies",
    0x0D53: "Luxottica",
    0x03C2: "Snap",
    0x0E29: "Flipper Devices",
    0x0006: "Microsoft",
    0x0059: "Nordic Semiconductor",
    0x0157: "Huami",
    0x038F: "Xiaomi",
}
SERVICES = {
    0xFD5A: "Samsung SmartTag",
    0xFEED: "Tile",
    0xFEEC: "Tile",
    0xFEAA: "Eddystone",
    0xFD5F: "Meta",
    0x3081: "Flipper-like",
    0x3082: "Flipper-like",
    0x3083: "Flipper-like",
    0xFE2C: "Google Fast Pair",
    0xFFFA: "ASTM Remote ID",
    0x180F: "Battery",
    0x180A: "Device Information",
    0xFFE0: "Serial (HM-10)",
}
UUID_BASE = "-0000-1000-8000-00805f9b34fb"
# Find My's status byte: the top two bits are the battery level (OpenHaystack's notes).
BATTERY = ("full", "medium", "low", "critically low")


def service_label(uuid: str) -> str:
    uuid = uuid.lower()
    if uuid.startswith("0000") and uuid.endswith(UUID_BASE):
        n = int(uuid[4:8], 16)
        return f"{SERVICES[n]} (0x{n:04X})" if n in SERVICES else f"0x{n:04X}"
    return uuid


def describe(
    kind: str,
    name: str | None,
    manufacturer: dict[int, bytes],
    services: list[str],
    service_data: dict[str, bytes],
    tx_power: int | None = None,
) -> dict:
    """What one advert says about its device, for the details panel. Nothing
    that identifies it: no address, no key material, no raw payloads."""
    d: dict = {}
    if name:
        d["name"] = name
    if tx_power is not None:
        d["tx_power"] = tx_power
    if manufacturer:
        d["makers"] = [COMPANIES.get(c, f"0x{c:04X}") for c in sorted(manufacturer)]
    labels = sorted({service_label(u) for u in list(services) + list(service_data)})
    if labels:
        d["services"] = labels
    apple = manufacturer.get(APPLE) or b""
    if kind == "findmy" and len(apple) > 2:
        d["battery"] = BATTERY[apple[2] >> 6 & 3]
    fmdn = service_data.get(uuid16(0xFEAA)) or b""
    if kind == "googletag" and fmdn:
        # Frame 0x41: unwanted-tracking protection mode, i.e. away from its owner.
        d["mode"] = "away from its owner" if fmdn[0] == 0x41 else "near its owner"
    return d


@dataclass
class Sighting:
    kind: str
    first: float
    last: float
    rssi: int
    number: int  # "device 3": tells devices apart on the page without an address
    adverts: int = 1
    rssi_min: int = 0
    rssi_max: int = 0
    address_type: str = ""
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        self.rssi_min = self.rssi_max = self.rssi


class Watch:
    def __init__(
        self,
        learn_seconds: float = 600,
        linger_seconds: float = 120,
        gone_seconds: float = 120,
        present_seconds: float = 30,
        started: float | None = None,
    ):
        self.learn_seconds, self.linger_seconds, self.gone_seconds = learn_seconds, linger_seconds, gone_seconds
        self.present_seconds = present_seconds
        self.started = time.time() if started is None else started
        self.salt = os.urandom(16)
        self.devices: dict[str, Sighting] = {}
        self.normal: dict[str, int] = {}
        self.over_since: dict[str, float] = {}
        self.alerts: list[dict] = []  # newest last, kept 30 minutes
        self._numbered = 0
        self.error = ""
        self.scanning = False  # set by the scanner once BlueZ is listening
        # Running totals for /metrics (metrics.py).
        self.advert_counts: Counter = Counter()
        self.alert_counts: Counter = Counter()
        self.failures = 0
        self._lock = threading.Lock()

    def _key(self, address: str) -> str:
        return hashlib.sha256(self.salt + address.encode()).hexdigest()[:10]

    def advert(
        self,
        address: str,
        kind: str,
        rssi: int,
        now: float | None = None,
        details: dict | None = None,
        address_type: str = "",
    ) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self.advert_counts[kind] += 1
            key = self._key(address)
            s = self.devices.get(key)
            if s is None or now - s.last > self.gone_seconds:
                self._numbered += 1
                s = self.devices[key] = Sighting(kind, now, now, rssi, self._numbered)
            else:
                s.last, s.rssi, s.adverts = now, rssi, s.adverts + 1
                s.rssi_min, s.rssi_max = min(s.rssi_min, rssi), max(s.rssi_max, rssi)
            if details:
                s.details.update(details)
            if address_type:
                s.address_type = address_type

    def _nearby(self, now: float) -> dict[str, list[tuple[str, Sighting]]]:
        by_kind: dict[str, list[tuple[str, Sighting]]] = {}
        for key, s in list(self.devices.items()):
            if now - s.last > self.gone_seconds:
                del self.devices[key]
                continue
            by_kind.setdefault(s.kind, []).append((key, s))
        return by_kind

    def tick(self, now: float | None = None) -> None:
        """Learn, or compare each kind with its normal count."""
        now = time.time() if now is None else now
        with self._lock:
            nearby = {
                k: [d for d in v if now - d[1].last <= self.present_seconds] for k, v in self._nearby(now).items()
            }
            nearby = {k: v for k, v in nearby.items() if v}
            learning = now - self.started < self.learn_seconds
            for kind, devs in nearby.items():
                if learning:
                    self.normal[kind] = max(self.normal.get(kind, 0), len(devs))
                    continue
                if KINDS[kind].confidence == "low" or len(devs) <= self.normal.get(kind, 0):
                    self.over_since.pop(kind, None)
                    continue
                since = self.over_since.setdefault(kind, now)
                if now - since >= self.linger_seconds and not any(
                    a["kind"] == kind and a["at"] >= since for a in self.alerts
                ):
                    newest = max(devs, key=lambda d: d[1].first)[1]
                    self.alert_counts[kind] += 1
                    with brick_observe.span("overwatch alert", **{"overwatch.kind": kind, "overwatch.nearby": len(devs)}):
                        self.alerts.append(
                            {
                                "kind": kind,
                                "label": KINDS[kind].label,
                                "confidence": KINDS[kind].confidence,
                                "at": now,
                                "count": len(devs),
                                "normal": self.normal.get(kind, 0),
                                "rssi": newest.rssi,
                                **tracing.carried(),
                            }
                        )
                        log.info("overwatch alert", kind=kind, nearby=len(devs), normal=self.normal.get(kind, 0))
            for kind in list(self.over_since):
                if kind not in nearby:
                    del self.over_since[kind]
            self.alerts = [a for a in self.alerts if now - a["at"] < 1800]

    def panel(self, st: dict) -> dict:
        """This feed in the page's common shape (panel.py)."""
        from . import panel
        return panel.bluetooth(st)

    def get(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self._lock:
            nearby = self._nearby(now)
            return {
                "learning": max(0, round(self.learn_seconds - (now - self.started))),
                "error": self.error,
                "kinds": [
                    {
                        "kind": k,
                        "label": KINDS[k].label,
                        "confidence": KINDS[k].confidence,
                        "tracker": k in TRACKERS,
                        "count": len(v),
                        "normal": self.normal.get(k, 0),
                        "closest": max(s.rssi for _, s in v),
                        "devices": [
                            {
                                "n": s.number,
                                "rssi": s.rssi,
                                "rssi_min": s.rssi_min,
                                "rssi_max": s.rssi_max,
                                "first": s.first,
                                "last": s.last,
                                "adverts": s.adverts,
                                "address_type": s.address_type,
                                **s.details,
                            }
                            for _, s in sorted(v, key=lambda d: -d[1].rssi)
                        ],
                    }
                    for k, v in sorted(nearby.items())
                ],
                "alerts": list(self.alerts),
            }

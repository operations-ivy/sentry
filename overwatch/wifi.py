"""The Wi-Fi watch: a monitor-mode dongle listening to 802.11 management
frames for attacks on the house's Wi-Fi.

- Deauth floods: deauthentication or disassociation frames for one access
  point faster than any real network sends them, which is how attackers
  knock clients off (to capture handshakes, or push them onto a twin). A
  flood counts against the house when any of the frame's addresses is one of
  its BSSIDs, a sibling of one (routers serve clients on BSSIDs they don't
  beacon: the same first five octets and nearby last octet, or the same last
  five with other bits set in the first), or matches a network's
  `prefixes`. A strong flood on an unknown BSSID is "near the house".
- Evil twins: one of the house's SSIDs beaconed by a BSSID that isn't one of
  its access points, or by one of its BSSIDs with weaker security or on a
  channel the house doesn't use.
- Karma / Pineapple: one access point answering probes for many SSIDs.

The house's networks (SSIDs, BSSIDs, security, channels) come from a JSON
file mounted from a SealedSecret, `OVERWATCH_WIFI_HOME`; nothing about them
is in this repo or on the page, which shows each network by its `name` only.
Without the file there's no twin detection. The dongle spends about 60% of
its time on the house's channels and hops the rest of the band in between
(`OVERWATCH_WIFI_HOME_SHARE`, 0.6).

Privacy, as on the Bluetooth side: addresses never leave this process
(access points are numbered on the page, through a per-start salted hash),
only the house's own network names leave it, and nothing is written to disk.

    GET /api/stream, /api/state, /health, /ready   as the scanner's
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import subprocess
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass

import brick_observe

from . import tracing

log = brick_observe.get_logger(__name__)

BROADCAST = "ff:ff:ff:ff:ff:ff"
BEACON, PROBE_RESP, DISASSOC, DEAUTH = 8, 5, 10, 12
SUBTYPES = {BEACON: "beacon", PROBE_RESP: "probe_response", DISASSOC: "disassoc", DEAUTH: "deauth"}
# Security from weakest to strongest; a twin offering less than the house is a downgrade.
RANK = {"open": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA2-Enterprise": 3, "WPA2/WPA3": 4, "WPA3": 5}
CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    128,
    132,
    136,
    140,
    144,
    149,
    153,
    157,
    161,
    165,
]


def channel_of(freq: int) -> int:
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    return 0


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def radiotap(buf: bytes) -> tuple[int | None, int, bytes]:
    """(signal dBm or None, channel or 0, the 802.11 frame) from a radiotap
    capture. Only the fields up to the antenna signal are needed, which all
    sit in the first presence word."""
    if len(buf) < 8 or buf[0] != 0:
        raise ValueError("not radiotap")
    length, present = struct.unpack_from("<HI", buf, 2)
    pos, word = 8, present
    while word & 0x80000000:  # more presence words follow
        (word,) = struct.unpack_from("<I", buf, pos)
        pos += 4
    flags, channel, signal = 0, 0, None
    for bit, (align, size) in enumerate(((8, 8), (1, 1), (1, 1), (2, 4), (1, 2), (1, 1))):
        if not present & (1 << bit):
            continue
        pos = (pos + align - 1) // align * align
        if bit == 1:
            flags = buf[pos]
        elif bit == 3:
            channel = channel_of(struct.unpack_from("<H", buf, pos)[0])
        elif bit == 5:
            signal = struct.unpack_from("<b", buf, pos)[0]
        pos += size
    frame = buf[length:]
    if flags & 0x10:  # the frame ends with its FCS
        frame = frame[:-4]
    return signal, channel, frame


def security(capability: int, ies: dict[int, list[bytes]]) -> str:
    """What a beacon or probe response offers, from its RSN and WPA elements."""
    for rsn in ies.get(48, []):
        try:
            n = struct.unpack_from("<H", rsn, 6)[0]
            off = 8 + 4 * n
            m = struct.unpack_from("<H", rsn, off)[0]
            suites = [rsn[off + 2 + 4 * i :][:4] for i in range(m)]  # noqa: E203 (black's slice spacing)
            akms = {x[3] for x in suites if len(x) == 4 and x[:3] == b"\x00\x0f\xac"}
        except (struct.error, IndexError):
            return "WPA2"
        if akms & {8, 9, 24, 25} and akms & {2, 6}:
            return "WPA2/WPA3"
        if akms & {8, 9, 24, 25}:
            return "WPA3"
        if akms & {1, 3, 5, 11, 12}:
            return "WPA2-Enterprise"
        return "WPA2"
    if any(v[:4] == b"\x00\x50\xf2\x01" for v in ies.get(221, [])):
        return "WPA"
    return "WEP" if capability & 0x10 else "open"


@dataclass
class Frame:
    subtype: int
    receiver: str
    transmitter: str
    bssid: str
    ssid: str | None = None
    security: str | None = None
    channel: int = 0  # from the DS parameter set: the channel the AP says it's on
    retry: bool = False  # the frame-control retry bit: a resend, not a fresh frame
    reason: int | None = None  # deauth/disassoc reason code (802.11 §9.4.1.7)


def parse(frame: bytes) -> Frame | None:
    """A management frame's fields, or None for anything else."""
    if len(frame) < 24 or (frame[0] >> 2) & 3 != 0:
        return None
    f = Frame(frame[0] >> 4, mac(frame[4:10]), mac(frame[10:16]), mac(frame[16:22]))
    f.retry = bool(frame[1] & 0x08)
    if f.subtype in (DEAUTH, DISASSOC) and len(frame) >= 26:
        (f.reason,) = struct.unpack_from("<H", frame, 24)
    if f.subtype in (BEACON, PROBE_RESP) and len(frame) >= 36:
        (capability,) = struct.unpack_from("<H", frame, 34)
        ies: dict[int, list[bytes]] = {}
        pos = 36
        while pos + 2 <= len(frame):
            eid, n = frame[pos], frame[pos + 1]
            start = pos + 2
            ies.setdefault(eid, []).append(frame[start:][:n])
            pos += 2 + n
        raw = (ies.get(0) or [b""])[0]
        f.ssid = (
            raw.decode("utf-8", "replace") if raw.strip(b"\x00") else None
        )  # hidden networks send nothing, or zeros
        f.security = security(capability, ies)
        if ies.get(3) and ies[3][0]:
            f.channel = ies[3][0][0]
    return f


@dataclass
class Network:
    name: str
    ssid: str
    bssids: set[str]
    security: str
    channels: set[int]
    prefixes: tuple[str, ...] = ()  # BSSID prefixes that are the house too (sibling BSSIDs)


def octets(address: str) -> bytes:
    return bytes.fromhex(address.replace(":", ""))


def siblings(a: str, b: str) -> bool:
    """Two BSSIDs one router would hand out: the same first five octets and
    the last in the same block of 16, or the same last five and the first
    differing only in its locally-administered and top bits (virtual and mesh
    BSSIDs set those). Never two different makers' unicast addresses."""
    x, y = octets(a), octets(b)
    if len(x) != 6 or len(y) != 6 or x == y:
        return False
    if x[:5] == y[:5] and x[5] >> 4 == y[5] >> 4:
        return True
    return x[1:] == y[1:] and (x[0] & 0x01) == (y[0] & 0x01)


def load_home(path: str) -> list[Network]:
    """The house's networks: {"networks": [{"name", "ssid", "bssids",
    "security", "channels", "prefixes"}]} ("prefixes" optional)."""
    with open(path) as f:
        data = json.load(f)
    return [
        Network(
            n["name"],
            n["ssid"],
            {b.lower() for b in n.get("bssids", [])},
            n.get("security", "WPA2"),
            {int(c) for c in n.get("channels", [])},
            tuple(p.lower() for p in n.get("prefixes", [])),
        )
        for n in data["networks"]
    ]


@dataclass(frozen=True)
class Kind:
    key: str
    label: str


KINDS = {
    k.key: k
    for k in (
        Kind("deauth", "Deauth flood"),
        Kind("twin", "Evil twin"),
        Kind("karma", "Karma / Pineapple"),
        Kind("harvester", "Deauth spray"),
    )
}


@dataclass
class Threat:
    kind: str
    number: int  # "AP 3": tells access points apart on the page without a BSSID
    first: float
    last: float
    confidence: str
    target: str  # the house network's name, "a network near the house" or "a neighbour's network"
    reason: str
    rssi: int | None = None
    channel: int = 0
    frames: int = 0
    broadcast: bool = False
    ssids: int = 0
    networks: int = 0  # harvester: distinct BSSIDs deauthed in the window


class WifiWatch:
    def __init__(
        self,
        home: list[Network] | None = None,
        # 30 in 5 s (6/s) sits well above a router's own deauths and well
        # below any real flood: the quietest tool (ESP8266 Deauther) sends
        # ~10 per target per second, aireplay-ng and ESP32 Marauder hundreds.
        deauth_frames: int = 30,
        deauth_seconds: float = 5,
        karma_ssids: int = 4,
        karma_seconds: float = 60,
        # A handshake harvester (pwnagotchi, and the like) sprays deauths across
        # every network in range to force reconnects. Each BSSID stays well under
        # the single-target flood, but deauths touching many BSSIDs in a short
        # window is a pattern a home never makes on its own.
        spray_bssids: int = 4,
        spray_seconds: float = 12,
        gone_seconds: float = 120,
        overlap_seconds: float = 60,
        near_dbm: int = -60,
    ):
        self.home = home or []
        self.deauth_frames, self.deauth_seconds = deauth_frames, deauth_seconds
        self.karma_ssids, self.karma_seconds = karma_ssids, karma_seconds
        self.spray_bssids, self.spray_seconds = spray_bssids, spray_seconds
        self._sprayed: dict[str, float] = {}  # BSSID -> last fresh deauth, for the spray window
        self.gone_seconds = gone_seconds
        # A flood on a BSSID that isn't the house's, heard louder than this,
        # is close by: "near the house", not "a neighbour's".
        self.near_dbm = near_dbm
        # A house BSSID on a channel outside the list is a twin only while
        # the real one is still heard on a house channel: heard there after
        # the other channel's first beacon, within this long. A router that
        # moved (a restart, DFS) went quiet on the old channel first.
        self.overlap_seconds = overlap_seconds
        self._home_last: dict[str, float] = {}  # BSSID -> last heard on a house channel
        self._off: dict[tuple[str, int], list[float]] = {}  # (BSSID, channel) -> [first, last]
        self.moved: dict[str, tuple[str, int, float]] = {}  # hashed BSSID -> (network, channel, last)
        self.salt = os.urandom(16)
        self.threats: dict[tuple[str, str], Threat] = {}
        self.alerts: list[dict] = []  # newest last, kept 30 minutes
        self.aps: dict[str, float] = {}  # hashed BSSID -> last heard
        self._numbers: dict[str, int] = {}
        self._deauths: dict[str, deque] = {}
        self._probes: dict[str, dict[str, float]] = {}
        self.channel = 0
        self.error = ""
        self.scanning = False
        # Running totals for /metrics (metrics.py).
        self.frame_counts: Counter = Counter()
        self.alert_counts: Counter = Counter()
        self.failures = 0
        self._lock = threading.Lock()

    def _key(self, address: str) -> str:
        return hashlib.sha256(self.salt + address.encode()).hexdigest()[:10]

    def _number(self, key: str) -> int:
        return self._numbers.setdefault(key, len(self._numbers) + 1)

    def home_channels(self) -> list[int]:
        return sorted({c for n in self.home for c in n.channels})

    def _network(self, bssid: str) -> Network | None:
        return next((n for n in self.home if bssid in n.bssids), None)

    def _attacked(self, f: Frame) -> tuple[Network | None, str]:
        """The house network a deauth is aimed at, by any of its addresses,
        and how: "" (one of its BSSIDs), "sibling" or "prefix"."""
        addresses = [a for a in (f.bssid, f.transmitter, f.receiver) if a != BROADCAST]
        tests = {
            "": lambda a, n: a in n.bssids,
            "sibling": lambda a, n: any(siblings(a, h) for h in n.bssids),
            "prefix": lambda a, n: any(a.startswith(p) for p in n.prefixes),
        }
        for how, test in tests.items():  # the closest match first
            for n in self.home:
                if any(test(a, n) for a in addresses):
                    return n, how
        return None, ""

    def _threat(self, kind: str, bssid: str, now: float, confidence: str, target: str, reason: str, **extra) -> None:
        key = self._key(bssid)
        t = self.threats.get((kind, key))
        if t is None or now - t.last > self.gone_seconds:
            t = self.threats[(kind, key)] = Threat(kind, self._number(key), now, now, confidence, target, reason)
            self.alert_counts[kind] += 1
            with brick_observe.span("overwatch alert", **{"overwatch.kind": kind}):
                self.alerts.append(
                    {
                        "kind": kind,
                        "label": KINDS[kind].label,
                        "confidence": confidence,
                        "at": now,
                        "detail": f"{reason} · AP {t.number}" + (f" · against {target}" if kind == "deauth" else ""),
                        "rssi": extra.get("rssi"),
                        **tracing.carried(),
                    }
                )
                log.info("overwatch wifi alert", kind=kind, reason=reason)
        t.last, t.confidence, t.target, t.reason = now, confidence, target, reason
        for k, v in extra.items():
            if v is not None:
                setattr(t, k, v)

    def heard(self, f: Frame, rssi: int | None, channel: int, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self.frame_counts[SUBTYPES.get(f.subtype, "other")] += 1
            if f.subtype in (DEAUTH, DISASSOC):
                # A retried frame is the AP resending to a client that already
                # left, not a fresh flood frame: counting it is how a routine
                # disconnect used to read as an attack.
                if not f.retry:
                    self._deauth(f, rssi, channel, now)
            elif f.subtype in (BEACON, PROBE_RESP):
                self.aps[self._key(f.bssid)] = now
                if f.ssid:
                    self._beacon(f, rssi, channel, now)

    def _deauth(self, f: Frame, rssi: int | None, channel: int, now: float) -> None:
        """A flood starts at `deauth_frames` in `deauth_seconds` for one BSSID;
        after that every frame for it counts towards the same flood until it
        goes quiet for `gone_seconds`."""
        self._sprayed[f.bssid] = now
        for b in [b for b, seen in self._sprayed.items() if now - seen > self.spray_seconds]:
            del self._sprayed[b]
        if len(self._sprayed) >= self.spray_bssids:
            self._threat(
                "harvester", "spray", now, "high", "many networks",
                f"deauths for {len(self._sprayed)} networks in {self.spray_seconds:g} s",
                rssi=rssi, channel=channel, networks=len(self._sprayed),
            )
        broadcast = f.receiver == BROADCAST
        t = self.threats.get(("deauth", self._key(f.bssid)))
        if t and now - t.last <= self.gone_seconds:
            t.last, t.frames, t.broadcast = now, t.frames + 1, t.broadcast or broadcast
            t.rssi, t.channel = rssi if rssi is not None else t.rssi, channel or t.channel
            return
        q = self._deauths.setdefault(f.bssid, deque())
        q.append((now, broadcast, SUBTYPES.get(f.subtype, "deauth")))
        while q and now - q[0][0] > self.deauth_seconds:
            q.popleft()
        if len(q) < self.deauth_frames:
            return
        net, how = self._attacked(f)
        broadcast = any(b for _, b, _ in q)
        # Both subtypes paired for one BSSID is the ESP8266/Marauder pattern;
        # a router sends one kind at a time.
        kinds = {s for _, _, s in q}
        what = "deauth and disassoc" if len(kinds) == 2 else ("disassoc" if "disassoc" in kinds else "deauth")
        reason = f"{len(q)} {what} frames in {self.deauth_seconds:g} s" + (", to everyone" if broadcast else "")
        if how:
            reason += f", on a {'sibling BSSID' if how == 'sibling' else 'BSSID in its prefixes'}"
        if self._key(f.bssid) not in self.aps:
            reason += ", BSSID not beaconing"
        if f.reason is not None:
            reason += f", reason code {f.reason}"
        if net:
            target = net.name
        elif rssi is not None and rssi > self.near_dbm:
            target = "a network near the house"
        else:
            target = "a neighbour's network"
        self._threat(
            "deauth",
            f.bssid,
            now,
            "high" if net else "medium",
            target,
            reason,
            rssi=rssi,
            channel=channel,
            broadcast=broadcast,
            frames=len(q),
        )
        del self._deauths[f.bssid]

    def _beacon(self, f: Frame, rssi: int | None, channel: int, now: float) -> None:
        net = self._network(f.bssid)
        if f.subtype == PROBE_RESP and not net:
            seen = self._probes.setdefault(f.bssid, {})
            seen[f.ssid] = now
            for s in [s for s, t in seen.items() if now - t > self.karma_seconds]:
                del seen[s]
            if len(seen) >= self.karma_ssids:
                self._threat(
                    "karma",
                    f.bssid,
                    now,
                    "high",
                    "",
                    f"answering probes for {len(seen)} networks",
                    rssi=rssi,
                    channel=channel,
                    ssids=len(seen),
                )
        for home in self.home:
            if f.ssid != home.ssid:
                continue
            on = f.channel or channel
            if f.bssid not in home.bssids:
                reason, confidence = (
                    f"{home.name}'s name from an access point that isn't the house's ({f.security})",
                    "high",
                )
            elif RANK.get(f.security or "", 0) < RANK.get(home.security, 3):
                reason, confidence = f"{home.name}'s own BSSID offering {f.security}, not {home.security}", "high"
            elif home.channels and on and on in home.channels:
                self._home_last[f.bssid] = now
                self.moved.pop(self._key(f.bssid), None)
                continue
            elif home.channels and on:
                seen = self._off.get((f.bssid, on))
                if seen is None or now - seen[1] > self.gone_seconds:
                    seen = self._off[(f.bssid, on)] = [now, now]
                seen[1] = now
                last_home = self._home_last.get(f.bssid)
                if last_home is None or last_home < seen[0] or now - last_home > self.overlap_seconds:
                    # Moved, not doubled: news for the page, not an alert.
                    self.moved[self._key(f.bssid)] = (home.name, on, now)
                    continue
                channels = ", ".join(str(c) for c in sorted(home.channels))
                reason, confidence = (
                    f"{home.name}'s own BSSID on channel {on} while still on its own ({channels})",
                    "medium",
                )
            else:
                continue
            self._threat("twin", f.bssid, now, confidence, home.name, reason, rssi=rssi, channel=on)

    def panel(self, st: dict) -> dict:
        """This feed in the page's common shape (panel.py)."""
        from . import panel

        return panel.wifi(st)

    def get(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self._lock:
            for k in [k for k, t in self.threats.items() if now - t.last > self.gone_seconds]:
                del self.threats[k]
            for k in [k for k, t in self.aps.items() if now - t > self.gone_seconds]:
                del self.aps[k]
            for k in [k for k, m in self.moved.items() if now - m[2] > self.gone_seconds]:
                del self.moved[k]
            self.alerts = [a for a in self.alerts if now - a["at"] < 1800]
            return {
                "error": self.error,
                "channel": self.channel,
                "home": [n.name for n in self.home],
                "aps": len(self.aps),
                # A house network heard only on a channel outside its list:
                # update overwatch-wifi-home's channels.
                "moved": sorted({(name, ch) for name, ch, _ in self.moved.values()}),
                "threats": [
                    {
                        "kind": t.kind,
                        "label": KINDS[t.kind].label,
                        "confidence": t.confidence,
                        "n": t.number,
                        "first": t.first,
                        "last": t.last,
                        "target": t.target,
                        "reason": t.reason,
                        "rssi": t.rssi,
                        "channel": t.channel,
                        "frames": t.frames,
                        "broadcast": t.broadcast,
                        "ssids": t.ssids,
                        "networks": t.networks,
                    }
                    for t in sorted(self.threats.values(), key=lambda t: -t.last)
                ],
                "alerts": list(self.alerts),
            }


def schedule(home: list[int], home_share: float = 0.6, cycle: float = 5, peek_seconds: float = 0.25):
    """Channel hops forever: each `cycle` seconds, `home_share` of it across
    the house's channels and the rest on other channels, `peek_seconds` each
    (at 0.6, 8 of them a cycle: the whole band in about 25 s). With no house
    channels it hops the whole band evenly."""
    others = [c for c in CHANNELS_24 + CHANNELS_5 if c not in home]
    dwell, peek = home_share * cycle, max(1, round((1 - home_share) * cycle / peek_seconds))
    i = 0
    while True:
        if home:
            for c in home:
                yield c, dwell / len(home)
            for _ in range(peek):
                yield others[i % len(others)], peek_seconds
                i += 1
        else:
            yield others[i % len(others)], peek_seconds
            i += 1


def run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True, timeout=5)


def monitor_mode(iface: str) -> None:
    run("ip", "link", "set", iface, "down")
    run("iw", "dev", iface, "set", "type", "monitor")
    run("ip", "link", "set", iface, "up")


def hop_forever(watch: WifiWatch, iface: str, home_share: float = 0.6) -> None:
    bad: set[int] = set()
    for channel, seconds in schedule(watch.home_channels(), home_share):
        if not watch.scanning:  # not in monitor mode yet, or the dongle's gone
            time.sleep(1)
            continue
        if channel in bad:
            time.sleep(0.01)
            continue
        try:
            run("iw", "dev", iface, "set", "channel", str(channel))
            watch.channel = channel
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            bad.add(channel)  # not allowed here (regulatory domain) or not on this dongle
            log.info("skipping channel", channel=channel)
            continue
        time.sleep(seconds)


def capture_forever(watch: WifiWatch, hub, iface: str, retry_seconds: float = 30) -> None:
    from .scanner import state

    while True:
        try:
            monitor_mode(iface)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((iface, 0))
            sock.settimeout(1)
            watch.error, watch.scanning = "", True
            log.info("capturing", iface=iface)
            last_tick = 0.0
            while True:
                try:
                    buf = sock.recv(4096)
                except TimeoutError:
                    buf = b""
                if buf:
                    try:
                        rssi, channel, raw = radiotap(buf)
                        f = parse(raw)
                    except (ValueError, struct.error, IndexError):
                        f = None
                    if f:
                        before = len(watch.threats)
                        watch.heard(f, rssi, channel or watch.channel)
                        if len(watch.threats) != before:
                            hub.publish(state(watch))
                now = time.time()
                if now - last_tick >= 1:  # threats ageing out, alert ages, the channel
                    hub.publish(state(watch))
                    last_tick = now
        except Exception as e:  # no dongle, unplugged, no permission
            watch.error, watch.scanning = "no Wi-Fi monitor", False
            watch.failures += 1
            hub.publish(state(watch))
            log.warning("capture failed", error=str(e))
        time.sleep(retry_seconds)


def survey(iface: str, seconds: float) -> None:
    """Print a draft OVERWATCH_WIFI_HOME from what the dongle hears, strongest
    first, for picking the house's networks. Run it in the wifi pod; it reads
    alongside the watch, which keeps hopping."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))
    sock.settimeout(1)
    nets: dict[str, dict] = {}
    end = time.time() + seconds
    while time.time() < end:
        try:
            rssi, channel, raw = radiotap(sock.recv(4096))
            f = parse(raw)
        except (TimeoutError, ValueError, struct.error, IndexError):
            continue
        if not f or f.subtype not in (BEACON, PROBE_RESP) or not f.ssid:
            continue
        n = nets.setdefault(
            f.ssid,
            {"name": "", "ssid": f.ssid, "bssids": set(), "security": f.security, "channels": set(), "rssi": -127},
        )
        n["bssids"].add(f.bssid)
        n["channels"].add(f.channel or channel)
        n["rssi"] = max(n["rssi"], rssi if rssi is not None else -127)
    out = sorted(nets.values(), key=lambda n: -n["rssi"])
    for n in out:
        n["bssids"], n["channels"] = sorted(n["bssids"]), sorted(c for c in n["channels"] if c)
    print(json.dumps({"networks": out}, indent=2))


def main(host: str, port: int, iface: str, home_path: str, home_share: float = 0.6) -> None:
    from .hub import Hub
    from .metrics import wifi_registry
    from .scanner import make_server

    home: list[Network] = []
    if home_path and os.path.exists(home_path):
        home = load_home(home_path)
        log.info("watching house networks", networks=len(home))
    else:
        log.warning("no house networks: deauth and karma only, no twins", path=home_path or "unset")
    watch, hub = (
        WifiWatch(
            home,
            deauth_frames=int(os.environ.get("OVERWATCH_DEAUTH_FRAMES", "30")),
            deauth_seconds=float(os.environ.get("OVERWATCH_DEAUTH_SECONDS", "5")),
        ),
        Hub(),
    )
    threading.Thread(target=capture_forever, args=(watch, hub, iface), daemon=True).start()
    threading.Thread(target=hop_forever, args=(watch, iface, home_share), daemon=True).start()
    log.info("wifi watch listening", host=host, port=port)
    make_server(watch, hub, host, port, registry=wifi_registry).serve_forever()

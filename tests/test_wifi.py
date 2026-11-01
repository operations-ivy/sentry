from __future__ import annotations

import itertools
import json
import struct
import tempfile
import unittest

from overwatch.wifi import (
    BEACON,
    DEAUTH,
    DISASSOC,
    PROBE_RESP,
    Network,
    WifiWatch,
    load_home,
    parse,
    radiotap,
    schedule,
    siblings,
)

HOME_AP, OTHER_AP, CLIENT = "02:00:00:00:00:01", "02:00:00:00:00:99", "02:00:00:00:00:42"
WPA2_RSN = (
    bytes([1, 0]) + b"\x00\x0f\xac\x04" + bytes([1, 0]) + b"\x00\x0f\xac\x04" + bytes([1, 0]) + b"\x00\x0f\xac\x02"
)
WPA3_RSN = WPA2_RSN[:-1] + b"\x08"


def b(addr: str) -> bytes:
    return bytes.fromhex(addr.replace(":", ""))


def ie(eid: int, body: bytes) -> bytes:
    return bytes([eid, len(body)]) + body


def mgmt(subtype: int, receiver: str, transmitter: str, bssid: str, body: bytes = b"") -> bytes:
    return bytes([subtype << 4, 0]) + b"\x00\x00" + b(receiver) + b(transmitter) + b(bssid) + b"\x00\x00" + body


def beacon(bssid: str, ssid: str, rsn: bytes | None = WPA2_RSN, channel: int = 6, subtype: int = BEACON) -> bytes:
    capability = 0x0411 if rsn else 0x0401
    body = bytes(8) + struct.pack("<HH", 100, capability) + ie(0, ssid.encode()) + ie(3, bytes([channel]))
    if rsn:
        body += ie(48, rsn)
    return mgmt(subtype, "ff:ff:ff:ff:ff:ff", bssid, bssid, body)


def deauth(bssid: str, receiver: str = CLIENT, reason: int = 7, retry: bool = False, subtype: int = DEAUTH) -> bytes:
    frame = mgmt(subtype, receiver, bssid, bssid, struct.pack("<H", reason))
    if retry:
        frame = bytes([frame[0], frame[1] | 0x08]) + frame[2:]  # frame-control retry bit
    return frame


def captured(frame: bytes, freq: int = 2437, signal: int = -48, fcs: bool = True) -> bytes:
    """A radiotap header as rtw88 sends it: flags, rate, channel, signal, with
    an FCS on the end."""
    present = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5)
    fields = bytes([0x10 if fcs else 0, 2]) + struct.pack("<HH", freq, 0x00A0) + struct.pack("<b", signal)
    header = struct.pack("<BBHI", 0, 0, 8 + len(fields), present) + fields
    return header + frame + (b"\xde\xad\xbe\xef" if fcs else b"")


HOME = [Network("home", "Castle", {HOME_AP}, "WPA2", {6, 149})]


class ParseTests(unittest.TestCase):
    def test_radiotap_signal_channel_and_fcs(self):
        frame = beacon(HOME_AP, "Castle")
        signal, channel, raw = radiotap(captured(frame, freq=5745, signal=-61))
        self.assertEqual((signal, channel, raw), (-61, 149, frame))

    def test_radiotap_with_an_extra_presence_word(self):
        frame = deauth(HOME_AP)
        present = (1 << 5) | (1 << 31)
        buf = struct.pack("<BBHII", 0, 0, 13, present, 0) + struct.pack("<b", -70) + frame
        self.assertEqual(radiotap(buf), (-70, 0, frame))

    def test_beacon_fields_and_security(self):
        f = parse(beacon(HOME_AP, "Castle", channel=11))
        self.assertEqual((f.subtype, f.bssid, f.ssid, f.security, f.channel), (BEACON, HOME_AP, "Castle", "WPA2", 11))
        self.assertEqual(parse(beacon(HOME_AP, "Castle", rsn=WPA3_RSN)).security, "WPA3")
        self.assertEqual(parse(beacon(HOME_AP, "Castle", rsn=None)).security, "open")

    def test_transition_mode(self):
        rsn = WPA2_RSN[:-6] + bytes([2, 0]) + b"\x00\x0f\xac\x02" + b"\x00\x0f\xac\x08"
        self.assertEqual(parse(beacon(HOME_AP, "Castle", rsn=rsn)).security, "WPA2/WPA3")

    def test_hidden_networks_and_data_frames(self):
        self.assertIsNone(parse(beacon(HOME_AP, "\x00\x00\x00")).ssid)
        self.assertIsNone(parse(bytes([0x08, 0x01]) + bytes(22)))  # a data frame
        self.assertIsNone(parse(b"\x80\x00"))  # too short


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.w = WifiWatch(HOME, deauth_frames=10, deauth_seconds=5)

    def hear(self, frame: bytes, t: float, channel: int = 6, rssi: int = -50):
        self.w.heard(parse(frame), rssi, channel, now=t)

    def kinds(self, t: float) -> list[tuple[str, str]]:
        return [(x["kind"], x["confidence"]) for x in self.w.get(now=t)["threats"]]

    def test_a_deauth_spray_across_networks_is_a_harvester(self):
        # Five BSSIDs, three deauths each: none is a flood, together they are a spray.
        w = WifiWatch(HOME, deauth_frames=10, spray_bssids=4, spray_seconds=12)
        for i in range(5):
            bssid = f"02:00:00:00:0{i + 1}:00"
            for n in range(3):
                w.heard(parse(deauth(bssid)), -55, 6, now=i * 0.5 + n * 0.05)
        threats = w.get(now=3)["threats"]
        kinds = {t["kind"]: t for t in threats}
        self.assertIn("harvester", kinds)
        self.assertNotIn("deauth", kinds)  # no single BSSID crossed the flood line
        h = kinds["harvester"]
        self.assertEqual((h["confidence"], h["networks"]), ("high", 5))
        self.assertIn("5 networks", h["reason"])

    def test_a_single_target_flood_is_not_a_spray(self):
        for i in range(40):
            self.hear(deauth(HOME_AP), 100 + i * 0.1)
        kinds = {k for k, _ in self.kinds(104)}
        self.assertIn("deauth", kinds)
        self.assertNotIn("harvester", kinds)

    def test_a_few_networks_are_not_a_spray(self):
        # Three BSSIDs is below the threshold: a couple of clients leaving, not a sweep.
        w = WifiWatch(HOME, spray_bssids=4, spray_seconds=12)
        for i in range(3):
            w.heard(parse(deauth(f"02:00:00:00:0{i + 1}:00")), -55, 6, now=i * 0.3)
        self.assertEqual(w.get(now=2)["threats"], [])

    def test_deauths_spread_past_the_window_are_not_a_spray(self):
        w = WifiWatch(HOME, spray_bssids=4, spray_seconds=12)
        for i in range(6):
            w.heard(parse(deauth(f"02:00:00:00:0{i + 1}:00")), -55, 6, now=i * 5.0)
        # Only the last few BSSIDs are ever inside one 12 s window.
        self.assertEqual([t["kind"] for t in w.get(now=26)["threats"]], [])

    def test_a_known_pwnagotchi_is_greeted_not_alarmed(self):
        pwn = "02:00:00:00:00:77"
        w = WifiWatch(HOME, known={pwn: {"name": "Pwny", "face": "(◕‿◕)"}})
        w.heard(parse(beacon(pwn, "anything")), -40, 1, now=5)
        st = w.get(now=6)
        self.assertEqual(st["threats"], [])
        self.assertEqual(st["friends"], [{"name": "Pwny", "face": "(◕‿◕)", "last": 5}])

    def test_a_pwnagotchi_goes_offline_after_the_window(self):
        pwn = "02:00:00:00:00:77"
        w = WifiWatch(HOME, known={pwn: {"name": "Pwny", "face": "(◕‿◕)"}})
        w.heard(parse(beacon(pwn, "anything")), -40, 1, now=0)
        self.assertEqual(len(w.get(now=300)["friends"]), 1)
        self.assertEqual(w.get(now=601)["friends"], [])

    def test_the_house_itself_is_no_threat(self):
        for t in range(30):
            self.hear(beacon(HOME_AP, "Castle"), t)
            self.hear(beacon(OTHER_AP, "Neighbours"), t)
            if t % 10 == 0:
                self.hear(deauth(HOME_AP), t)  # a client leaving now and then
        st = self.w.get(now=30)
        self.assertEqual((st["threats"], st["alerts"], st["aps"]), ([], [], 2))

    def test_a_deauth_flood_on_the_house_alerts_once(self):
        for i in range(40):
            self.hear(deauth(HOME_AP, "ff:ff:ff:ff:ff:ff"), 100 + i * 0.1)
        st = self.w.get(now=104)
        self.assertEqual(self.kinds(104), [("deauth", "high")])
        t = st["threats"][0]
        self.assertEqual((t["target"], t["frames"], t["broadcast"]), ("home", 40, True))
        self.assertEqual(len(st["alerts"]), 1)
        self.assertIn("against home", st["alerts"][0]["detail"])

    def test_a_flood_on_a_neighbour_is_medium(self):
        for i in range(12):
            self.hear(deauth(OTHER_AP), i * 0.2, rssi=-75)
        self.assertEqual(self.kinds(3), [("deauth", "medium")])
        t = self.w.get(now=3)["threats"][0]
        self.assertEqual(t["target"], "a neighbour's network")
        self.assertIn("BSSID not beaconing", t["reason"])

    def test_a_strong_flood_on_an_unknown_bssid_is_near_the_house(self):
        # overwatch#5: live, -49 dBm, "a neighbour's network" was misleading.
        for i in range(12):
            self.hear(deauth(OTHER_AP), i * 0.2, rssi=-49)
        self.assertEqual(self.kinds(3), [("deauth", "medium")])
        self.assertEqual(self.w.get(now=3)["threats"][0]["target"], "a network near the house")

    def test_a_flood_on_a_sibling_bssid_is_the_house(self):
        # overwatch#5: the router served clients on a BSSID it didn't beacon.
        for sibling in ("02:00:00:00:00:05", "06:00:00:00:00:01", "a2:00:00:00:00:01"):
            w = WifiWatch(HOME, deauth_frames=10, deauth_seconds=5)
            w.heard(parse(beacon(HOME_AP, "Castle")), -50, 6, now=0)
            for i in range(12):
                w.heard(parse(deauth(sibling)), -49, 6, now=1 + i * 0.2)
            t = w.get(now=4)["threats"]
            self.assertEqual(
                [(x["kind"], x["confidence"], x["target"]) for x in t], [("deauth", "high", "home")], sibling
            )
            self.assertIn("on a sibling BSSID", t[0]["reason"])
            self.assertIn("BSSID not beaconing", t[0]["reason"])

    def test_a_flood_sent_from_the_house_bssid_counts_whatever_addr3_says(self):
        frame = mgmt(DEAUTH, CLIENT, HOME_AP, OTHER_AP, b"\x07\x00")  # transmitter is the house
        for i in range(12):
            self.hear(frame, i * 0.2, rssi=-75)
        self.assertEqual(self.w.get(now=3)["threats"][0]["target"], "home")

    def test_prefixes_in_the_home_file(self):
        prefixed = "0a:bb:cc:dd:ee:77"
        w = WifiWatch([Network("home", "Castle", {HOME_AP}, "WPA2", {6}, ("0a:bb:cc",))], deauth_frames=10)
        for i in range(12):
            w.heard(parse(deauth(prefixed)), -75, 6, now=i * 0.2)
        t = w.get(now=3)["threats"][0]
        self.assertEqual((t["confidence"], t["target"]), ("high", "home"))
        self.assertIn("in its prefixes", t["reason"])

    def test_slow_deauths_are_not_a_flood(self):
        for i in range(30):
            self.hear(deauth(HOME_AP), i)  # one a second
        self.assertEqual(self.kinds(30), [])

    def test_retried_frames_are_not_a_flood(self):
        # A router resending a deauth to a client that already left: a burst
        # of retries must not read as an attack (the false-positive bug).
        for i in range(40):
            self.hear(deauth(HOME_AP, "ff:ff:ff:ff:ff:ff", retry=True), 100 + i * 0.1)
        self.assertEqual(self.kinds(104), [])

    def test_the_default_threshold_is_thirty(self):
        w = WifiWatch(HOME)  # defaults
        for i in range(25):
            w.heard(parse(deauth(HOME_AP)), -50, 6, now=i * 0.1)
        self.assertEqual(w.get(now=3)["threats"], [])  # 25 in 2.5 s is under the bar
        for i in range(25, 35):
            w.heard(parse(deauth(HOME_AP)), -50, 6, now=i * 0.1)
        self.assertEqual([x["kind"] for x in w.get(now=4)["threats"]], ["deauth"])

    def test_a_flood_names_its_reason_code(self):
        for i in range(12):
            self.hear(deauth(OTHER_AP, reason=1), i * 0.2, rssi=-75)
        self.assertIn("reason code 1", self.w.get(now=3)["threats"][0]["reason"])

    def test_both_subtypes_read_as_a_tool(self):
        for i in range(12):
            sub = DEAUTH if i % 2 else DISASSOC
            self.hear(deauth(OTHER_AP, subtype=sub), i * 0.2, rssi=-75)
        self.assertIn("deauth and disassoc frames", self.w.get(now=3)["threats"][0]["reason"])

    def test_a_twin_with_another_bssid(self):
        self.hear(beacon(OTHER_AP, "Castle", rsn=None), 10)
        self.assertEqual(self.kinds(10), [("twin", "high")])
        self.assertIn("isn't the house's (open)", self.w.get(now=10)["threats"][0]["reason"])

    def test_the_house_bssid_with_weaker_security(self):
        self.hear(beacon(HOME_AP, "Castle", rsn=None), 10)
        self.assertEqual(self.kinds(10), [("twin", "high")])
        self.assertIn("offering open, not WPA2", self.w.get(now=10)["threats"][0]["reason"])

    def test_the_house_bssid_on_another_channel_while_still_on_its_own(self):
        self.hear(beacon(HOME_AP, "Castle", channel=6), 5)  # the real one
        self.hear(beacon(HOME_AP, "Castle", channel=1), 10, channel=1)  # a copy appears
        self.assertEqual(self.kinds(10), [])  # not yet: could be a move
        self.hear(beacon(HOME_AP, "Castle", channel=6), 12)  # the real one carries on
        self.hear(beacon(HOME_AP, "Castle", channel=1), 14, channel=1)
        self.assertEqual(self.kinds(14), [("twin", "medium")])
        self.assertIn("while still on its own (6, 149)", self.w.get(now=14)["threats"][0]["reason"])

    def test_the_house_moving_channel_is_news_not_a_twin(self):
        for t in range(0, 30, 2):
            self.hear(beacon(HOME_AP, "Castle", channel=6), t)  # before the restart
        for t in range(90, 400, 2):
            self.hear(beacon(HOME_AP, "Castle", channel=1), t, channel=1)  # after: only on 1
        st = self.w.get(now=400)
        self.assertEqual((st["threats"], st["alerts"]), ([], []))
        self.assertEqual(st["moved"], [("home", 1)])
        self.hear(beacon(HOME_AP, "Castle", channel=6), 401)  # back on its own channel
        self.assertEqual(self.w.get(now=402)["moved"], [])

    def test_a_move_seen_mid_switch_still_isnt_a_twin(self):
        self.hear(beacon(HOME_AP, "Castle", channel=6), 100)  # last beacon on 6
        for t in range(101, 300):  # a channel switch: 1 from now on
            self.hear(beacon(HOME_AP, "Castle", channel=1), t, channel=1)
        self.assertEqual(self.kinds(300), [])

    def test_karma_answers_for_many_networks(self):
        for i, ssid in enumerate(["Starbucks", "Airport", "attwifi", "xfinitywifi"]):
            self.hear(beacon(OTHER_AP, ssid, subtype=PROBE_RESP), i)
        self.assertEqual(self.kinds(4), [("karma", "high")])

    def test_threats_go_after_gone_seconds_and_alerts_after_30_min(self):
        self.hear(beacon(OTHER_AP, "Castle"), 0)
        self.assertEqual(len(self.w.get(now=100)["threats"]), 1)
        self.assertEqual(self.w.get(now=121)["threats"], [])
        self.assertEqual(len(self.w.get(now=1799)["alerts"]), 1)
        self.assertEqual(self.w.get(now=1801)["alerts"], [])

    def test_no_addresses_or_ssids_leave(self):
        self.hear(beacon(OTHER_AP, "Castle"), 0)
        for i in range(12):
            self.hear(deauth(HOME_AP), i * 0.1)
        text = json.dumps(self.w.get(now=2))
        for secret in (HOME_AP, OTHER_AP, CLIENT, "Castle"):
            self.assertNotIn(secret, text)


class HomeAndScheduleTests(unittest.TestCase):
    def test_load_home(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump(
                {
                    "networks": [
                        {
                            "name": "home",
                            "ssid": "Castle",
                            "bssids": ["02:00:00:00:00:AA"],
                            "security": "WPA3",
                            "channels": [6],
                        }
                    ]
                },
                f,
            )
            f.flush()
            (n,) = load_home(f.name)
        self.assertEqual((n.name, n.bssids, n.security, n.channels), ("home", {"02:00:00:00:00:aa"}, "WPA3", {6}))
        self.assertEqual(n.prefixes, ())

    def test_load_home_with_prefixes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump({"networks": [{"name": "home", "ssid": "Castle", "bssids": [], "prefixes": ["0A:BB:CC"]}]}, f)
            f.flush()
            (n,) = load_home(f.name)
        self.assertEqual(n.prefixes, ("0a:bb:cc",))

    def test_siblings(self):
        home = "a0:11:22:33:44:51"
        for yes in ("a0:11:22:33:44:5f", "a2:11:22:33:44:51", "ae:11:22:33:44:51"):
            self.assertTrue(siblings(home, yes), yes)
        for no in (home, "a0:11:22:33:44:61", "a0:11:22:33:45:51", "a1:11:22:33:44:51", "b0:99:22:33:44:51"):
            self.assertFalse(siblings(home, no), no)

    def test_sixty_percent_at_home(self):
        hops = list(itertools.islice(schedule([6, 149], home_share=0.6), 1000))
        home = sum(s for c, s in hops if c in (6, 149))
        self.assertAlmostEqual(home / sum(s for _, s in hops), 0.6, places=2)
        others = {c for c, _ in hops if c not in (6, 149)}
        self.assertEqual(len(others), 13 + 25 - 2)  # every other channel gets a look

    def test_no_house_channels_hops_evenly(self):
        hops = list(itertools.islice(schedule([]), 38))
        self.assertEqual(len({c for c, _ in hops}), 38)


if __name__ == "__main__":
    unittest.main()

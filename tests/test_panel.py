import unittest

from overwatch import panel

KIND = {"kind": "tile", "label": "Tile tracker", "confidence": "high", "tracker": True, "count": 3, "normal": 1,
        "closest": -58, "devices": [{"n": 1, "rssi": -58, "rssi_min": -70, "rssi_max": -55, "first": 100.0,
                                     "last": 160.0, "adverts": 30, "address_type": "random"}]}


class BluetoothPanelTests(unittest.TestCase):
    def test_above_usual_is_a_hot_row_and_a_heads_up(self):
        p = panel.bluetooth({"scanning": True, "learning": 0, "error": "", "kinds": [KIND], "alerts": []})
        self.assertEqual((p["status"], p["headline"]["severity"], p["headline"]["word"]),
                         ({"state": "ok", "text": "scanning"}, 2, "HEADS UP"))
        row = p["rows"][0]
        self.assertEqual((row["hot"], row["verdict"], row["icon"], row["tone"]),
                         (True, {"text": "above usual", "tone": "bad"}, "tile", "cyan"))
        card = row["details"][0]
        self.assertEqual(card["fields"][0], ["here for", [{"for": 100.0}]])  # the page keeps it ticking
        self.assertIn(["address", "random (rotating, private)"], card["fields"])
        self.assertEqual(p["stats"][0], {"label": "Trackers", "value": "3", "sub": "nearby now", "tone": "cyan"})

    def test_learning_and_errors(self):
        learning = panel.bluetooth({"scanning": True, "learning": 61, "error": "", "kinds": [KIND]})
        self.assertEqual((learning["headline"]["word"], learning["rows"][0]["verdict"]["text"]), ("LEARNING", "learning"))
        self.assertIn("2 min left", learning["headline"]["line"])
        down = panel.bluetooth({"scanning": False, "learning": 0, "error": "no adapter", "kinds": []})
        self.assertEqual((down["status"]["state"], down["headline"]["severity"]), ("error", 3))

    def test_all_clear(self):
        p = panel.bluetooth({"scanning": True, "learning": 0, "error": "", "kinds": []})
        self.assertEqual((p["headline"]["severity"], p["headline"]["line"]), (0, "Nothing of interest nearby."))


class WifiPanelTests(unittest.TestCase):
    def test_a_threat(self):
        t = {"kind": "deauth", "label": "Deauth flood", "confidence": "high", "n": 2, "first": 10.0, "last": 20.0,
             "reason": "flooding Castle", "rssi": -50, "channel": 6, "frames": 40, "broadcast": True, "ssids": 0}
        p = panel.wifi({"scanning": True, "error": "", "channel": 6, "home": ["home"], "aps": 9, "threats": [t]})
        self.assertEqual(p["headline"]["severity"], 3)
        row = p["rows"][0]
        self.assertEqual(row["sub"][0], "flooding Castle · 40 frames, broadcast · ")
        self.assertEqual(row["sub"][1:], [{"for": 10.0}, ", last ", {"ago": 20.0}])
        self.assertEqual([c["text"] for c in row["cells"]], ["6", "-50"])

    def test_quiet_and_unplugged(self):
        quiet = panel.wifi({"scanning": True, "error": "", "channel": 1, "home": [], "aps": 3, "threats": []})
        self.assertEqual((quiet["headline"]["severity"], quiet["empty"], quiet["status"]["text"]), (0, "No attacks heard.", "ch 1"))
        gone = panel.wifi({"scanning": False, "error": "no dongle", "threats": []})
        self.assertEqual((gone["status"]["state"], gone["empty"]), ("error", "no dongle."))

    def test_a_known_pwnagotchi_is_greeted(self):
        p = panel.wifi({"scanning": True, "error": "", "channel": 1, "home": ["home"], "aps": 3,
                        "threats": [], "friends": [{"name": "Pwny", "face": "(◕‿◕)", "last": 5}]})
        self.assertEqual(p["headline"]["word"], "ALL CLEAR")
        self.assertIn("pwnagotchi Pwny is online!", p["headline"]["line"])
        self.assertIn("(◕‿◕)", p["headline"]["line"])

    def test_a_house_network_that_moved_is_news(self):
        p = panel.wifi({"scanning": True, "error": "", "channel": 1, "home": ["home"], "aps": 3, "threats": [],
                        "moved": [("home", 116)]})
        self.assertEqual((p["headline"]["severity"], p["headline"]["word"]), (0, "ALL CLEAR"))
        self.assertEqual(p["headline"]["line"], "home is on channel 116, which isn't in its list: update its channels")


class UpnpPanelTests(unittest.TestCase):
    def forward(self, allowed):
        return {"protocol": "TCP", "external_port": 25565, "client": "192.0.2.9", "internal_port": 25565,
                "description": "game", "enabled": True, "lease": 0, "allowed": allowed, "since": 50.0}

    def test_an_unexpected_forward_is_a_threat_first(self):
        p = panel.upnp({"error": "", "polled": 1.0, "allowed_rules": 1,
                        "mappings": [self.forward(True), {**self.forward(False), "external_port": 22}]})
        self.assertEqual((p["status"]["state"], p["headline"]["severity"]), ("error", 3))
        self.assertIn("1 UPnP port forward open that isn't", p["headline"]["line"])
        self.assertEqual([r["verdict"]["text"] for r in p["rows"]], ["unexpected", "allowed"])
        self.assertEqual(p["rows"][0]["sub"][1:], [" · seen ", {"mins": 50.0}])

    def test_none(self):
        p = panel.upnp({"error": "", "polled": 1.0, "allowed_rules": 0, "mappings": []})
        self.assertEqual((p["status"], p["empty"]), ({"state": "ok", "text": "0 forwards"}, "No ports forwarded. Good."))
        starting = panel.upnp({"error": "", "polled": None, "mappings": []})
        self.assertEqual(starting["status"]["state"], "starting")

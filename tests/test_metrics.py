import threading
import time
import unittest

from overwatch import web
from overwatch.hub import Hub
from overwatch.metrics import wifi_registry
from overwatch.scanner import make_server
from overwatch.watch import Watch
from overwatch.wifi import WifiWatch, parse
from tests.helpers import get, serve
from tests.test_wifi import HOME_AP, deauth


def metrics(base: str) -> str:
    status, body = get(base + "/metrics")
    assert status == 200, status
    return body.decode()


class ScannerMetricsTests(unittest.TestCase):
    def setUp(self):
        self.watch, self.hub = Watch(learn_seconds=0, started=0, linger_seconds=0), Hub()
        self.base, stop = serve(make_server(self.watch, self.hub, "127.0.0.1", 0, heartbeat=0.2))
        self.addCleanup(stop)

    def test_counts_by_kind_and_no_addresses(self):
        self.watch.scanning = True
        self.watch.advert("F0:12:34:56:78:9A", "findmy", -58)
        self.watch.advert("F0:12:34:56:78:9A", "findmy", -55)
        text = metrics(self.base)
        self.assertIn("overwatch_ble_scanning 1.0", text)
        self.assertIn('overwatch_ble_adverts_total{kind="findmy"} 2.0', text)
        self.assertIn('overwatch_ble_devices{kind="findmy"} 1.0', text)
        self.assertIn('overwatch_ble_closest_rssi_dbm{kind="findmy"} -55.0', text)
        self.assertNotIn("F0:12", text)
        self.assertNotIn("overwatch_wifi", text)  # the scanner has no Wi-Fi

    def test_alerts_are_counted(self):
        self.watch.advert("AA", "findmy", -60, now=100)
        self.watch.tick(now=100)
        self.watch.tick(now=101)
        self.assertIn('overwatch_ble_alerts_total{kind="findmy"} 1.0', metrics(self.base))

    def test_requests_counted(self):
        get(self.base + "/health")
        get(self.base + "/nope")
        text = metrics(self.base)
        self.assertIn('http_server_requests_total{code="200",method="GET",route="/health"} 1.0', text)
        self.assertIn('http_server_requests_total{code="404",method="GET",route="other"} 1.0', text)


class WifiMetricsTests(unittest.TestCase):
    def test_frames_threats_and_alerts(self):
        watch, hub = WifiWatch(deauth_frames=3), Hub()
        base, stop = serve(make_server(watch, hub, "127.0.0.1", 0, registry=wifi_registry))
        self.addCleanup(stop)
        for i in range(3):
            watch.heard(parse(deauth(HOME_AP)), -50, 6, now=100 + i * 0.1)
        text = metrics(base)
        self.assertIn('overwatch_wifi_frames_total{subtype="deauth"} 3.0', text)
        self.assertIn('overwatch_wifi_alerts_total{kind="deauth"} 1.0', text)
        self.assertIn("overwatch_wifi_capturing 0.0", text)
        self.assertNotIn("overwatch_ble", text)
        self.assertNotIn(HOME_AP, text)


class WebMetricsTests(unittest.TestCase):
    def test_upstream_up_and_stream_clients(self):
        watch, scanner_hub = Watch(learn_seconds=0, started=0), Hub()
        watch.scanning = True
        scanner_url, stop1 = serve(make_server(watch, scanner_hub, "127.0.0.1", 0, heartbeat=0.2))
        self.addCleanup(stop1)
        hub = Hub()
        relay = web.Relay([("scanner", scanner_url)], hub, timeout=1, retry=0.05)
        base, stop2 = serve(web.make_server(relay, hub, "127.0.0.1", 0, heartbeat=0.2))
        self.addCleanup(stop2)
        threading.Thread(target=relay.run, daemon=True).start()
        deadline = time.time() + 3
        while time.time() < deadline and not relay.ready:
            time.sleep(0.01)
        text = metrics(base)
        self.assertIn('overwatch_web_upstream_up{upstream="scanner"} 1.0', text)
        self.assertNotIn('upstream="wifi"', text)
        # The web pod follows the scanner's stream: one listener there.
        self.assertIn("overwatch_stream_clients 1.0", metrics(scanner_url))

"""Meraki API and MAC-to-port matching tests using mocked HTTP responses."""
import unittest
from unittest.mock import patch, MagicMock

from mac_finder.network.meraki import MerakiClient
from mac_finder.network.mac import normalize_mac


def _fake_response(payload):
    resp = MagicMock()
    resp.read.return_value = __import__("json").dumps(payload).encode("utf-8")
    resp.__enter__ = lambda self: self
    resp.__exit__ = lambda self, *a: False
    return resp


class MerakiClientMockTests(unittest.TestCase):
    def setUp(self):
        self.client = MerakiClient("test-key", timeout=5, max_retries=0)

    def _patch_get(self, mapping):
        """Patch urlopen so path -> payload. Match by normalized path (ignore query)."""
        def fake_urlopen(request, timeout=None):
            url = request.full_url
            # Normalize: split off query string for path matching
            if "?" in url:
                path = url.split("?")[0]
            else:
                path = url
            path = path.replace(MerakiClient.BASE_URL, "")
            # Prefer the longest (most specific) matching prefix so that
            # "/organizations" does not shadow "/organizations/111/devices".
            for key in sorted(mapping, key=len, reverse=True):
                if path == key or path.startswith(key):
                    return _fake_response(mapping[key])
            raise AssertionError(f"Unexpected URL path: {path}")
        return patch("urllib.request.urlopen", side_effect=fake_urlopen)

    def test_find_switch_by_mac_uses_inventory_filter(self):
        mapping = {
            "/organizations": [{"id": "111", "name": "Test Org"}],
            "/organizations/111/devices": [
                {
                    "productType": "switch", "model": "MS120-24P",
                    "serial": "Q4DE-57E5-WTP9", "mac": "B8:AB:61:AB:DA:6E",
                    "name": "core-sw", "networkId": "N_1", "lanIp": "10.0.0.2",
                    "firmware": "MS 14.40", "tags": ["core"],
                    "address": "HQ", "notes": "",
                }
            ],
        }
        with self._patch_get(mapping):
            found = self.client.find_switch_by_identifier("B8:AB:61:AB:DA:6E")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["serial"], "Q4DE-57E5-WTP9")
        self.assertEqual(found[0]["model"], "MS120-24P")
        self.assertEqual(normalize_mac(found[0]["mac"]), "B8:AB:61:AB:DA:6E")

    def test_find_switch_by_serial_and_model(self):
        mapping = {
            "/organizations": [{"id": "111", "name": "Test Org"}],
            "/organizations/111/devices": [
                {"productType": "switch", "model": "MS120-24P", "serial": "Q4DE-57E5-WTP9",
                 "mac": "B8:AB:61:AB:DA:6E", "networkId": "N_1"},
            ],
        }
        with self._patch_get(mapping):
            by_serial = self.client.find_switch_by_identifier("Q4DE-57E5-WTP9")
            by_model = self.client.find_switch_by_identifier("MS120-24P")
        self.assertEqual(len(by_serial), 1)
        self.assertEqual(len(by_model), 1)

    def test_find_client_port_network_clients(self):
        mapping = {
            "/organizations": [{"id": "111", "name": "Test Org"}],
            "/organizations/111/networks": [{"id": "N_1", "name": "Main"}],
            "/networks/N_1/clients": [
                {
                    "mac": "b8:ab:61:ab:da:6e", "ip": "10.0.0.50",
                    "manufacturer": "Cisco Meraki", "status": "Online",
                    "switchport": "Port 12", "vlan": 10,
                    "recentDeviceSerial": "Q4DE-57E5-WTP9",
                }
            ],
            "/organizations/111/devices": [],
        }
        with self._patch_get(mapping):
            result = self.client.find_client_port_by_mac("B8:AB:61:AB:DA:6E")
        self.assertIsNotNone(result["best_match"])
        self.assertEqual(result["best_match"]["source"], "network_clients")
        self.assertEqual(result["best_match"]["ip"], "10.0.0.50")
        self.assertEqual(result["best_match"]["vlan"], 10)
        self.assertEqual(result["best_match"]["switchport"], "Port 12")

    def test_find_client_port_mac_table_live_tool(self):
        client = self.client
        client.mac_table_create = MagicMock(return_value={"id": "job1"})
        client.mac_table_get = MagicMock(return_value={
            "status": "complete",
            "entries": [{"mac": "B8:AB:61:AB:DA:6E", "port": "Port 5", "vlanId": 20}],
        })
        client.device_clients = MagicMock(return_value=[])

        mapping = {
            "/organizations": [{"id": "111", "name": "Test Org"}],
            "/organizations/111/networks": [{"id": "N_1", "name": "Main"}],
            "/networks/N_1/clients": [],
            "/organizations/111/devices": [
                {"productType": "switch", "model": "MS120-24P",
                 "serial": "Q4DE-57E5-WTP9", "name": "sw1", "networkId": "N_1"},
            ],
        }
        with self._patch_get(mapping):
            result = client.find_client_port_by_mac("B8:AB:61:AB:DA:6E")
        self.assertIsNotNone(result["best_match"])
        self.assertEqual(result["best_match"]["source"], "mac_table")
        self.assertEqual(result["best_match"]["port"], "Port 5")
        self.assertEqual(result["best_match"]["vlan_id"], 20)

    def test_no_match_returns_empty_sources(self):
        mapping = {
            "/organizations": [{"id": "111", "name": "Test Org"}],
            "/organizations/111/networks": [],
        }
        with self._patch_get(mapping):
            result = self.client.find_client_port_by_mac("AA:BB:CC:DD:EE:FF")
        self.assertEqual(result["sources"], [])
        self.assertIsNone(result["best_match"])

    def test_429_retry_then_success(self):
        import urllib.error
        calls = {"n": 0}

        def fake_urlopen(request, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.HTTPError(
                    request.full_url, 429, "Too Many Requests", {"Retry-After": "0"}, None)
            return _fake_response([{"id": "1"}])

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            client = MerakiClient("k", timeout=5, max_retries=2)
            result = client.organizations()
        self.assertEqual(result, [{"id": "1"}])
        self.assertEqual(calls["n"], 2)

    def test_401_error_message(self):
        import urllib.error
        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, None)
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(RuntimeError) as ctx:
                self.client.organizations()
        self.assertIn("401", str(ctx.exception))
        self.assertIn("anahtar", str(ctx.exception).lower())

    def test_403_error_message(self):
        import urllib.error
        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(RuntimeError) as ctx:
                self.client.organizations()
        self.assertIn("403", str(ctx.exception))
        self.assertIn("yetki", str(ctx.exception).lower())

    def test_switch_ports_statuses_fields(self):
        mapping = {
            "/devices/Q4DE-57E5-WTP9/switch/ports/statuses": [
                {"portId": "1", "link": "up", "speed": "1 Gbps", "duplex": "full",
                 "isUplink": False, "poeEnabled": True, "powerUsageInWh": 12.5,
                 "vlan": 10, "clientCount": 1, "status": "connected"},
            ],
        }
        with self._patch_get(mapping):
            statuses = self.client.switch_ports_statuses("Q4DE-57E5-WTP9")
        self.assertEqual(statuses[0]["portId"], "1")
        self.assertIn("poeEnabled", statuses[0])
        self.assertIn("powerUsageInWh", statuses[0])

    def test_rate_limit_interval_enforced(self):
        import time
        client = MerakiClient("k", timeout=5)
        start = time.monotonic()
        client._throttle()
        client._throttle()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.10)


if __name__ == "__main__":
    unittest.main()

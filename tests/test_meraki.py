"""Meraki API and MAC-to-port matching tests using mocked HTTP responses."""
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock

from mac_finder.inventory.store import InventoryStore
from mac_finder.network.inspector import MerakiInspector
from mac_finder.network.meraki import (
    MerakiAPIError,
    MerakiClient,
    normalize_mac_table,
    normalize_poe_data,
    normalize_traffic_data,
    normalize_topology,
)
from mac_finder.network.security import SecureCredentialStore


class FakeResponse:
    def __init__(self, payload, headers=None):
        self.payload = payload
        self.headers = headers or {}

    def read(self):
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class MerakiClientTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.responses = []
        self.sleeps = []

        def opener(request, timeout):
            self.requests.append((request, timeout))
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        self.client = MerakiClient(
            "test-secret", opener=opener, sleep=self.sleeps.append,
            requests_per_second=10, max_retries=2,
        )
        self.client._throttle = MagicMock()
        self.client._throttle_live_tool = MagicMock()

    def test_uses_api_key_header_and_supported_inventory_filters(self):
        self.responses.append(FakeResponse([{
            "serial": "Q4DE-57E5-WTP9", "mac": "B8:AB:61:AB:DA:6E",
            "model": "MS120-24P", "productType": "switch",
        }]))
        devices = self.client.organization_devices("42", filters={"mac": "b8ab.61ab.da6e"})
        request = self.requests[0][0]
        self.assertEqual(request.get_header("X-cisco-meraki-api-key"), "test-secret")
        self.assertIn("mac=B8%3AAB%3A61%3AAB%3ADA%3A6E", request.full_url)
        self.assertEqual(devices[0]["model"], "MS120-24P")

    def test_follows_link_header_pagination(self):
        first = "https://api.meraki.com/api/v1/organizations/42/devices?perPage=1000"
        following = first + "&startingAfter=token"
        self.responses.extend([
            FakeResponse([{"serial": "A"}], {"Link": f'<{following}>; rel="next"'}),
            FakeResponse([{"serial": "B"}]),
        ])
        result = self.client.organization_devices("42")
        self.assertEqual([item["serial"] for item in result], ["A", "B"])
        self.assertEqual(self.requests[1][0].full_url, following)

    def test_short_term_cache_avoids_duplicate_requests(self):
        self.responses.append(FakeResponse([{"id": "1", "name": "Org"}]))
        self.assertEqual(self.client.organizations(), self.client.organizations())
        self.assertEqual(len(self.requests), 1)

    def test_retry_after_is_used_for_rate_limit(self):
        error = urllib.error.HTTPError(
            "https://api.meraki.com/api/v1/organizations", 429, "Too Many Requests",
            {"Retry-After": "2"}, io.BytesIO(b'{"errors":["slow down"]}'),
        )
        self.responses.extend([error, FakeResponse([])])
        self.assertEqual(self.client.organizations(), [])
        self.assertIn(2.0, self.sleeps)

    def test_401_403_and_404_have_actionable_messages(self):
        for status, text in {401: "anahtarı", 403: "izni", 404: "bulunamadı"}.items():
            with self.subTest(status=status):
                client = MerakiClient("secret", opener=MagicMock(), max_retries=0)
                client._throttle = MagicMock()
                client._opener.side_effect = urllib.error.HTTPError(
                    "https://api.meraki.com/api/v1/test", status, "error", {},
                    io.BytesIO(b'{"message":"denied"}'),
                )
                with self.assertRaises(MerakiAPIError) as caught:
                    client.get("/test")
                self.assertEqual(caught.exception.status, status)
                self.assertIn(text, str(caught.exception))

    def test_mac_table_is_async_and_filters_entries(self):
        target = "B8:AB:61:AB:DA:6E"
        self.responses.extend([
            FakeResponse({"macTableId": "job-1", "status": "new"}),
            FakeResponse({"macTableId": "job-1", "status": "running"}),
            FakeResponse({
                "macTableId": "job-1", "status": "complete",
                "entries": [
                    {"mac": target.lower(), "port": "5", "vlanId": 100},
                    {"mac": "00:11:22:33:44:55", "port": "6", "vlanId": 200},
                ],
            }),
        ])
        result = self.client.query_mac_table("Q4DE-57E5-WTP9", "b8ab.61ab.da6e", interval=0.5)
        self.assertEqual(json.loads(self.requests[0][0].data.decode()), {"mac": target})
        self.assertIn("/liveTools/macTable/job-1", self.requests[-1][0].full_url)
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual((result["entries"][0]["port"], result["entries"][0]["vlan_id"]), ("5", 100))

    def test_port_status_does_not_supply_client_mac_mapping(self):
        self.responses.extend([
            FakeResponse([{"id": "org-1", "name": "Test Org"}]),
            FakeResponse([{
                "serial": "Q4DE-57E5-WTP9", "networkId": "N_1",
                "productType": "switch", "model": "MS120-24P",
            }]),
            FakeResponse([{
                "id": "k74272e", "mac": "B8:AB:61:AB:DA:6E", "ip": "192.168.7.20",
                "status": "Online", "switchport": "7", "vlan": "100", "namedVlan": "Users",
                "recentDeviceConnection": "Wired", "recentDeviceSerial": "Q4DE-57E5-WTP9",
                "recentDeviceName": "Core Switch", "usage": {"sent": 12, "recv": 34},
            }]),
        ])
        result = self.client.find_switch_port("B8:AB:61:AB:DA:6E")
        self.assertEqual((result["port_id"], result["client_ip"], result["vlan"]), ("7", "192.168.7.20", "100"))
        self.assertFalse(any("/switch/ports/statuses" in request.full_url for request, _ in self.requests))

    def test_switch_ports_statuses_alias(self):
        self.responses.append(FakeResponse([{"portId": "1", "status": "Connected"}]))
        statuses = self.client.switch_ports_statuses("Q4DE-57E5-WTP9")
        self.assertEqual(statuses[0]["portId"], "1")

    def test_vlan_poe_and_energy_units_are_preserved(self):
        rows = MerakiClient.normalize_ports(
            [{"portId": "1", "vlan": 10, "nativeVlan": 1, "allowedVlans": "1-4094", "poeEnabled": True}],
            [{"portId": "1", "status": "Connected", "poe": {"isAllocated": True}, "powerUsageInWh": 55.9}],
        )
        self.assertEqual(rows[0]["config"]["vlan"], 10)
        self.assertTrue(rows[0]["poe"]["isAllocated"])
        power = normalize_poe_data(
            rows, {"status": "complete", "results": {"instant": 82.5, "peak": 120.0}},
            manufacturer_budget=370,
        )
        self.assertEqual(power["per_port"][0]["power_usage_wh"], 55.9)
        self.assertIsNone(power["per_port"][0]["instant_watts"])
        self.assertEqual((power["instant_w"], power["remaining_w"]), (82.5, 287.5))
        traffic = normalize_traffic_data(rows, [{
            "portId": "1", "packets": [{"desc": "Total", "total": 100, "sent": 70, "recv": 30,
                                        "ratePerSec": {"total": 2, "sent": 1, "recv": 1}}],
        }], retrieved_at=123.0)
        self.assertEqual((traffic[0]["packets_total"], traffic[0]["rate_total"]), (100, 2))
        self.assertIn("son 5 dakika", traffic[0]["freshness"])

    def test_topology_draws_only_two_ended_discovered_links(self):
        result = normalize_topology({
            "nodes": [
                {"derivedId": "a", "type": "device", "device": {"name": "Switch A"}},
                {"derivedId": "b", "type": "device", "device": {"name": "Switch B"}},
            ],
            "links": [
                {"ends": [{"node": {"derivedId": "a"}, "discovered": {"lldp": {"portId": "1"}}},
                          {"node": {"derivedId": "b"}, "discovered": {"cdp": {"portId": "2", "nativeVlan": 10}}}]},
                {"ends": [{"node": {"derivedId": "a"}}]},
            ],
        })
        self.assertEqual(len(result["links"]), 1)
        self.assertEqual(result["links"][0]["a_port"], "1")
        self.assertEqual(result["links"][0]["b_vlan"], 10)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.target = "B8:AB:61:AB:DA:6E"
        self.device = {"serial": "Q4DE-57E5-WTP9", "mac": self.target, "model": "MS120-24P",
                       "productType": "switch", "networkId": "N_1", "lanIp": "192.168.7.2",
                       "name": "Core Switch", "firmware": "MS 17.0"}

    def test_discovery_reports_every_source_without_inventing_identity(self):
        device = self.device

        class Client:
            def organizations(self):
                return [{"id": "org-1", "name": "Test Org"}]

            def organization_devices(self, organization_id, filters=None, network_ids=None):
                return [device]

        class Scanner:
            def __init__(self, *args, **kwargs):
                pass

            def find_mac(self, *args, **kwargs):
                return None

        with tempfile.TemporaryDirectory() as folder:
            store = InventoryStore(Path(folder) / "inventory.db")
            inspector = MerakiInspector(
                client=Client(), store=store,
                arp_provider=lambda: [{"ip": "192.168.7.2", "mac": self.target}],
                scanner_factory=Scanner,
                status_provider=lambda: {"reachable": False, "error": "DNS yok"},
            )
            result = inspector.discover(self.target, "192.168.7.0/24", "192.168.7.10")
            self.assertEqual(result["selected_device"]["serial"], "Q4DE-57E5-WTP9")
            self.assertEqual([item["source"] for item in result["evidence"]], [
                "SQLite envanteri", "Yerel ARP", "Yerel subnet", "Meraki API",
                "Yerel SNMP", "Local Status Page",
            ])
            self.assertEqual(store.get_meraki_device("Q4DE-57E5-WTP9")["model"], "MS120-24P")

    def test_conflicting_mac_sources_are_all_returned_with_timestamps(self):
        target = self.target

        class Client:
            def network_clients(self, network_id, mac=None):
                return [{"mac": target, "ip": "192.168.7.20", "switchport": "5", "vlan": "100",
                         "recentDeviceConnection": "Wired", "recentDeviceSerial": "Q4DE-57E5-WTP9",
                         "recentDeviceName": "Core"}]

            def device_clients(self, serial):
                return []

            def query_mac_table(self, serial, mac, **kwargs):
                return {"entries": [{"mac": mac, "port": "6", "vlan_id": 200,
                                     "observed_at": 200.0, "raw": {}}]}

        result = MerakiInspector(client=Client(), arp_provider=lambda: []).locate_mac(
            target, self.device, include_forwarding=True)
        self.assertTrue(result["found"])
        self.assertEqual({item["port"] for item in result["mappings"]}, {"5", "6"})
        self.assertTrue(all(item["observed_at"] for item in result["mappings"]))
        self.assertEqual({item["source"] for item in result["mappings"]}, {
            "Meraki network client", "Switch MAC forwarding table",
        })

    def test_mac_table_normalizer_accepts_official_port_field(self):
        result = normalize_mac_table({"status": "complete", "entries": [
            {"mac": self.target, "port": "24", "vlanId": 20},
        ]}, self.target)
        self.assertEqual(result["entries"][0]["port"], "24")


class CredentialTests(unittest.TestCase):
    def test_dpapi_roundtrip_never_writes_plaintext(self):
        with tempfile.TemporaryDirectory() as folder:
            store = SecureCredentialStore(Path(folder))
            secret = "never-store-this-plaintext-api-key"
            store.save("meraki_api_key", secret)
            self.assertEqual(store.load("meraki_api_key"), secret)
            self.assertNotIn(secret.encode(), (Path(folder) / "meraki_api_key.dpapi").read_bytes())
            store.delete("meraki_api_key")
            self.assertEqual(store.load("meraki_api_key"), "")


if __name__ == "__main__":
    unittest.main()

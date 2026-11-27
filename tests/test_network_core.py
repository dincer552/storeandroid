import unittest
from unittest.mock import patch, MagicMock

from mac_finder.network.mac import normalize_mac, macs_match
from mac_finder.network.scanner import ARPScanner


class MacAddressTests(unittest.TestCase):
    def test_normalizes_common_formats(self):
        self.assertEqual(normalize_mac("b8-ab-61-ab-da-6e"), "B8:AB:61:AB:DA:6E")
        self.assertEqual(normalize_mac("B8AB.61AB.DA6E"), "B8:AB:61:AB:DA:6E")
        self.assertIsNone(normalize_mac("not-a-mac"))
        self.assertTrue(macs_match("B8AB.61AB.DA6E", "B8:AB:61:AB:DA:6E"))


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.adapter = [{
            "name": "Ethernet", "ip": "192.168.7.10",
            "network": "192.168.7.0/24", "gateway": "192.168.7.1"
        }]

    @patch("mac_finder.network.scanner.resolve_hostname", return_value="meraki-switch")
    @patch("mac_finder.network.scanner.get_arp_table")
    @patch("mac_finder.network.scanner.get_active_adapters")
    def test_mac_lookup_stops_on_initial_arp_match(self, adapters, arp, hostname):
        arp.return_value = [{
            "ip": "192.168.7.50", "mac": "B8-AB-61-AB-DA-6E",
            "type": "dynamic", "interface": "192.168.7.10"
        }]
        adapters.return_value = self.adapter
        scanner = ARPScanner("B8:AB:61:AB:DA:6E")
        scanner._scapy_sweep = MagicMock()
        scanner._ping = MagicMock()
        found = scanner.find_mac("b8ab.61ab.da6e", "192.168.7.0/24", "192.168.7.10")
        self.assertEqual(found["ip"], "192.168.7.50")
        self.assertEqual(found["method"], "arp_table")
        self.assertTrue(found["online"])
        scanner._scapy_sweep.assert_not_called()
        scanner._ping.assert_not_called()

    @patch("mac_finder.network.scanner.get_active_adapters")
    def test_rejects_subnet_outside_active_adapter(self, adapters):
        adapters.return_value = self.adapter
        scanner = ARPScanner()
        with self.assertRaises(ValueError):
            scanner.scan_network("10.10.10.0/24", "192.168.7.10")

    @patch("mac_finder.network.scanner.resolve_hostname", return_value="host-1")
    @patch("mac_finder.network.scanner.get_arp_table")
    @patch("mac_finder.network.scanner.get_active_adapters")
    def test_full_scan_refreshes_arp_after_ping(self, adapters, arp, hostname):
        adapters.return_value = self.adapter
        arp.side_effect = [
            [],
            [{"ip": "192.168.7.2", "mac": "00-11-22-33-44-55",
              "type": "static", "interface": "192.168.7.10"}]
        ]
        scanner = ARPScanner(workers=4)
        scanner._scapy_sweep = lambda network: []
        scanner._ping = lambda ip, timeout: True
        found = scanner.scan_network("192.168.7.0/30", "192.168.7.10")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["ip"], "192.168.7.2")
        self.assertEqual(found[0]["method"], "ping+arp")


if __name__ == "__main__":
    unittest.main()

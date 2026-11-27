import tempfile
import time
import unittest
from pathlib import Path

from mac_finder.inventory.store import InventoryStore


class InventoryTests(unittest.TestCase):
    def test_persists_device_and_preserves_first_seen_and_custom_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            store = InventoryStore(Path(folder) / "inventory.db")
            device = {
                "mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.1.20",
                "hostname": "controller-1", "vendor": "Example",
                "gateway": "192.168.1.1", "interface": "Ethernet",
                "method": "arp_table", "online": True
            }
            self.assertEqual(store.save_scan_results([device], "192.168.1.0/24"), 1)
            first = store.get_device("AA:BB:CC:DD:EE:FF")
            first_seen = first["first_seen"]
            store.update_custom_fields(first["mac"], "AHU PLC", "Panel-1")
            time.sleep(0.02)
            device["ip"] = "192.168.1.21"
            self.assertEqual(store.save_scan_results([device], "192.168.1.0/24"), 0)
            updated = store.get_device(first["mac"])
            self.assertEqual(updated["first_seen"], first_seen)
            self.assertEqual(updated["custom_name"], "AHU PLC")
            self.assertEqual(updated["notes"], "Panel-1")
            self.assertEqual(updated["ip"], "192.168.1.21")
            self.assertTrue(updated["online"])
            last_seen = updated["last_seen"]
            store.save_scan_results([], "192.168.1.0/24")
            offline = store.get_device(first["mac"])
            self.assertFalse(offline["online"])
            self.assertEqual(offline["first_seen"], first_seen)
            self.assertEqual(offline["last_seen"], last_seen)

    def test_scan_only_marks_same_subnet_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            store = InventoryStore(Path(folder) / "inventory.db")
            items = [
                {"mac":"00:00:00:00:00:01","ip":"192.168.1.5","online":True},
                {"mac":"00:00:00:00:00:02","ip":"192.168.2.5","online":True},
            ]
            store.save_scan_results(items)
            store.save_scan_results([], "192.168.1.0/24")
            self.assertFalse(store.get_device(items[0]["mac"])["online"])
            self.assertTrue(store.get_device(items[1]["mac"])["online"])


if __name__ == "__main__":
    unittest.main()

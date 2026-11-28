import sys
sys.path.insert(0, '.')

from mac_finder.config import Config
from mac_finder.gui.main_window import MACFinderApp
from mac_finder.gui.meraki_ui import MerakiUIManager, MS120_24P_SPEC
from mac_finder.network.meraki import MerakiClient, find_switch_port_legacy
from mac_finder.network.snmp import SnmpClient, snmp_v3_available

print("=== MAC Finder Pro - Import Test ===")
print("Config test MAC:", Config.get_test_mac())
print("MS120-24P spec RJ45 ports:", MS120_24P_SPEC["rj45"], "SFP ports:", MS120_24P_SPEC["sfp"])
print("pysnmp (v3) available:", snmp_v3_available())
print("MerakiClient methods:",
      hasattr(MerakiClient, "find_client_port_by_mac"),
      hasattr(MerakiClient, "switch_ports_statuses"),
      hasattr(MerakiClient, "switch_ports_packets"),
      hasattr(MerakiClient, "mac_table_create"),
      hasattr(MerakiClient, "power_usage_create"))
print("MerakiUIManager pages: render() method present:", hasattr(MerakiUIManager, "render"))
print("ALL IMPORTS OK")
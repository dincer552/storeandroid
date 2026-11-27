"""Offline vendor lookup using a small built-in OUI fallback list."""
from .mac import mac_to_oui

OUI_REGISTRY = {
    "B8:AB:61":"Cisco Meraki", "00:18:0A":"Cisco Meraki", "00:1E:13":"Cisco Meraki",
    "00:0D:DD":"Cisco Systems", "00:1A:A3":"Cisco Systems", "00:1B:0D":"Cisco Systems",
    "00:1D:45":"Cisco Systems", "00:1E:2A":"Cisco Systems", "00:1F:9F":"Cisco Systems",
    "00:21:6A":"Cisco Systems", "00:22:BD":"Cisco Systems", "00:23:5E":"Cisco Systems",
    "00:24:C4":"Cisco Systems", "00:25:83":"Cisco Systems", "00:26:0B":"Cisco Systems",
    "00:00:0C":"Cisco Systems", "00:40:96":"Cisco Systems", "00:60:09":"Cisco Systems",
    "00:60:2F":"Cisco Systems", "00:E0:1E":"Cisco Systems", "CC:46:D6":"Cisco Systems",
    "08:00:27":"Oracle VirtualBox", "00:0C:29":"VMware", "00:50:56":"VMware",
    "B8:27:EB":"Raspberry Pi", "DC:A6:32":"Raspberry Pi", "E4:5F:01":"Espressif",
    "18:FE:34":"Espressif", "D0:EF:76":"Espressif", "52:54:00":"QEMU/KVM"
}


def lookup_vendor(mac):
    oui = mac_to_oui(mac)
    return OUI_REGISTRY.get(oui, "Bilinmiyor") if oui else "Bilinmiyor"

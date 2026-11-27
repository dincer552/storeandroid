"""MAC address normalization and comparison."""
import re


def normalize_mac(mac):
    if not mac:
        return None
    value = re.sub(r"[.:\-\s]", "", str(mac)).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", value):
        return None
    return ":".join(value[index:index+2] for index in range(0, 12, 2))


def mac_to_oui(mac):
    normalized = normalize_mac(mac)
    return normalized[:8] if normalized else None


def macs_match(mac1, mac2):
    first, second = normalize_mac(mac1), normalize_mac(mac2)
    return bool(first and second and first == second)

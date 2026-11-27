def normalize_mac(mac):
    """Normalize MAC address to uppercase with colons."""
    if not mac:
        return None
    mac = mac.strip().upper()
    mac = mac.replace("-", ":").replace(".", ":").replace(" ", ":")
    parts = [p for p in mac.split(":") if p]
    if len(parts) != 6:
        return None
    for p in parts:
        if len(p) != 2 or not all(c in "0123456789ABCDEF" for c in p):
            return None
    return ":".join(parts)

def mac_to_oui(mac):
    """Extract OUI (first 3 octets) from MAC address."""
    norm = normalize_mac(mac)
    if not norm:
        return None
    return norm[:8]

def macs_match(mac1, mac2):
    """Check if two MAC addresses match."""
    return normalize_mac(mac1) == normalize_mac(mac2)
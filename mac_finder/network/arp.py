import subprocess
import re
import platform

def get_arp_table():
    """
    Parse Windows ARP table.
    Returns list of dicts: {ip, mac, interface}
    """
    entries = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        )
        if result.returncode != 0:
            return entries
        
        current_interface = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Interface line
            if line.startswith("Interface:"):
                parts = line.split()
                if len(parts) >= 2:
                    current_interface = parts[1]
                continue
            
            # ARP entry line: IP address      Physical address     Type
            # e.g.  192.168.1.1         00-11-22-33-44-55     dynamic
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                entry_type = match.group(3)
                entries.append({
                    "ip": ip,
                    "mac": mac,
                    "type": entry_type,
                    "interface": current_interface,
                })
    except Exception:
        pass
    return entries

def get_gateway_from_arp():
    """Try to find default gateway from ARP table."""
    entries = get_arp_table()
    # Common gateway IPs end in .1 or .254
    for entry in entries:
        ip = entry["ip"]
        if ip.endswith(".1") or ip.endswith(".254"):
            return ip
    return None
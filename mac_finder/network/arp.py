"""Cross-platform ARP / neighbour table reader."""
import platform
import re
import subprocess


def _run(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if platform.system() == "Windows" else 0).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def get_arp_table():
    """Return neighbour entries as {ip, mac, type, interface}."""
    entries = []
    if platform.system().lower() == "windows":
        output = _run(["arp", "-a"])
        current_interface = "Bilinmiyor"
        for line in output.splitlines():
            line = line.strip()
            if line.lower().startswith("interface:"):
                match = re.search(r"Interface:\s*([\d.]+)", line, re.I)
                if match:
                    current_interface = match.group(1)
                continue
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
            if match:
                entries.append({"ip":match.group(1), "mac":match.group(2).replace("-", ":").upper(),
                                "type":match.group(3).lower(), "interface":current_interface})
    else:
        output = _run(["ip", "neigh", "show"])
        for line in output.splitlines():
            match = re.match(r"(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9a-fA-F:]{17}))?(?:\s+(\S+))?", line)
            if match and match.group(3):
                entries.append({"ip":match.group(1), "mac":match.group(3).upper(),
                                "type":(match.group(4) or "reachable").lower(), "interface":match.group(2)})
    return entries


def get_gateway_from_arp():
    """Resolve the default gateway from the routing table (not an IP suffix heuristic)."""
    if platform.system().lower() == "windows":
        output = _run(["route", "print", "-4"])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[:2] == ["0.0.0.0", "0.0.0.0"]:
                return parts[2]
    else:
        output = _run(["ip", "route", "show", "default"])
        match = re.search(r"^default via (\S+)", output, re.M)
        if match:
            return match.group(1)
    return None

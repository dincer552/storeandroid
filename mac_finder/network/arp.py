"""Read the operating system's neighbour/ARP table without packet injection."""
import platform
import re
import subprocess


def _run(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            if platform.system().lower() == "windows" else 0).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def get_arp_table():
    """Return entries as dictionaries with ip, mac, type, and interface."""
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
            match = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line
            )
            if match:
                entries.append({
                    "ip": match.group(1),
                    "mac": match.group(2).replace("-", ":").upper(),
                    "type": match.group(3).lower(),
                    "interface": current_interface,
                })
    else:
        output = _run(["ip", "neigh", "show"])
        for line in output.splitlines():
            match = re.match(
                r"(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+([0-9a-fA-F:]{17}))?(?:\s+(\S+))?",
                line
            )
            if match and match.group(3):
                entries.append({
                    "ip": match.group(1),
                    "mac": match.group(3).upper(),
                    "type": (match.group(4) or "reachable").lower(),
                    "interface": match.group(2),
                })
    return entries


def get_gateway_from_arp():
    """Compatibility wrapper; gateway is obtained from the route table."""
    from .adapter import get_active_adapters
    adapters = get_active_adapters()
    return adapters[0].get("gateway") if adapters else None

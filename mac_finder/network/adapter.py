"""Network adapter discovery helpers."""
import platform
import re
import subprocess
import socket
import psutil


def _default_gateway():
    system = platform.system().lower()
    command = ["route", "print", "-4"] if system == "windows" else ["ip", "route", "show", "default"]
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if system == "windows" else 0).stdout
        if system == "windows":
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[:2] == ["0.0.0.0", "0.0.0.0"]:
                    return parts[2]
        else:
            match = re.search(r"^default via (\S+)", output, re.M)
            if match:
                return match.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def get_active_adapters():
    """Return active non-loopback IPv4 adapters with OS-reported link details."""
    adapters = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    gateway = _default_gateway()
    link_family = getattr(psutil, "AF_LINK", None)
    for name, address_list in addrs.items():
        state = stats.get(name)
        if not state or not state.isup:
            continue
        ipv4 = next((addr for addr in address_list
                     if addr.family == socket.AF_INET and addr.address and addr.netmask), None)
        if not ipv4 or ipv4.address.startswith(("127.", "169.254.")):
            continue
        mac = next((addr.address for addr in address_list
                    if link_family is not None and addr.family == link_family), "Bilinmiyor")
        try:
            prefixlen = sum(bin(int(octet)).count("1") for octet in ipv4.netmask.split("."))
        except (AttributeError, ValueError):
            prefixlen = 0
        adapters.append({
            "name": name, "ip": ipv4.address, "netmask": ipv4.netmask,
            "prefixlen": prefixlen, "mac": mac, "gateway": gateway or "Bilinmiyor",
            "speed_mbps": state.speed or 0, "mtu": state.mtu or 0,
            "duplex": str(state.duplex), "is_up": state.isup
        })
    return adapters


def get_adapter_stats():
    """Return per-interface byte and packet counters."""
    try:
        return psutil.net_io_counters(pernic=True)
    except Exception:
        return {}

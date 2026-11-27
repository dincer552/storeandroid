"""Windows/Linux adapter discovery using psutil and the OS route table."""
import ipaddress
import platform
import re
import socket
import subprocess

import psutil


def _run(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            if platform.system().lower() == "windows" else 0).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _default_gateways():
    gateways = {}
    if platform.system().lower() == "windows":
        output = _run(["route", "print", "-4"])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                try:
                    ipaddress.IPv4Address(parts[2])
                    ipaddress.IPv4Address(parts[3])
                    gateways[parts[3]] = parts[2]
                except ValueError:
                    continue
    else:
        output = _run(["ip", "-4", "route", "show", "default"])
        for line in output.splitlines():
            via = re.search(r"\bvia\s+(\S+)", line)
            dev = re.search(r"\bdev\s+(\S+)", line)
            if via and dev:
                gateways[dev.group(1)] = via.group(1)
    return gateways


def get_active_adapters():
    """Return usable IPv4 interfaces and their OS-reported link metadata."""
    adapters = []
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    gateways = _default_gateways()
    link_family = getattr(psutil, "AF_LINK", getattr(socket, "AF_PACKET", None))

    for name, address_list in addresses.items():
        state = stats.get(name)
        if not state or not state.isup:
            continue
        ipv4 = next((address for address in address_list
                     if address.family == socket.AF_INET and address.address and address.netmask), None)
        if not ipv4:
            continue
        try:
            ip = ipaddress.IPv4Address(ipv4.address)
            network = ipaddress.IPv4Network(f"{ipv4.address}/{ipv4.netmask}", strict=False)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            continue

        mac = "Bilinmiyor"
        if link_family is not None:
            mac = next((address.address.upper().replace("-", ":")
                        for address in address_list
                        if address.family == link_family and address.address), mac)
        gateway = gateways.get(ipv4.address)
        if not gateway and platform.system().lower() != "windows":
            gateway = gateways.get(name)
        adapters.append({
            "name": name,
            "ip": ipv4.address,
            "netmask": ipv4.netmask,
            "prefixlen": network.prefixlen,
            "network": str(network),
            "mac": mac,
            "gateway": gateway or "Bilinmiyor",
            "speed_mbps": int(state.speed or 0),
            "mtu": int(state.mtu or 0),
            "duplex": str(state.duplex),
            "is_up": bool(state.isup),
        })
    return adapters


def get_adapter_stats():
    """Per-interface traffic counters."""
    try:
        return psutil.net_io_counters(pernic=True)
    except Exception:
        return {}

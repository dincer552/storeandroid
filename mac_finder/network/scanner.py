"""Bounded local IPv4 discovery using ARP cache, optional Scapy, then ping + ARP."""
import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..network.adapter import get_active_adapters
from ..network.arp import get_arp_table
from ..network.mac import normalize_mac, macs_match
from ..network.vendor import lookup_vendor
from .hostname import resolve_hostname


class ARPScanner:
    def __init__(self, target_mac=None, workers=48, timeout_ms=650, max_hosts=4096):
        self.target_mac = normalize_mac(target_mac) if target_mac else None
        self.workers = max(4, min(int(workers), 96))
        self.timeout_ms = max(250, min(int(timeout_ms), 3000))
        self.max_hosts = max(16, min(int(max_hosts), 4096))
        self.cancelled = False
        self.scan_progress = 0
        self.total_devices = 0
        self.found_device = None

    def cancel(self):
        self.cancelled = True

    @staticmethod
    def _safe_entries(entries, network):
        result = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            try:
                address = ipaddress.ip_address(entry.get("ip", ""))
                if address in network and normalize_mac(entry.get("mac")):
                    item = dict(entry)
                    item["mac"] = normalize_mac(item["mac"])
                    item["ip"] = str(address)
                    result[item["ip"]] = item
            except ValueError:
                continue
        return result

    @staticmethod
    def _online(entry):
        state = (entry.get("type") or "").lower()
        return state in {"dynamic", "reachable", "delay", "probe", "permanent", "noarp"}

    def _adapter_for(self, network, selected_adapter_ip=None):
        adapters = get_active_adapters()
        candidates = []
        if selected_adapter_ip:
            selected = next((item for item in adapters if item["ip"] == selected_adapter_ip), None)
            if not selected:
                raise ValueError("Selected network adapter is no longer active.")
            candidates = [selected]
        else:
            candidates = adapters
        for adapter in candidates:
            try:
                local_network = ipaddress.ip_network(adapter["network"], strict=False)
                if network.subnet_of(local_network):
                    return adapter
            except (KeyError, ValueError):
                continue
        raise ValueError(
            "For safety, scans are restricted to a subnet inside the selected active adapter's local network."
        )

    @staticmethod
    def _interface_name(entry, adapter):
        interface = entry.get("interface") or ""
        if interface == adapter.get("ip"):
            return adapter.get("name", interface)
        if interface:
            return interface
        return adapter.get("name", "Bilinmiyor")

    def _device(self, entry, adapter, method):
        return {
            "mac": normalize_mac(entry["mac"]),
            "ip": entry["ip"],
            "hostname": resolve_hostname(entry["ip"]),
            "vendor": lookup_vendor(entry["mac"]),
            "gateway": adapter.get("gateway", "Bilinmiyor"),
            "interface": self._interface_name(entry, adapter),
            "method": method,
            "online": self._online(entry),
            "first_seen": None,
            "last_seen": time.time(),
        }

    @staticmethod
    def _ping(ip, timeout_ms):
        system = platform.system().lower()
        if system == "windows":
            command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            command = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
        try:
            result = subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=(timeout_ms / 1000) + 2,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if system == "windows" else 0,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _scapy_sweep(self, network):
        """Optional Layer-2 ARP discovery. Requires Scapy and a suitable capture driver."""
        try:
            from scapy.all import ARP, Ether, srp
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                timeout=1.5, retry=1, verbose=0
            )
            return [
                {"ip": received.psrc, "mac": received.hwsrc,
                 "type": "reachable", "interface": "Scapy"}
                for _, received in answered
            ]
        except Exception:
            # Missing Scapy, Npcap, permissions, or unsupported capture driver is a normal fallback.
            return []

    def _validate_network(self, cidr):
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 subnet: {exc}")
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 subnet scans are supported.")
        host_count = max(0, network.num_addresses - 2)
        if host_count > self.max_hosts:
            raise ValueError(
                f"Subnet has {host_count} host addresses; maximum is {self.max_hosts}."
            )
        return network

    def scan_network(self, cidr, selected_adapter_ip=None, progress_callback=None):
        """Discover all responsive/cached devices on one bounded local IPv4 subnet."""
        network = self._validate_network(cidr)
        adapter = self._adapter_for(network, selected_adapter_ip)
        self.cancelled = False
        self.scan_progress = 0
        self.total_devices = max(0, network.num_addresses - 2)

        # Step 1: current OS neighbour cache.
        entries = self._safe_entries(get_arp_table(), network)
        methods = {ip: "arp_table" for ip in entries}

        # Step 2: optional raw ARP discovery; gracefully fall back when unavailable.
        for ip, entry in self._safe_entries(self._scapy_sweep(network), network).items():
            entries[ip] = entry
            methods[ip] = "scapy"

        # Step 3: bounded ping sweep. Refresh ARP after each small batch.
        hosts = [str(host) for host in network.hosts()]
        responded = set()
        batch_size = max(8, self.workers)
        for offset in range(0, len(hosts), batch_size):
            if self.cancelled:
                break
            batch = hosts[offset:offset + batch_size]
            with ThreadPoolExecutor(max_workers=min(self.workers, len(batch) or 1)) as pool:
                futures = {pool.submit(self._ping, host, self.timeout_ms): host for host in batch}
                for future in as_completed(futures):
                    if self.cancelled:
                        break
                    if future.result():
                        responded.add(futures[future])
                    self.scan_progress += 1
                    if progress_callback:
                        progress_callback(self.scan_progress, self.total_devices)
            refreshed = self._safe_entries(get_arp_table(), network)
            for ip, entry in refreshed.items():
                if ip not in entries:
                    methods[ip] = "ping+arp"
                entries[ip] = entry

        devices = []
        for ip in sorted(entries, key=ipaddress.ip_address):
            entry = entries[ip]
            method = "ping+arp" if ip in responded else methods.get(ip, "arp_table")
            device = self._device(entry, adapter, method)
            if ip in responded:
                device["online"] = True
            devices.append(device)
        return devices

    def find_mac(self, mac, cidr, selected_adapter_ip=None, progress_callback=None):
        """Find one MAC; stop after an ARP/Scapy/ping batch reveals the target."""
        target = normalize_mac(mac)
        if not target:
            raise ValueError("Invalid MAC address.")
        network = self._validate_network(cidr)
        adapter = self._adapter_for(network, selected_adapter_ip)
        self.cancelled = False
        self.total_devices = max(0, network.num_addresses - 2)
        self.scan_progress = 0

        entries = self._safe_entries(get_arp_table(), network)
        for ip, entry in entries.items():
            if macs_match(entry.get("mac"), target):
                self.found_device = self._device(entry, adapter, "arp_table")
                return self.found_device

        for ip, entry in self._safe_entries(self._scapy_sweep(network), network).items():
            if macs_match(entry.get("mac"), target):
                self.found_device = self._device(entry, adapter, "scapy")
                return self.found_device
            entries[ip] = entry

        hosts = [str(host) for host in network.hosts()]
        batch_size = max(8, self.workers)
        for offset in range(0, len(hosts), batch_size):
            if self.cancelled:
                break
            batch = hosts[offset:offset + batch_size]
            responded = set()
            with ThreadPoolExecutor(max_workers=min(self.workers, len(batch) or 1)) as pool:
                futures = {pool.submit(self._ping, host, self.timeout_ms): host for host in batch}
                for future in as_completed(futures):
                    if self.cancelled:
                        break
                    if future.result():
                        responded.add(futures[future])
                    self.scan_progress += 1
                    if progress_callback:
                        progress_callback(self.scan_progress, self.total_devices)
            refreshed = self._safe_entries(get_arp_table(), network)
            for ip, entry in refreshed.items():
                entries[ip] = entry
                if macs_match(entry.get("mac"), target):
                    self.found_device = self._device(entry, adapter, "ping+arp")
                    if ip in responded:
                        self.found_device["online"] = True
                    return self.found_device
        self.found_device = None
        return None

    def scan_subnet(self, ip, netmask, selected_adapter_ip=None, progress_callback=None):
        return self.scan_network(
            f"{ip}/{netmask}", selected_adapter_ip=selected_adapter_ip,
            progress_callback=progress_callback
        )

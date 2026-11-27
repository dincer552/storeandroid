"""Safe, bounded local subnet and target-MAC discovery."""
import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..network.adapter import get_active_adapters
from ..network.arp import get_arp_table, get_gateway_from_arp
from ..network.mac import normalize_mac, macs_match
from ..network.vendor import lookup_vendor


class ARPScanner:
    def __init__(self, target_mac=None, workers=48, timeout_ms=650, max_hosts=4096):
        self.target_mac = normalize_mac(target_mac) if target_mac else None
        self.workers = max(4, min(int(workers), 128))
        self.timeout_ms = max(200, min(int(timeout_ms), 5000))
        self.max_hosts = max(16, min(int(max_hosts), 65536))
        self.found_device = None
        self.scan_progress = 0
        self.total_devices = 0
        self.cancelled = False

    def cancel(self):
        self.cancelled = True

    def _ping(self, ip):
        system = platform.system().lower()
        command = (["ping", "-n", "1", "-w", str(self.timeout_ms), ip] if system == "windows"
                   else ["ping", "-c", "1", "-W", str(max(1, self.timeout_ms // 1000)), ip])
        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=max(2, self.timeout_ms / 1000 + 1),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if system == "windows" else 0)
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _hostname(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            return "Bilinmiyor"

    def _make_device(self, entry, adapter, method):
        state = entry.get("type", "").lower()
        return {
            "ip": entry["ip"], "mac": entry["mac"], "hostname": self._hostname(entry["ip"]),
            "vendor": lookup_vendor(entry["mac"]),
            "interface": entry.get("interface") or adapter.get("name", "Bilinmiyor"),
            "gateway": adapter.get("gateway", "Bilinmiyor"),
            "online": state not in ("incomplete", "failed", "static"),
            "method": method, "timestamp": time.time()
        }

    def scan_network(self, cidr, progress_callback=None):
        """Discover devices in a supplied IPv4 CIDR; only scan bounded local ranges."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError("Geçersiz IP/CIDR: " + str(exc))
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Şu anda yalnızca IPv4 subnet taraması destekleniyor.")
        if network.num_addresses - 2 > self.max_hosts:
            raise ValueError(f"Ağ çok büyük ({network.num_addresses} adres). Tarama sınırı: {self.max_hosts} adres.")
        adapters = get_active_adapters()
        adapter = next((item for item in adapters if ipaddress.ip_address(item["ip"]) in network),
                       adapters[0] if adapters else {"name":"Bilinmiyor", "gateway":"Bilinmiyor"})
        entries = {entry["ip"]: entry for entry in get_arp_table() if entry.get("ip") and entry.get("mac")}
        self.total_devices = max(0, network.num_addresses - 2)
        self.scan_progress = 0
        results = []
        known = {ip: entry for ip, entry in entries.items()
                 if ipaddress.ip_address(ip) in network and entry.get("type") not in ("incomplete", "failed")}
        for entry in known.values():
            results.append(self._make_device(entry, adapter, "ARP önbelleği"))
        targets = [str(ip) for ip in network.hosts() if str(ip) not in known and not self.cancelled]
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._ping, ip): ip for ip in targets}
            for future in as_completed(futures):
                if self.cancelled:
                    for pending in futures:
                        pending.cancel()
                    break
                future.result()
                self.scan_progress += 1
                if progress_callback:
                    progress_callback(self.scan_progress, self.total_devices)
        # Re-read ARP after ping. A cache snapshot from before probing misses newly learned MACs.
        for entry in get_arp_table():
            if entry.get("ip") and entry.get("mac") and ipaddress.ip_address(entry["ip"]) in network:
                entries[entry["ip"]] = entry
        seen = {device["ip"] for device in results}
        for ip, entry in entries.items():
            if ip not in seen and ipaddress.ip_address(ip) in network:
                results.append(self._make_device(entry, adapter, "Ping + ARP"))
        return sorted(results, key=lambda item: ipaddress.ip_address(item["ip"]))

    def scan_subnet(self, ip, netmask, progress_callback=None):
        # ip_network accepts dotted netmasks; never cast 255.255.255.0 to int.
        return self.scan_network(f"{ip}/{netmask}", progress_callback)

    def find_mac(self, mac, cidr, progress_callback=None):
        target = normalize_mac(mac)
        if not target:
            raise ValueError("Geçersiz MAC adresi")
        self.target_mac = target
        try:
            requested_network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError("Geçersiz IP/CIDR: " + str(exc))
        match = next((entry for entry in get_arp_table()
                      if entry.get("ip") and ipaddress.ip_address(entry["ip"]) in requested_network
                      and macs_match(entry.get("mac"), target)), None)
        adapters = get_active_adapters()
        adapter = next((item for item in adapters if match and item["ip"] == match.get("interface")),
                       adapters[0] if adapters else {
                           "name":"Bilinmiyor", "gateway":get_gateway_from_arp() or "Bilinmiyor"})
        if match:
            self.found_device = self._make_device(match, adapter, "ARP önbelleği")
            return self.found_device
        devices = self.scan_network(cidr, progress_callback)
        self.found_device = next((device for device in devices if macs_match(device.get("mac"), target)), None)
        return self.found_device

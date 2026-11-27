import time
import socket
import re
import subprocess
import platform
import ipaddress
from typing import List, Dict, Optional
from ..network.adapter import get_active_adapters
from ..network.mac import normalize_mac, macs_match
from ..network.vendor import lookup_vendor
from ..network.arp import get_arp_table, get_gateway_from_arp

class ARPScanner:
    """ARP scanner engine."""
    
    def __init__(self, target_mac: str):
        self.target_mac = normalize_mac(target_mac)
        self.found_device = None
        self.scan_progress = 0
        self.total_devices = 0
        
    def scan_subnet(self, ip: str, netmask: str) -> List[Dict]:
        """Scan local subnet for devices matching target MAC."""
        # Extract network prefix
        import ipaddress
        network = ipaddress.ip_network(f"{ip}/{int(netmask)}", strict=False)
        self.total_devices = len(network)
        
        results = []
        self.scan_progress = 0
        
        print(f"Scanning subnet {network}")
        
        # Use ping sweep with concurrency
        active_adapters = get_active_adapters()
        if not active_adapters:
            raise RuntimeError("No active network adapters found")
            
        for adapter in active_adapters:
            ip_addr = adapter["ip"]
            netmask_val = adapter["netmask"]
            
            # Calculate network range
            try:
                net = ipaddress.ip_network(f"{ip_addr}/{int(netmask_val)}", strict=False)
                hosts = list(net.hosts())  # Exclude network and broadcast
                
                for target_ip in hosts:
                    self.scan_progress += 1
                    # Check if target MAC matches any found device
                    device_info = self._check_device(target_ip, target_mac)
                    if device_info:
                        results.append(device_info)
                        self.found_device = device_info
                        # Stop scanning once target is found
                        return results
                        
            except Exception as e:
                print(f"Error scanning {adapter}: {e}")
                continue
                
        return results
        
    def _check_device(self, ip: str, target_mac: str) -> Optional[Dict]:
        """Check if a device matches the target MAC."""
        # First check ARP table
        arp_entries = get_arp_table()
        for entry in arp_entries:
            if entry["ip"] == ip and macs_match(entry["mac"], target_mac):
                return {
                    "ip": ip,
                    "mac": entry["mac"],
                    "interface": entry["interface"],
                    "hostname": self._get_hostname(ip) or "Bilinmiyor",
                    "vendor": lookup_vendor(entry["mac"]),
                    "online": entry["type"] == "dynamic",
                    "method": "arp_table",
                    "timestamp": time.time()
                }
                
        # Then try ping sweep (if needed)
        try:
            # Try ping first
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            if result.returncode == 0:
                # Device is online, check if MAC matches
                arp_entries = get_arp_table()
                for entry in arp_entries:
                    if entry["ip"] == ip and macs_match(entry["mac"], target_mac):
                        return {
                            "ip": ip,
                            "mac": entry["mac"],
                            "interface": entry["interface"],
                            "hostname": self._get_hostname(ip) or "Bilinmiyor",
                            "vendor": lookup_vendor(entry["mac"]),
                            "online": True,
                            "method": "ping",
                            "timestamp": time.time()
                        }
        except Exception as e:
            pass
            
        return None
        
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Try to resolve hostname from IP."""
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
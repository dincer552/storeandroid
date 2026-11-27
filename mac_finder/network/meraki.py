"""Optional Cisco Meraki Dashboard read-only lookup."""
import json
import urllib.error
import urllib.parse
import urllib.request

from .mac import normalize_mac


class MerakiClient:
    BASE_URL = "https://api.meraki.com/api/v1"

    def __init__(self, api_key, timeout=15):
        self.api_key = str(api_key or "").strip()
        if not self.api_key:
            raise ValueError("Meraki API key is required.")
        self.timeout = timeout

    def _get(self, path):
        url = self.BASE_URL + path
        request = urllib.request.Request(url, headers={
            "X-Cisco-Meraki-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "MACFinderPro/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            message = exc.read().decode("utf-8", errors="replace")[:400]
            raise RuntimeError(f"Meraki API HTTP {exc.code}: {message}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Meraki API connection failed: {exc.reason}") from exc

    def organizations(self):
        return self._get("/organizations")

    def find_switch_port(self, mac):
        """Search switch-port status in each accessible organization."""
        target = normalize_mac(mac)
        if not target:
            raise ValueError("Invalid target MAC address.")
        orgs = self.organizations()
        for org in orgs:
            org_id = urllib.parse.quote(str(org["id"]), safe="")
            devices = self._get(f"/organizations/{org_id}/devices?perPage=1000")
            for device in devices:
                if str(device.get("productType", "")).lower() != "switch":
                    continue
                serial = urllib.parse.quote(str(device.get("serial", "")), safe="")
                if not serial:
                    continue
                try:
                    statuses = self._get(f"/devices/{serial}/switch/ports/statuses")
                except RuntimeError:
                    continue
                for port in statuses:
                    observed_mac = normalize_mac(port.get("clientMac"))
                    if observed_mac == target:
                        return {
                            "organization": org.get("name", ""),
                            "network_id": device.get("networkId", ""),
                            "switch_name": device.get("name") or device.get("model", "Meraki Switch"),
                            "model": device.get("model", "Unknown"),
                            "serial": device.get("serial", ""),
                            "switch_mac": device.get("mac", ""),
                            "port_id": str(port.get("portId", "")),
                            "client_mac": observed_mac,
                            "status": port.get("status", "Unknown"),
                            "vlan": port.get("vlan", ""),
                            "poe_enabled": port.get("poeEnabled", ""),
                            "power_usage": port.get("powerUsageInWh", ""),
                        }
        return None

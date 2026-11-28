"""Read-oriented Cisco Meraki Dashboard API client and evidence normalizers."""
import copy
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime

from .mac import macs_match, normalize_mac


class MerakiAPIError(RuntimeError):
    def __init__(self, status, message, retry_after=None):
        super().__init__(message)
        self.status = int(status or 0)
        self.retry_after = retry_after


class MerakiClient:
    BASE_URL = "https://api.meraki.com/api/v1"
    USER_AGENT = "MACFinderPro/2.0 (Meraki read-only inspector)"
    LIVE_TOOL_PATHS = {
        "macTable": "liveTools/macTable",
        "power": "liveTools/power/usage",
        "cable": "liveTools/cableTest",
        "ping": "liveTools/ping",
        "traceRoute": "liveTools/traceRoute",
        "throughput": "liveTools/throughputTest",
    }

    def __init__(self, api_key, timeout=20, cache_ttl=20, requests_per_second=9,
                 max_retries=3, opener=None, sleep=time.sleep):
        self.api_key = str(api_key or "").strip()
        if not self.api_key:
            raise ValueError("Meraki API anahtarı gerekli.")
        self.timeout = max(2, float(timeout))
        self.cache_ttl = max(0, float(cache_ttl))
        self.requests_per_second = max(1, min(float(requests_per_second), 10))
        self.max_retries = max(0, int(max_retries))
        self._opener = opener
        self._sleep = sleep
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._last_request_at = 0.0
        self._live_tool_last = {}

    @staticmethod
    def _quote(value):
        return urllib.parse.quote(str(value), safe="")

    @classmethod
    def _device_path(cls, serial, suffix=""):
        base = f"/devices/{cls._quote(serial)}"
        return f"{base}/{suffix.strip('/')}" if suffix else base

    @classmethod
    def _network_path(cls, network_id, suffix=""):
        base = f"/networks/{cls._quote(network_id)}"
        return f"{base}/{suffix.strip('/')}" if suffix else base

    @classmethod
    def _org_path(cls, organization_id, suffix=""):
        base = f"/organizations/{cls._quote(organization_id)}"
        return f"{base}/{suffix.strip('/')}" if suffix else base

    @staticmethod
    def _query(params):
        filtered = {key: value for key, value in (params or {}).items()
                    if value is not None and value != "" and value != []}
        return urllib.parse.urlencode(filtered, doseq=True)

    @classmethod
    def _with_query(cls, path, params):
        query = cls._query(params)
        return f"{path}?{query}" if query else path

    def _validated_url(self, url):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != "api.meraki.com":
            raise MerakiAPIError(0, "Güvenlik: Meraki API dışına istek gönderilmedi.")
        if not parsed.path.startswith("/api/v1/"):
            raise MerakiAPIError(0, "Geçersiz Meraki API yolu.")
        return urllib.parse.urlunparse(parsed)

    def _throttle(self):
        with self._rate_lock:
            delay = 1.0 / self.requests_per_second
            wait = self._last_request_at + delay - time.monotonic()
            if wait > 0:
                self._sleep(wait)
            self._last_request_at = time.monotonic()

    def _throttle_live_tool(self, serial):
        with self._rate_lock:
            wait = self._live_tool_last.get(str(serial), 0.0) + 5.0 - time.monotonic()
            if wait > 0:
                self._sleep(wait)
            self._live_tool_last[str(serial)] = time.monotonic()

    @staticmethod
    def _retry_after_seconds(value):
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            try:
                return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
            except (TypeError, ValueError, OverflowError):
                return None

    @staticmethod
    def _next_link(link_header):
        match = re.search(r"<([^>]+)>\s*;\s*rel=[\"']?next[\"']?", link_header or "", re.I)
        return match.group(1) if match else None

    @staticmethod
    def _error_detail(body):
        try:
            payload = json.loads(body)
        except (TypeError, ValueError):
            return str(body or "").strip()[:300]
        errors = payload.get("errors") if isinstance(payload, dict) else None
        if errors:
            return "; ".join(str(item) for item in errors)[:300]
        return str(payload.get("message") or payload)[:300]

    @staticmethod
    def _status_message(status, detail):
        messages = {
            401: "Meraki API anahtarı geçersiz veya iptal edilmiş.",
            403: "API anahtarının bu kaynak için yeterli izni yok.",
            404: "İstenen Meraki kaynağı bulunamadı.",
            429: "Meraki API hız sınırına ulaşıldı.",
        }
        if status in messages:
            return f"HTTP {status} · " + messages[status] + (f" {detail}" if detail else "")
        if status >= 500:
            return f"HTTP {status} · Meraki servisi geçici olarak yanıt vermiyor." + (f" {detail}" if detail else "")
        return f"Meraki API HTTP {status} hatası." + (f" {detail}" if detail else "")

    @staticmethod
    def _header(headers, name):
        if not headers:
            return ""
        try:
            value = headers.get(name)
        except Exception:
            return ""
        return value if isinstance(value, str) else ""

    def _request_once(self, method, url, payload=None):
        self._throttle()
        body = None
        headers = {
            "X-Cisco-Meraki-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": self.USER_AGENT,
        }
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            opener = self._opener or urllib.request.urlopen
            with opener(request, timeout=self.timeout) as response:
                raw = response.read()
                data = json.loads(raw.decode("utf-8")) if raw else None
                return data, self._next_link(self._header(getattr(response, "headers", None), "Link"))
        except urllib.error.HTTPError as exc:
            raw_error = exc.read()
            detail = self._error_detail(raw_error.decode("utf-8", errors="replace") if raw_error else "")
            exc.close()
            if self.api_key and self.api_key in detail:
                detail = detail.replace(self.api_key, "[REDACTED]")
            raise MerakiAPIError(
                exc.code, self._status_message(exc.code, detail),
                self._retry_after_seconds(self._header(exc.headers, "Retry-After")),
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise MerakiAPIError(0, f"Meraki API bağlantısı kurulamadı: {reason}") from exc
        except json.JSONDecodeError as exc:
            raise MerakiAPIError(0, "Meraki API geçersiz JSON yanıtı döndürdü.") from exc

    def _fetch(self, method, url, payload=None, cache=True):
        url = self._validated_url(url)
        cache_key = (method, url)
        if cache and method == "GET":
            with self._cache_lock:
                cached = self._cache.get(cache_key)
                if cached and time.monotonic() - cached[2] < self.cache_ttl:
                    return copy.deepcopy(cached[0]), copy.deepcopy(cached[1])
        for attempt in range(self.max_retries + 1):
            try:
                data, next_link = self._request_once(method, url, payload)
                if cache and method == "GET":
                    with self._cache_lock:
                        if len(self._cache) >= 256:
                            oldest = min(self._cache, key=lambda key: self._cache[key][2])
                            self._cache.pop(oldest, None)
                        self._cache[cache_key] = (copy.deepcopy(data), next_link, time.monotonic())
                return data, next_link
            except MerakiAPIError as exc:
                retryable = exc.status == 429 or exc.status >= 500 or exc.status == 0
                if not retryable or attempt >= self.max_retries:
                    raise
                delay = exc.retry_after if exc.retry_after is not None else min(30.0, 0.75 * (2 ** attempt))
                self._sleep(max(0.0, delay))
        raise MerakiAPIError(0, "Meraki API isteği tamamlanamadı.")

    def get(self, path, params=None, cache=True):
        url = self.BASE_URL + path
        if params:
            url += "?" + self._query(params)
        return self._fetch("GET", url, cache=cache)[0]

    def get_all(self, path, params=None):
        url = self.BASE_URL + self._with_query(path, params)
        collected = []
        visited = set()
        for _ in range(1000):
            if url in visited:
                raise MerakiAPIError(0, "Meraki API pagination döngüsü tespit edildi.")
            visited.add(url)
            page, next_link = self._fetch("GET", url, cache=True)
            if isinstance(page, list):
                collected.extend(page)
            elif page is not None:
                return page
            if not next_link:
                return collected
            url = urllib.parse.urljoin(url, next_link)
        raise MerakiAPIError(0, "Meraki API sayfa sınırı aşıldı.")

    def post(self, path, payload=None):
        return self._fetch("POST", self.BASE_URL + path, payload=payload, cache=False)[0]

    def organizations(self):
        return self.get_all("/organizations")

    def organization_devices(self, organization_id, filters=None, network_ids=None):
        params = dict(filters or {})
        if params.get("mac"):
            params["mac"] = normalize_mac(params["mac"]) or params["mac"]
        if network_ids:
            params["networkIds"] = list(network_ids)
        params.setdefault("perPage", 1000)
        return self.get_all(self._org_path(organization_id, "devices"), params)

    def network_clients(self, network_id, mac=None, timespan=86400, statuses=None):
        params = {"timespan": timespan, "perPage": 1000}
        if mac:
            params["mac"] = normalize_mac(mac) or mac
        if statuses:
            params["statuses[]"] = list(statuses)
        return self.get_all(self._network_path(network_id, "clients"), params)

    def device_clients(self, serial, timespan=86400):
        return self.get_all(self._device_path(serial, "clients"), {"timespan": timespan})

    def switch_ports(self, serial):
        return self.get_all(self._device_path(serial, "switch/ports"))

    def switch_port_statuses(self, serial, timespan=3600):
        return self.get_all(self._device_path(serial, "switch/ports/statuses"), {"timespan": timespan})

    # Remote/compat alias used by some callers and older tests.
    switch_ports_statuses = switch_port_statuses

    def switch_port(self, serial, port_id):
        return self.get(self._device_path(serial, f"switch/ports/{self._quote(port_id)}"))

    def switch_port_packets(self, serial, timespan=3600):
        return self.get_all(self._device_path(serial, "switch/ports/statuses/packets"), {"timespan": timespan})

    # Remote/compat alias used by some callers and older smoke tests.
    switch_ports_packets = switch_port_packets

    def lldp_cdp(self, serial):
        return self.get(self._device_path(serial, "lldpCdp"))

    def network_topology(self, network_id):
        return self.get(self._network_path(network_id, "topology/linkLayer"))

    def network_events(self, network_id, filters=None):
        params = dict(filters or {})
        params.setdefault("perPage", 1000)
        return self.get_all(self._network_path(network_id, "events"), params)

    def availability_change_history(self, organization_id, filters=None):
        params = dict(filters or {})
        params.setdefault("perPage", 1000)
        return self.get_all(self._org_path(organization_id, "devices/availabilities/changeHistory"), params)

    def organization_networks(self, organization_id):
        return self.get_all(self._org_path(organization_id, "networks"))

    def device(self, serial):
        return self.get(self._device_path(serial))

    def topology_link_layer(self, network_id):
        return self.network_topology(network_id)

    def events(self, network_id, **filters):
        return self.network_events(network_id, filters)

    def find_switch_by_identifier(self, identifier):
        value = str(identifier or "").strip()
        if not value:
            raise ValueError("MAC, seri, IP veya model girin.")
        mac = normalize_mac(value)
        filters = {}
        if mac:
            filters["mac"] = mac
        else:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                if re.fullmatch(r"[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", value):
                    filters["serial"] = value.upper()
                else:
                    filters["model"] = value
        found = []
        for organization in self.organizations():
            for raw in self.organization_devices(organization.get("id"), filters=filters):
                if str(raw.get("productType") or "").lower() != "switch":
                    continue
                if mac and not macs_match(raw.get("mac"), mac):
                    continue
                if filters.get("serial") and str(raw.get("serial") or "").upper() != filters["serial"]:
                    continue
                if filters.get("model") and str(raw.get("model") or "").upper() != filters["model"].upper():
                    continue
                if not filters and str(raw.get("lanIp") or "") != value:
                    continue
                item = dict(raw)
                item.update({
                    "network_id": raw.get("networkId", ""),
                    "lan_ip": raw.get("lanIp", ""),
                    "organization": organization.get("name", ""),
                    "organization_id": organization.get("id", ""),
                    "dashboard_url": raw.get("url") or "",
                })
                found.append(item)
        return found

    def create_live_tool(self, serial, kind, payload=None):
        if kind not in self.LIVE_TOOL_PATHS:
            raise ValueError(f"Desteklenmeyen Live Tools türü: {kind}")
        self._throttle_live_tool(serial)
        return self.post(self._device_path(serial, self.LIVE_TOOL_PATHS[kind]), payload or {})

    def get_live_tool(self, serial, kind, job_id):
        if kind not in self.LIVE_TOOL_PATHS:
            raise ValueError(f"Desteklenmeyen Live Tools türü: {kind}")
        return self.get(self._device_path(serial, f"{self.LIVE_TOOL_PATHS[kind]}/{self._quote(job_id)}"), cache=False)

    def wait_live_tool(self, serial, kind, job, timeout=90, interval=3, progress=None):
        job_id = str(job.get("macTableId") or job.get("jobId") or job.get("id") or "")
        if not job_id:
            raise MerakiAPIError(0, "Live Tools yanıtı geçerli bir job ID içermiyor.")
        deadline = time.monotonic() + max(1, float(timeout))
        current = job
        while True:
            status = str(current.get("status") or "new").lower()
            if progress:
                progress(status)
            if status in {"complete", "completed"}:
                return current
            if status in {"failed", "error"}:
                detail = current.get("error") or current.get("errors") or "Bilinmeyen Live Tools hatası"
                raise MerakiAPIError(0, f"Live Tools işi başarısız oldu: {detail}")
            if time.monotonic() >= deadline:
                raise MerakiAPIError(0, f"Live Tools işi zaman aşımına uğradı (son durum: {status}).")
            self._sleep(max(0.5, float(interval)))
            current = self.get_live_tool(serial, kind, job_id)

    def query_mac_table(self, serial, mac, timeout=90, interval=3, progress=None):
        target = normalize_mac(mac)
        if not target:
            raise ValueError("Geçerli bir MAC adresi girin.")
        job = self.mac_table_create(serial, target)
        job_id = str(job.get("macTableId") or job.get("jobId") or job.get("id") or "")
        if not job_id:
            raise MerakiAPIError(0, "Live Tools yanıtı geçerli bir job ID içermiyor.")
        deadline = time.monotonic() + max(1, float(timeout))
        current = job
        while True:
            status = str(current.get("status") or "new").lower()
            if progress:
                progress(status)
            if status in {"complete", "completed"}:
                return normalize_mac_table(current, target, serial)
            if status in {"failed", "error"}:
                detail = current.get("error") or current.get("errors") or "Bilinmeyen Live Tools hatası"
                raise MerakiAPIError(0, f"Live Tools işi başarısız oldu: {detail}")
            if time.monotonic() >= deadline:
                raise MerakiAPIError(0, f"Live Tools işi zaman aşımına uğradı (son durum: {status}).")
            self._sleep(max(0.5, float(interval)))
            current = self.mac_table_get(serial, job_id)

    def mac_table_create(self, serial, mac=None):
        payload = {"mac": normalize_mac(mac)} if mac else {}
        return self.create_live_tool(serial, "macTable", payload)

    def mac_table_get(self, serial, job_id):
        return self.get_live_tool(serial, "macTable", job_id)

    def power_usage_create(self, serial):
        return self.create_live_tool(serial, "power")

    def power_usage_get(self, serial, job_id):
        return self.get_live_tool(serial, "power", job_id)

    def cable_test_create(self, serial, ports):
        return self.create_live_tool(serial, "cable", {"ports": list(ports)})

    def cable_test_get(self, serial, job_id):
        return self.get_live_tool(serial, "cable", job_id)

    def ping_create(self, serial, target):
        return self.create_live_tool(serial, "ping", {"target": target})

    def ping_get(self, serial, job_id):
        return self.get_live_tool(serial, "ping", job_id)

    def trace_route_create(self, serial, target):
        return self.create_live_tool(serial, "traceRoute", {"target": target})

    def trace_route_get(self, serial, job_id):
        return self.get_live_tool(serial, "traceRoute", job_id)

    def throughput_create(self, serial):
        return self.create_live_tool(serial, "throughput")

    def throughput_get(self, serial, job_id):
        return self.get_live_tool(serial, "throughput", job_id)

    def find_client_port_by_mac(self, mac, include_forwarding=False):
        target = normalize_mac(mac)
        if not target:
            raise ValueError("Geçerli bir MAC adresi girin.")
        sources = []
        switches = []
        for organization in self.organizations():
            try:
                networks = self.organization_networks(organization.get("id"))
            except MerakiAPIError:
                networks = []
            for network in networks:
                try:
                    clients = self.network_clients(network.get("id"), mac=target)
                except MerakiAPIError:
                    continue
                for raw in clients:
                    client = self.normalize_client(raw, network.get("id", ""))
                    if client["mac"] != target:
                        continue
                    sources.append({
                        "source": "network_clients", "mac": target, "ip": client["ip"],
                        "switchport": client["switchport"], "port": client["switchport"],
                        "vlan": client["vlan"], "vlan_id": client["vlan"],
                        "switch_serial": client["recent_device_serial"],
                        "switch_name": client["recent_device_name"], "status": client["status"],
                        "last_seen": client["last_seen"], "first_seen": client["first_seen"],
                        "observed_at": client["observed_at"], "raw": client["raw"],
                    })
            try:
                devices = self.organization_devices(organization.get("id"))
            except MerakiAPIError:
                devices = []
            for device in devices:
                if str(device.get("productType") or "").lower() == "switch" and device.get("serial"):
                    switches.append(device)
        if not sources or include_forwarding:
            for device in switches:
                serial = device.get("serial")
                try:
                    clients = self.device_clients(serial)
                except MerakiAPIError:
                    clients = []
                for raw in clients:
                    client = self.normalize_client(raw, device.get("networkId", ""))
                    if client["mac"] != target:
                        continue
                    sources.append({
                        "source": "device_clients", "mac": target, "ip": client["ip"],
                        "switchport": client["switchport"], "port": client["switchport"],
                        "vlan": client["vlan"], "vlan_id": client["vlan"],
                        "switch_serial": serial, "switch_name": device.get("name") or device.get("model", ""),
                        "status": client["status"], "last_seen": client["last_seen"],
                        "first_seen": client["first_seen"], "observed_at": client["observed_at"], "raw": client["raw"],
                    })
                if include_forwarding:
                    try:
                        table = self.query_mac_table(serial, target)
                    except (MerakiAPIError, ValueError):
                        continue
                    for entry in table["entries"]:
                        sources.append({
                            "source": "mac_table", "mac": target, "ip": "",
                            "switchport": entry["port"], "port": entry["port"],
                            "vlan": entry["vlan_id"], "vlan_id": entry["vlan_id"],
                            "switch_serial": serial, "switch_name": device.get("name") or device.get("model", ""),
                            "observed_at": entry["observed_at"], "raw": entry["raw"],
                        })
        return {"target_mac": target, "sources": sources,
                "best_match": sources[0] if sources else None}

    @staticmethod
    def normalize_client(client, network_id="", observed_at=None):
        raw = dict(client or {})
        usage = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}
        return {
            "mac": normalize_mac(raw.get("mac")) or str(raw.get("mac") or ""),
            "ip": raw.get("ip") or "", "manufacturer": raw.get("manufacturer") or "",
            "description": raw.get("description") or "", "status": raw.get("status") or "Unknown",
            "first_seen": raw.get("firstSeen"), "last_seen": raw.get("lastSeen"),
            "vlan": raw.get("vlan") or raw.get("namedVlan") or "",
            "named_vlan": raw.get("namedVlan") or "", "switchport": raw.get("switchport") or "",
            "recent_device_connection": raw.get("recentDeviceConnection") or "",
            "recent_device_name": raw.get("recentDeviceName") or "",
            "recent_device_serial": raw.get("recentDeviceSerial") or "",
            "recent_device_mac": raw.get("recentDeviceMac") or "",
            "recv": usage.get("recv", raw.get("recv")), "sent": usage.get("sent", raw.get("sent")),
            "usage": usage or raw.get("usage") or {}, "os": raw.get("os") or "",
            "device_type_prediction": raw.get("deviceTypePrediction") or "",
            "dhcp_hostname": raw.get("dhcpHostname") or raw.get("description") or "",
            "mdns_name": raw.get("mdnsName") or "", "network_id": network_id or raw.get("networkId") or "",
            "observed_at": observed_at or time.time(), "raw": raw,
        }

    @staticmethod
    def normalize_ports(configs, statuses):
        config_by_id = {str(item.get("portId")): item for item in (configs or []) if item.get("portId") is not None}
        rows = []
        for status in statuses or []:
            port_id = str(status.get("portId", ""))
            config = config_by_id.get(port_id, {})
            merged = dict(config)
            merged.update(status)
            merged.update({"portId": port_id, "config": config, "status_data": status, "status_verified": True})
            rows.append(merged)
        known = {row["portId"] for row in rows}
        for port_id, config in config_by_id.items():
            if port_id not in known:
                rows.append({**dict(config), "portId": port_id, "status": "Unknown",
                             "status_verified": False, "config": config, "status_data": {}})
        return rows

    def find_switch_port(self, mac):
        """Compatibility lookup using network clients, never port status clientMac."""
        target = normalize_mac(mac)
        if not target:
            raise ValueError("Geçersiz hedef MAC adresi.")
        networks = {}
        for organization in self.organizations():
            for device in self.organization_devices(organization.get("id")):
                if str(device.get("productType", "")).lower() == "switch" and device.get("networkId"):
                    networks.setdefault(device["networkId"], []).append((organization, device))
        for network_id, switches in networks.items():
            for raw in self.network_clients(network_id, mac=target):
                client = self.normalize_client(raw, network_id)
                if client["mac"] != target or client["recent_device_connection"] != "Wired":
                    continue
                serial = client["recent_device_serial"]
                match = next((item for item in switches if item[1].get("serial") == serial), None)
                organization, device = match if match else ({}, {})
                return {
                    "organization": organization.get("name", ""), "network_id": network_id,
                    "switch_name": client["recent_device_name"] or device.get("name") or device.get("model", ""),
                    "model": device.get("model", ""), "serial": serial, "switch_mac": device.get("mac", ""),
                    "port_id": client["switchport"], "client_mac": target, "client_ip": client["ip"],
                    "status": client["status"], "vlan": client["vlan"],
                    "source": "Meraki network client", "observed_at": client["observed_at"], "raw": client["raw"],
                }
        return None


def normalize_mac_table(result, target_mac, serial=""):
    target = normalize_mac(target_mac)
    entries = []
    for raw in result.get("entries") or []:
        mac = normalize_mac(raw.get("mac"))
        if target and mac != target:
            continue
        entries.append({
            "mac": mac or str(raw.get("mac") or ""),
            "port": str(raw.get("port") or raw.get("portId") or ""),
            "vlan_id": raw.get("vlanId", raw.get("vlan")), "serial": serial,
            "job_status": result.get("status", ""), "observed_at": time.time(), "raw": dict(raw),
        })
    return {"serial": serial, "status": result.get("status", ""), "entries": entries,
            "error": result.get("error") or "", "observed_at": time.time(), "raw": dict(result)}


def normalize_ports(configs, statuses):
    config_by_id = {str(item.get("portId")): item for item in (configs or []) if item.get("portId") is not None}
    rows = []
    for status in statuses or []:
        port_id = str(status.get("portId", ""))
        config = config_by_id.get(port_id, {})
        merged = dict(config)
        merged.update(status)
        merged.update({"portId": port_id, "config": config, "status_data": status, "status_verified": True})
        rows.append(merged)
    known = {row["portId"] for row in rows}
    for port_id, config in config_by_id.items():
        if port_id not in known:
            rows.append({**dict(config), "portId": port_id, "status": "Unknown",
                         "status_verified": False, "config": config, "status_data": {}})
    return rows


def normalize_poe_data(statuses, live_result=None, manufacturer_budget=None):
    per_port = []
    energy_values = []
    for status in statuses or []:
        poe = status.get("poe") if isinstance(status.get("poe"), dict) else {}
        energy = status.get("powerUsageInWh")
        if isinstance(energy, (int, float)):
            energy_values.append(float(energy))
        per_port.append({
            "port_id": str(status.get("portId", "")), "poe_enabled": status.get("enabled"),
            "is_allocated": poe.get("isAllocated"),
            "client_connected": status.get("clientCount", 0) > 0 if status.get("clientCount") is not None else None,
            "power_usage_wh": energy, "instant_watts": None, "status": status.get("status", "Unknown"),
        })
    results = (live_result or {}).get("results") or {}
    budget = results.get("budget")
    budget_source = "Meraki Live Tools" if isinstance(budget, (int, float)) else "Üretici teknik özelliği"
    if not isinstance(budget, (int, float)) and manufacturer_budget is not None:
        budget = manufacturer_budget
    instant, peak = results.get("instant"), results.get("peak")
    remaining = budget - instant if isinstance(budget, (int, float)) and isinstance(instant, (int, float)) else None
    return {
        "per_port": per_port, "manufacturer_budget_w": manufacturer_budget, "budget_w": budget,
        "budget_source": budget_source if budget is not None else "Bilinmiyor",
        "instant_w": instant if isinstance(instant, (int, float)) else None,
        "peak_w": peak if isinstance(peak, (int, float)) else None, "remaining_w": remaining,
        "total_energy_wh": sum(energy_values) if energy_values else None,
        "live_tool_status": (live_result or {}).get("status", ""), "observed_at": time.time(),
        "note": "powerUsageInWh enerji (Wh) değeridir; anlık Watt yalnızca Live Tools sonucundan alınır.",
    }


def normalize_traffic_data(statuses, packets, retrieved_at=None):
    retrieved_at = retrieved_at or time.time()
    status_by_id = {str(item.get("portId")): item for item in statuses or []}
    rows = []
    for item in packets or []:
        port_id = str(item.get("portId", ""))
        counters = item.get("packets") or []
        total = next((entry for entry in counters if str(entry.get("desc", "")).lower() == "total"), None)
        if total is None and counters:
            total = counters[0]
        status = status_by_id.get(port_id, {})
        rows.append({
            "port_id": port_id, "packets_total": (total or {}).get("total"),
            "packets_sent": (total or {}).get("sent"), "packets_recv": (total or {}).get("recv"),
            "rate_total": (total or {}).get("ratePerSec", {}).get("total"),
            "rate_sent": (total or {}).get("ratePerSec", {}).get("sent"),
            "rate_recv": (total or {}).get("ratePerSec", {}).get("recv"),
            "usage_kb": status.get("usageInKb") or {}, "traffic_kbps": status.get("trafficInKbps") or {},
            "retrieved_at": retrieved_at, "data_source": "Meraki switch ports statuses + packets",
            "freshness": "Bilinmiyor (API periyodik toplar; son 5 dakika eksik olabilir)",
        })
    return rows


def normalize_topology(topology, lldp_cdp=None):
    topology = topology or {}
    nodes, node_by_id = [], {}
    for raw in topology.get("nodes") or []:
        device = raw.get("device") if isinstance(raw.get("device"), dict) else {}
        discovered = raw.get("discovered") if isinstance(raw.get("discovered"), dict) else {}
        stack = raw.get("stack") if isinstance(raw.get("stack"), dict) else {}
        lldp = discovered.get("lldp") if isinstance(discovered.get("lldp"), dict) else {}
        cdp = discovered.get("cdp") if isinstance(discovered.get("cdp"), dict) else {}
        node_id = str(raw.get("derivedId") or raw.get("mac") or device.get("serial") or stack.get("id") or "")
        if not node_id:
            continue
        label = device.get("name") or stack.get("name") or lldp.get("systemName") or cdp.get("deviceId") or node_id
        node = {
            "id": node_id, "label": label, "type": raw.get("type") or "unknown",
            "mac": raw.get("mac") or "", "serial": device.get("serial") or "",
            "model": device.get("model") or stack.get("name") or cdp.get("platform") or "",
            "management_ip": lldp.get("managementAddress") or cdp.get("managementAddress") or "",
            "root": bool(raw.get("root")), "raw": raw,
        }
        nodes.append(node)
        node_by_id[node_id] = node
    links = []
    for raw in topology.get("links") or []:
        ends = raw.get("ends") or []
        if len(ends) != 2:
            continue
        normalized_ends = []
        for end in ends:
            reference = end.get("node") if isinstance(end.get("node"), dict) else {}
            device = end.get("device") if isinstance(end.get("device"), dict) else {}
            discovered = end.get("discovered") if isinstance(end.get("discovered"), dict) else {}
            lldp = discovered.get("lldp") if isinstance(discovered.get("lldp"), dict) else {}
            cdp = discovered.get("cdp") if isinstance(discovered.get("cdp"), dict) else {}
            normalized_ends.append({
                "node_id": str(reference.get("derivedId") or ""), "serial": device.get("serial") or "",
                "name": device.get("name") or "", "port": lldp.get("portId") or cdp.get("portId") or "",
                "native_vlan": cdp.get("nativeVlan"),
                "chassis_id": lldp.get("chassisId") or cdp.get("deviceId") or "",
            })
        if not all(item["node_id"] in node_by_id for item in normalized_ends):
            continue
        first, second = normalized_ends
        links.append({
            "a_node": first["node_id"], "a_name": node_by_id[first["node_id"]]["label"],
            "a_port": first["port"], "a_vlan": first["native_vlan"],
            "b_node": second["node_id"], "b_name": node_by_id[second["node_id"]]["label"],
            "b_port": second["port"], "b_vlan": second["native_vlan"],
            "last_reported": raw.get("lastReportedAt") or "", "raw": raw,
        })
    lldp_rows = []
    for port_id, raw in ((lldp_cdp or {}).get("ports") or {}).items():
        lldp = raw.get("lldp") if isinstance(raw.get("lldp"), dict) else {}
        cdp = raw.get("cdp") if isinstance(raw.get("cdp"), dict) else {}
        if lldp or cdp:
            lldp_rows.append({
                "port_id": str(port_id), "system_name": lldp.get("systemName") or "",
                "cdp_device_id": cdp.get("deviceId") or "", "platform": cdp.get("platform") or "",
                "management_ip": lldp.get("managementAddress") or cdp.get("address") or "",
                "remote_port": lldp.get("portId") or cdp.get("portId") or "",
                "chassis_id": lldp.get("chassisId") or "", "native_vlan": cdp.get("nativeVlan"), "raw": raw,
            })
    return {"nodes": nodes, "links": links, "lldp": lldp_rows,
            "errors": topology.get("errors") or [], "raw": topology, "observed_at": time.time()}

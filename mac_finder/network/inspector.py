"""Evidence-first Meraki discovery and MAC-to-switch-port correlation."""
import ipaddress
import re
import time

from .arp import get_arp_table
from .local_status import probe_local_status_page
from .mac import normalize_mac, macs_match
from .meraki import MerakiAPIError, MerakiClient
from .scanner import ARPScanner


class MerakiInspector:
    def __init__(self, client=None, store=None, arp_provider=get_arp_table,
                 scanner_factory=ARPScanner, status_provider=probe_local_status_page,
                 snmp_provider=None, clock=time.time):
        self.client = client
        self.store = store
        self.arp_provider = arp_provider
        self.scanner_factory = scanner_factory
        self.status_provider = status_provider
        self.snmp_provider = snmp_provider
        self.clock = clock

    @staticmethod
    def classify_query(query):
        value = str(query or "").strip()
        mac = normalize_mac(value)
        if mac:
            return "mac", mac
        try:
            return "ip", str(ipaddress.ip_address(value))
        except ValueError:
            pass
        if re.fullmatch(r"[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", value):
            return "serial", value.upper()
        return "model", value

    @staticmethod
    def _evidence(source, status, message, data=None, error=None):
        return {"source": source, "status": status, "message": message, "data": data,
                "error": error, "observed_at": time.time()}

    @staticmethod
    def _device_matches(device, kind, query):
        if kind == "mac":
            return macs_match(device.get("mac"), query)
        if kind == "serial":
            return str(device.get("serial") or "").upper() == query.upper()
        if kind == "model":
            return str(device.get("model") or "").upper() == query.upper()
        if kind == "ip":
            return str(device.get("lanIp") or device.get("lan_ip") or "") == query
        return False

    def _local_matches(self, entries, kind, query):
        matches = []
        for entry in entries:
            if kind == "mac" and macs_match(entry.get("mac"), query):
                matches.append(entry)
            elif kind == "ip" and str(entry.get("ip") or "") == query:
                matches.append(entry)
        return matches

    def discover(self, query, cidr=None, adapter_ip=None, organization_id=None,
                 include_local_scan=True, progress=None):
        kind, normalized = self.classify_query(query)
        if not normalized:
            raise ValueError("Arama için MAC, seri, IP veya model girin.")
        evidence, local_devices, api_devices = [], [], []
        selected_device = None

        def report(step, status, message):
            if progress:
                progress(step, status, message)

        report("SQLite envanteri", "running", "Kayıtlı cihazlar kontrol ediliyor")
        if self.store:
            local_devices, cached_devices = self.store.find_inventory(normalized)
            if local_devices or cached_devices:
                evidence.append(self._evidence(
                    "SQLite envanteri", "found", "Envanterde eşleşen kayıtlar bulundu.",
                    {"devices": local_devices, "meraki_devices": cached_devices},
                ))
                exact_cached = [item for item in cached_devices if self._device_matches(item, kind, normalized)]
                if exact_cached:
                    selected_device = exact_cached[0]
            else:
                evidence.append(self._evidence("SQLite envanteri", "not_found", "Eşleşen kayıt yok."))
        else:
            evidence.append(self._evidence("SQLite envanteri", "skipped", "Envanter bağlantısı yok."))

        report("Yerel ARP", "running", "İşletim sistemi ARP tablosu okunuyor")
        try:
            arp_matches = self._local_matches(self.arp_provider(), kind, normalized)
            if arp_matches:
                evidence.append(self._evidence("Yerel ARP", "found", "ARP tablosunda eşleşme bulundu.", arp_matches))
            elif kind in {"mac", "ip"}:
                evidence.append(self._evidence("Yerel ARP", "not_found", "ARP tablosunda eşleşme yok."))
            else:
                evidence.append(self._evidence("Yerel ARP", "skipped", "Seri/model eşleşmesi ARP tablosundan doğrulanamaz."))
        except Exception as exc:
            evidence.append(self._evidence("Yerel ARP", "failed", "ARP tablosu okunamadı.", error=str(exc)))

        management_ip = str((arp_matches[0].get("ip") or "")) if arp_matches else ""
        for item in local_devices:
            if not management_ip and item.get("ip"):
                management_ip = item["ip"]

        report("Yerel subnet", "running", "Seçili yerel subnet kontrol ediliyor")
        if kind not in {"mac", "ip"}:
            evidence.append(self._evidence("Yerel subnet", "skipped", "Yerel tarama MAC/IP eşleşmesi için kullanılabilir."))
        elif not include_local_scan:
            evidence.append(self._evidence("Yerel subnet", "skipped", "Yerel tarama kapatıldı."))
        elif not cidr:
            evidence.append(self._evidence("Yerel subnet", "skipped", "Seçili aktif subnet yok."))
        else:
            try:
                scanner = self.scanner_factory(target_mac=normalized if kind == "mac" else None)
                callback = lambda done, total: report("Yerel subnet", "running", f"{done}/{total} host kontrol edildi")
                if kind == "mac":
                    found = scanner.find_mac(normalized, cidr, adapter_ip, callback)
                    found_devices = [found] if found else []
                else:
                    found_devices = [item for item in scanner.scan_network(cidr, adapter_ip, callback)
                                     if str(item.get("ip") or "") == normalized]
                if found_devices:
                    evidence.append(self._evidence("Yerel subnet", "found", "Yerel subnet taramasında eşleşme bulundu.", found_devices))
                    management_ip = management_ip or found_devices[0].get("ip", "")
                    if self.store:
                        for item in found_devices:
                            self.store.upsert_device(item)
                else:
                    evidence.append(self._evidence("Yerel subnet", "not_found", "Yerel subnet'te eşleşme bulunamadı."))
            except Exception as exc:
                evidence.append(self._evidence("Yerel subnet", "failed", "Yerel subnet taraması başarısız.", error=str(exc)))

        report("Meraki API", "running", "Organization inventory sorgulanıyor")
        if not self.client:
            evidence.append(self._evidence("Meraki API", "skipped", "Meraki API anahtarı yapılandırılmadı."))
        else:
            try:
                organizations = self.client.organizations()
                if organization_id:
                    organizations = [item for item in organizations if str(item.get("id")) == str(organization_id)]
                if not organizations:
                    evidence.append(self._evidence("Meraki API", "not_found", "Erişilebilir organizasyon bulunamadı."))
                for organization in organizations:
                    filters = {}
                    if kind == "mac":
                        filters["mac"] = normalized
                    elif kind == "serial":
                        filters["serial"] = normalized
                    elif kind == "model":
                        filters["model"] = normalized
                    try:
                        devices = self.client.organization_devices(organization.get("id"), filters=filters)
                        matches = []
                        for raw in devices:
                            if str(raw.get("productType") or "").lower() != "switch":
                                continue
                            if not self._device_matches(raw, kind, normalized):
                                continue
                            item = dict(raw)
                            item.update({"organization_id": organization.get("id", ""),
                                         "organization_name": organization.get("name", ""),
                                         "dashboard_url": raw.get("url") or "", "observed_at": time.time()})
                            matches.append(item)
                            if self.store:
                                self.store.save_meraki_device(item)
                        api_devices.extend(matches)
                        if matches:
                            evidence.append(self._evidence(
                                "Meraki API", "found",
                                f"{organization.get('name') or organization.get('id')}: {len(matches)} switch bulundu.", matches,
                            ))
                        else:
                            evidence.append(self._evidence(
                                "Meraki API", "not_found",
                                f"{organization.get('name') or organization.get('id')}: eşleşen switch yok.",
                            ))
                    except MerakiAPIError as exc:
                        evidence.append(self._evidence(
                            "Meraki API", "failed",
                            f"{organization.get('name') or organization.get('id')}: inventory sorgusu başarısız.", error=str(exc),
                        ))
                if api_devices and selected_device is None:
                    selected_device = api_devices[0]
            except MerakiAPIError as exc:
                evidence.append(self._evidence("Meraki API", "failed", "Organizasyonlar sorgulanamadı.", error=str(exc)))

        if selected_device:
            management_ip = management_ip or str(selected_device.get("lanIp") or selected_device.get("lan_ip") or "")

        report("Yerel SNMP", "running", "SNMP ayarları kontrol ediliyor")
        if not self.snmp_provider:
            evidence.append(self._evidence("Yerel SNMP", "skipped", "SNMP yapılandırılmadı."))
        else:
            try:
                result = self.snmp_provider(normalized, management_ip)
                evidence.append(self._evidence(
                    "Yerel SNMP", result.get("status", "found"), result.get("message", "SNMP sorgusu tamamlandı."),
                    result.get("data"), result.get("error"),
                ))
            except Exception as exc:
                evidence.append(self._evidence("Yerel SNMP", "failed", "SNMP sorgusu başarısız.", error=str(exc)))

        report("Local Status Page", "running", "Yerel status sayfası kontrol ediliyor")
        try:
            result = self.status_provider()
            evidence.append(self._evidence(
                "Local Status Page", "found" if result.get("reachable") else "not_found",
                "Yerel status sayfası erişilebilir." if result.get("reachable") else "Yerel status sayfası erişilemedi.",
                result, result.get("error"),
            ))
        except Exception as exc:
            evidence.append(self._evidence("Local Status Page", "failed", "Yerel status kontrolü başarısız.", error=str(exc)))

        report("Tamamlandı", "complete", "Keşif tamamlandı")
        return {"query": normalized, "kind": kind, "devices": api_devices, "local_devices": local_devices,
                "selected_device": selected_device, "management_ip": management_ip,
                "evidence": evidence, "completed_at": self.clock()}

    def locate_mac(self, mac, device=None, network_id=None, include_forwarding=True, progress=None):
        target = normalize_mac(mac)
        if not target:
            raise ValueError("Geçerli bir MAC adresi girin.")
        device = device or {}
        serial = str(device.get("serial") or "")
        network_id = str(network_id or device.get("networkId") or "")
        evidence, mappings = [], []

        try:
            arp_matches = self._local_matches(self.arp_provider(), "mac", target)
            evidence.append(self._evidence(
                "Yerel ARP", "found" if arp_matches else "not_found",
                "ARP eşleşmesi bulundu." if arp_matches else "ARP eşleşmesi yok.", arp_matches,
            ))
            for item in arp_matches:
                mappings.append({"source": "Yerel ARP", "mac": target, "ip": item.get("ip", ""),
                                 "switch_serial": "", "switch_name": "", "port": "", "vlan": "",
                                 "observed_at": time.time(), "raw": item})
        except Exception as exc:
            evidence.append(self._evidence("Yerel ARP", "failed", "ARP sorgusu başarısız.", error=str(exc)))

        if not self.client:
            evidence.append(self._evidence("Meraki API", "skipped", "Meraki API anahtarı yapılandırılmadı."))
        else:
            if network_id:
                try:
                    if progress:
                        progress("Meraki network client", "running")
                    clients = self.client.network_clients(network_id, mac=target)
                    matches = [MerakiClient.normalize_client(item, network_id) for item in clients]
                    matches = [item for item in matches if item["mac"] == target]
                    evidence.append(self._evidence(
                        "Meraki network client", "found" if matches else "not_found",
                        "Network clients API eşleşmesi bulundu." if matches else "Network clients API eşleşmesi bulunamadı.", matches,
                    ))
                    for client in matches:
                        mappings.append({
                            "source": "Meraki network client", "mac": target, "ip": client["ip"],
                            "switch_serial": client["recent_device_serial"], "switch_name": client["recent_device_name"],
                            "port": client["switchport"], "vlan": client["vlan"], "status": client["status"],
                            "observed_at": client["observed_at"], "raw": client["raw"],
                        })
                except MerakiAPIError as exc:
                    evidence.append(self._evidence("Meraki network client", "failed", "Network clients sorgusu başarısız.", error=str(exc)))
            else:
                evidence.append(self._evidence("Meraki network client", "skipped", "Doğrulanmış Network ID yok."))

            if serial:
                try:
                    clients = self.client.device_clients(serial)
                    matches = [MerakiClient.normalize_client(item, network_id) for item in clients]
                    matches = [item for item in matches if item["mac"] == target]
                    evidence.append(self._evidence(
                        "Meraki device clients", "found" if matches else "not_found",
                        "Device clients API eşleşmesi bulundu." if matches else "Device clients API eşleşmesi bulunamadı.", matches,
                    ))
                    for client in matches:
                        mappings.append({
                            "source": "Meraki device clients", "mac": target, "ip": client["ip"],
                            "switch_serial": serial, "switch_name": device.get("name") or device.get("model") or "",
                            "port": client["switchport"], "vlan": client["vlan"], "status": client["status"],
                            "observed_at": client["observed_at"], "raw": client["raw"],
                        })
                except MerakiAPIError as exc:
                    evidence.append(self._evidence("Meraki device clients", "failed", "Device clients sorgusu başarısız.", error=str(exc)))

                if include_forwarding:
                    try:
                        if progress:
                            progress("Switch MAC forwarding table", "running")
                        table = self.client.query_mac_table(
                            serial, target,
                            progress=lambda status: progress("Switch MAC forwarding table", status) if progress else None,
                        )
                        evidence.append(self._evidence(
                            "Switch MAC forwarding table", "found" if table["entries"] else "not_found",
                            "MAC forwarding table eşleşmesi bulundu." if table["entries"] else "MAC forwarding table'de eşleşme yok.", table,
                        ))
                        for entry in table["entries"]:
                            mappings.append({
                                "source": "Switch MAC forwarding table", "mac": target, "ip": "",
                                "switch_serial": serial, "switch_name": device.get("name") or device.get("model") or "",
                                "port": entry["port"], "vlan": entry["vlan_id"],
                                "observed_at": entry["observed_at"], "raw": entry["raw"],
                            })
                    except (MerakiAPIError, ValueError) as exc:
                        evidence.append(self._evidence(
                            "Switch MAC forwarding table", "failed", "MAC forwarding table sorgusu başarısız.", error=str(exc),
                        ))
            else:
                evidence.append(self._evidence("Switch MAC forwarding table", "skipped", "Doğrulanmış switch seri numarası yok."))

        if self.snmp_provider:
            try:
                result = self.snmp_provider(target, "")
                evidence.append(self._evidence(
                    "Yerel SNMP", result.get("status", "found"), result.get("message", "SNMP sorgusu tamamlandı."),
                    result.get("data"), result.get("error"),
                ))
            except Exception as exc:
                evidence.append(self._evidence("Yerel SNMP", "failed", "SNMP sorgusu başarısız.", error=str(exc)))
        else:
            evidence.append(self._evidence("Yerel SNMP", "skipped", "SNMP yapılandırılmadı."))

        return {"mac": target, "device": device, "mappings": mappings, "evidence": evidence,
                "found": bool(mappings), "completed_at": self.clock()}

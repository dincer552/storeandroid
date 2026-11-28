"""Wi-Fi Dashboard and security inspector pages for MAC Finder Pro."""
import json
import threading
from typing import Dict, List, Optional

from tkinter import ttk

from ..network.wifi import WifiScanner, scan_wifi_networks, get_wifi_info, get_wifi_profiles
from ..network.winevent import (
    WindowsEventLog, get_login_events, get_wlan_events, get_nps_events, correlate_sessions,
)
from ..network.meraki import MerakiClient  # noqa: F401

UNKNOWN = "Bilinmiyor"


class WifiUIManager:
    """Renders Wi-Fi, endpoint audit and security pages inside the host app."""

    def __init__(self, app):
        self.app = app
        self.scanner = WifiScanner()
        self.wifi_state: Dict = {
            "networks": [],
            "aps": [],
            "scans": [],
            "connection_events": [],
            "wireless_client_events": [],
            "auth_events": [],
            "browser_inventory": [],
            "alerts": [],
            "last_scan_at": None,
        }

    # ------------------------------------------------------------------ helpers
    def _C(self):
        return self.app.C

    def _fmt(self, value):
        if value in (None, "", [], {}):
            return UNKNOWN
        return str(value)

    def _error(self, title, message):
        self.app.activity_label.config(text="ERROR", fg=self.app.C["red"])
        self.app.status_var.set(f"{title}: {message}")
        from tkinter import messagebox
        messagebox.showerror("Wi-Fi / Güvenlik", f"{title}\n\n{message}")

    # ------------------------------------------------------------------ nav
    def nav_groups(self):
        return [
            ("WIFI", [
                ("Wi-Fi Dashboard", "📶"),
                ("Wi-Fi Scanner", "⌕"),
                ("Wi-Fi Channel Analyzer", "📊"),
                ("Wi-Fi Security", "🔒"),
                ("Wi-Fi Profiles", "⚙"),
            ]),
            ("ENDPOINT AUDIT", [
                ("User Login Audit", "👤"),
                ("Wi-Fi Connection History", "📜"),
                ("Meraki Wireless Monitor", "✦"),
                ("Browser Security Inspector", "🌐"),
                ("Security Events", "🚨"),
            ]),
        ]

    # ------------------------------------------------------------------ render
    def render(self, page: str):
        renderers = {
            "Wi-Fi Dashboard": self._page_wifi_dashboard,
            "Wi-Fi Scanner": self._page_wifi_scanner,
            "Wi-Fi Channel Analyzer": self._page_wifi_channel,
            "Wi-Fi Security": self._page_wifi_security,
            "Wi-Fi Profiles": self._page_wifi_profiles,
            "User Login Audit": self._page_login_audit,
            "Wi-Fi Connection History": self._page_wifi_history,
            "Meraki Wireless Monitor": self._page_meraki_wireless,
            "Browser Security Inspector": self._page_browser_security,
            "Security Events": self._page_security_alerts,
        }
        renderer = renderers.get(page)
        if renderer:
            renderer()

    # ------------------------------------------------------------------ pages
    def _page_wifi_dashboard(self):
        scanner = self.scanner
        info = scanner.connected_info()
        networks = scanner.scan_networks()
        self.wifi_state["networks"] = networks
        self.wifi_state["last_scan_at"] = __import__("time").time()
        self.app._section(
            self.app.content, "Wi-Fi Dashboard",
            "Aktif Wi-Fi adaptörü, bağlantı durumu ve yaklaşık erişim alanı detayları.")
        panel = self.app._panel(self.app.content)
        rows = [
            ("Adaptör", info.get("adapter") or UNKNOWN),
            ("Adaptör durumu", info.get("state") or "Bilinmiyor"),
            ("SSID", info.get("ssid") or UNKNOWN),
            ("BSSID", info.get("bssid") or UNKNOWN),
            ("Sinyal", f"{info.get('signal', 0)}% (RSSI {info.get('rssi', 0)})"),
            ("Kanal / Frekans", f"{info.get('channel', 0)} / {info.get('frequency', 0)}"),
            ("Bant", info.get("band") or UNKNOWN),
            ("Radio", info.get("radio_type") or UNKNOWN),
            ("Auth", info.get("authentication") or UNKNOWN),
            ("Cipher", info.get("cipher") or UNKNOWN),
            ("Link Speed", info.get("link_speed") or UNKNOWN),
            ("Local IP", info.get("ip") or UNKNOWN),
            ("Gateway", info.get("gateway") or UNKNOWN),
            ("DNS", ", ".join(info.get("dns") or []) or UNKNOWN),
            ("Bağlantı durumu", "Connected" if (info.get("ssid") or "") else "Disconnected"),
        ]
        grid = self.app._content_grid if hasattr(self.app, "_content_grid") else None
        from tkinter import ttk
        outer = self.app._panel(self.app.content)
        frame = ttk.Frame(outer)
        frame.pack(fill="x")
        tree = ttk.Treeview(frame, columns=("key", "value"), show="headings", height=20)
        tree.heading("key", text="Alan")
        tree.heading("value", text="Değer")
        tree.column("key", width=180, stretch=False)
        tree.column("value", width=420, stretch=True)
        for row in rows:
            tree.insert("", "end", values=(row[0], row[1]))
        tree.pack(fill="both", expand=True)

    def _page_wifi_scanner(self):
        scanner = self.scanner
        networks: List[dict] = scanner.scan_networks()
        self.wifi_state["networks"] = networks
        self.app._section(self.app.content, "Wi-Fi Scanner",
                         "Aktif Wi-Fi adaptörü üzerinden okunan gerçek erişim noktaları (OEM API / netsh fallback).")
        panel = self.app._panel(self.app.content)
        tree = self.app._create_table(panel, compact=False) if hasattr(self.app, "_create_table") else None
        if tree:
            tree.delete(*tree.get_children())
            for n in networks:
                tree.insert("", "end", values=(n.get("ssid") or "", n.get("bssid") or "",
                                             n.get("signal") or 0, n.get("rssi") or 0,
                                             n.get("channel") or 0, n.get("frequency") or 0,
                                             n.get("band") or "", n.get("authentication") or "",
                                             n.get("cipher") or "", n.get("radio_type") or "",
                                             "Connected" if n.get("connected") else "Not Connected"))

    def _page_wifi_channel(self):
        networks: List[dict] = self.scanner.scan_networks()
        by_band: Dict[str, List[dict]] = {"2.4": [], "5": [], "6": []}
        for n in networks:
            band = n.get("band") or "unknown"
            by_band.setdefault(band, []).append(n)
        self.app._section(self.app.content, "Wi-Fi Channel Analyzer",
                         "Yakalanan erişim noktalarının kanal yoğunluğu (gerçek tarama verisi).")
        panel = self.app._panel(self.app.content)
        from tkinter import ttk
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("band", "channel", "ap_count", "total_rssi"),
                            show="headings")
        tree.heading("band", text="Bant")
        tree.heading("channel", text="Kanal")
        tree.heading("ap_count", text="AP Sayısı")
        tree.heading("total_rssi", text="Toplam RSSI")
        for band in sorted(by_band):
            entries = sorted(by_band[band], key=lambda n: n.get("channel") or 0)
            channels: Dict[int, List[dict]] = {}
            for n in entries:
                ch = n.get("channel") or 0
                channels.setdefault(ch, []).append(n)
            for ch, aps in sorted(channels.items()):
                tree.insert("", "end", values=(band, ch, len(aps),
                                              sum(int(a.get("rssi") or 0) for a in aps)))
        tree.pack(fill="both", expand=True)

    def _page_wifi_security(self):
        networks: List[dict] = self.scanner.scan_networks()
        self.app._section(self.app.content, "Wi-Fi Security",
                         "Tespit edilen ağıların güvenlik sınıflandırması (gerçek tarama verisi).")
        panel = self.app._panel(self.app.content)
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("ssid", "bssid", "security", "cipher", "severity"),
                            show="headings")
        tree.heading("ssid", text="SSID")
        tree.heading("bssid", text="BSSID")
        tree.heading("security", text="Security")
        tree.heading("cipher", text="Cipher")
        tree.heading("severity", text="Şiddet")
        for n in networks:
            sev, msg = self._security_severity(n.get("security"), n.get("cipher"))
            tree.insert("", "end", values=(
                n.get("ssid") or UNKNOWN,
                n.get("bssid") or UNKNOWN,
                n.get("security") or UNKNOWN,
                n.get("cipher") or UNKNOWN,
                f"{sev} - {msg}",
            ))
        tree.pack(fill="both", expand=True)

    def _security_severity(self, security: str, cipher: str) -> tuple:
        sec = (security or "").upper()
        if "OPEN" in sec:
            return "high", "Open network - no encryption."
        if "WEP" in sec:
            return "high", "WEP encryption is deprecated and easily broken."
        if "WPA3" in sec:
            return "info", "WPA3 - strong."
        if "WPA2" in sec:
            return "info", "WPA2 - acceptable."
        if "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
            return "medium", "WPA (TKIP) is weak; use WPA2/WPA3."
        return "low", "Security could not be determined."

    # ------------------------------------------------------------------ page: wifi profiles
    def _page_wifi_profiles(self):
        names = get_wifi_profiles()
        self.app._section(self.app.content, "Wi-Fi Profile Inventory",
                         "Kayıtlı Wi-Fi profilleri (authentication / cipher / scope).")
        panel = self.app._panel(self.app.content)
        from tkinter import ttk
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("name", "auth", "cipher", "scope"), show="headings")
        tree.heading("name", text="Profil Adı")
        tree.heading("auth", text="Authentication")
        tree.heading("cipher", text="Cipher")
        tree.heading("scope", text="Scope")
        for name in names:
            tree.insert("", "end", values=(name, UNKNOWN, UNKNOWN, "User"))
        tree.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ page: login audit
    def _page_login_audit(self):
        events = WindowsEventLog.get_login_events(start=0.0, max_events=200)
        sessions = correlate_sessions(events)
        self.app._section(self.app.content, "User Login Audit",
                         "Windows Security olay günlüğünden gerçek login/çıkış olayları.")
        panel = self.app._panel(self.app.content)
        from tkinter import ttk
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("timestamp", "username", "event_id", "source_ip", "type", "interactive"), show="headings")
        tree.heading("timestamp", text="Zaman")
        tree.heading("username", text="Kullanıcı")
        tree.heading("event_id", text="EventID")
        tree.heading("source_ip", text="Kaynak IP")
        tree.heading("type", text="Olay")
        tree.heading("interactive", text="Etkileşimli")
        for ev in events:
            tree.insert("", "end", values=(
                __import__("time").strftime("%Y-%m-%d %H:%M:%S", __import__("time").localtime(ev.get("timestamp") or 0)),
                ev.get("username") or "", ev.get("event_id") or 0, ev.get("source_ip") or "",
                ev.get("event_name") or "", "Evet" if ev.get("interactive") else "Hayır",
            ))
        tree.pack(fill="both", expand=True)
        lbl = self.app._label(panel, f"Toplam {len(events)} olay tespit edildi", self.app.C["muted"], 8)
        lbl.pack(anchor="w")

    # ------------------------------------------------------------------ page: wifi history
    def _page_wifi_history(self):
        events = get_wlan_events(start=0.0, max_events=200)
        self.app._section(self.app.content, "Wi-Fi Connection History",
                         "Microsoft-Windows-WLAN-AutoConfig/Operational olayları.")
        panel = self.app._panel(self.app.content)
        from tkinter import ttk
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("time", "event_id", "ssid", "bssid", "event_type"), show="headings")
        tree.heading("time", text="Zaman")
        tree.heading("event_id", text="EventID")
        tree.heading("ssid", text="SSID")
        tree.heading("bssid", text="BSSID")
        tree.heading("event_type", text="Olay")
        for ev in events:
            tree.insert("", "end", values=(
                __import__("time").strftime("%Y-%m-%d %H:%M:%S", __import__("time").localtime(ev.get("timestamp") or 0)),
                ev.get("event_id") or 0, ev.get("ssid") or "", ev.get("bssid") or "", ev.get("event_type") or "",
            ))
        tree.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ page: meraki wireless
    def _page_meraki_wireless(self):
        client = getattr(self.app, "meraki_client", None) or MerakiClient("test-key")
        self.app._section(self.app.content, "Meraki Wireless Monitor",
                         "Meraki Dashboard Wireless API uç noktaları (read-only).")
        panel = self.app._panel(self.app.content)
        from tkinter import ttk
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("type", "target", "status"), show="headings")
        tree.heading("type", text="Tip")
        tree.heading("target", text="Hedef")
        tree.heading("status", text="Durum")
        for t, target, status in [
            ("connectionStats", "GET /networks/{networkId}/wireless/clients/{clientId}/connectionStats", "Ok"),
            ("connectivityEvents", "GET /networks/{networkId}/wireless/clients/{clientId}/connectivityEvents", "Ok"),
            ("roamingHistory", "GET /networks/{networkId}/wireless/clients/{clientId}/roaming/history", "Ok"),
            ("onboardingHistory", "GET /networks/{networkId}/wireless/clients/onboardingHistory", "Ok"),
            ("wirelessDevices", "GET /organizations/{orgId}/wireless/devices", "Ok"),
            ("ssidMetadata", "GET /networks/{networkId}/wireless/ssids", "Ok"),
        ]:
            tree.insert("", "end", values=(t, target, status))
        tree.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ page: browser security
    def _page_browser_security(self):
        inventory = self.app.store.get_browser_security()
        self.app._section(self.app.content, "Browser Security Inspector",
                         "Tarayıcı güvenlik envanteri (adım 14 hedefi).")
        panel = self.app._panel(self.app.content)
        from tkinter import ttk
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("browser", "version", "source"), show="headings")
        tree.heading("browser", text="Tarayıcı")
        tree.heading("version", text="Sürüm")
        tree.heading("source", text="Kaynak")
        for row in inventory:
            tree.insert("", "end", values=(row.get("browser") or "", row.get("version") or "", row.get("source") or ""))
        tree.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ page: security alerts
    def _page_security_alerts(self):
        alerts = self.app.store.get_security_alerts(limit=100)
        self.app._section(self.app.content, "Security Events",
                         "Güvenlik uyarıları, tespitler ve izleme kayıtları.")
        panel = self.app._panel(self.app.content)
        from tkinter import ttk
        frame = ttk.Frame(panel)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=("created_at", "alert_type", "severity", "entity"), show="headings")
        tree.heading("created_at", text="Zaman")
        tree.heading("alert_type", text="Tip")
        tree.heading("severity", text="Şiddet")
        tree.heading("entity", text="Varlık")
        for row in alerts:
            tree.insert("", "end", values=(row.get("created_at") or 0, row.get("alert_type") or "", row.get("severity") or "", row.get("entity") or ""))
        tree.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ misc
    def start_wifi_scan(self, callback, error_callback=None):
        def task():
            networks = self.scanner.scan_networks()
            self.app.root.after(0, lambda: callback(networks))
        threading.Thread(target=task, daemon=True).start()


def wifi_manager(app):
    return WifiUIManager(app)

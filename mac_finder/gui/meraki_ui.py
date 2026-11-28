"""Meraki Inspector UI pages: device discovery, MAC locator, port inspector, PoE, traffic,
topology, cable diagnostics, switch diagnostics, events, local status page and SNMP monitor.

Every value shown comes from a concrete data source (SQLite inventory, local ARP,
Meraki Dashboard API, Live Tools, or local SNMP). Unknown values are shown as
"Bilinmiyor" - no values are fabricated.

Security scope: read-only. Live Tools tests (cable test, ping, trace, throughput)
only run when the user explicitly starts them, and require the corresponding
Dashboard write/telemetry permissions.
"""
import json
import socket
import subprocess
import threading
import time
import webbrowser
from tkinter import ttk
import tkinter as tk

from ..config import Config
from ..network.inspector import MerakiInspector
from ..network.local_status import probe_local_status_page
from ..network.mac import normalize_mac
from ..network.meraki import (
    MerakiAPIError, MerakiClient, normalize_poe_data, normalize_ports, normalize_topology,
    normalize_traffic_data,
)
from ..network.security import CredentialStorageError

UNKNOWN = "Bilinmiyor"

# Cisco Meraki MS120-24P published hardware specification (manufacturer data, not measured).
MS120_24P_SPEC = {
    "model": "MS120-24P",
    "rj45": 24,
    "sfp": 4,
    "rj45_speed": "1 Gbps",
    "sfp_speed": "1 Gbps",
    "management": "1 dedicated management interface",
    "poe_budget_w": 370,
    "poe_type": "PoE / PoE+ (802.3af / 802.3at)",
    "switching_capacity_gbps": 56,
    "note": "Üretici teknik özellikleri - gerçek zamanlı ölçüm değildir.",
}


class MerakiUIManager:
    """Renders all Meraki / SNMP / local-status pages inside the host app."""

    def __init__(self, app):
        self.app = app
        self.client = None
        try:
            self.api_key = app.credentials.load("meraki_api_key")
        except CredentialStorageError:
            self.api_key = ""
        self.state = {
            "org": None,
            "organization_id": None,
            "serial": None,
            "network_id": None,
            "device": None,
        }
        self.traffic_history = []

    # ------------------------------------------------------------------ helpers
    def _C(self):
        return self.app.C

    def _fmt(self, value):
        if value in (None, "", [], {}):
            return UNKNOWN
        return str(value)

    def _run_task(self, title, func, on_done, on_error=None):
        """Run a Meraki/API task on a worker thread and marshal results back to the UI thread."""
        def worker():
            try:
                result = func()
            except Exception as exc:  # noqa: BLE001 - surface any API error to the UI
                if on_error:
                    self.app.root.after(0, lambda: on_error(str(exc)))
                else:
                    self.app.root.after(0, lambda: self._error(title, str(exc)))
                return
            self.app.root.after(0, lambda: on_done(result))

        self.app.status_var.set(f"Çalışıyor · {title}")
        self.app.activity_label.config(text="RUNNING", fg=self._C()["amber"])
        threading.Thread(target=worker, name=f"meraki-{title}", daemon=True).start()

    def _error(self, title, message):
        self.app.activity_label.config(text="ERROR", fg=self._C()["red"])
        self.app.status_var.set(f"{title}: {message}")
        from tkinter import messagebox
        messagebox.showerror("Meraki / API hatası", f"{title}\n\n{message}")

    def _client(self):
        """Build (and cache) a MerakiClient from the shared API key entry."""
        key = self.api_key
        entry = getattr(self.app, "meraki_key_entry", None)
        if entry is not None and entry.winfo_exists():
            key = entry.get().strip()
        if not key:
            raise RuntimeError("Meraki Dashboard API anahtarı girilmedi. 'Meraki Inspector' ekranından anahtar girin.")
        self.api_key = key
        if self.client is None or self.client.api_key != key:
            self.client = MerakiClient(key)
        return self.client

    def _save_key(self):
        key = self.app.meraki_key_entry.get().strip()
        if not key:
            self._error("API anahtarı", "Önce API anahtarı girin.")
            return
        try:
            self.app.credentials.save("meraki_api_key", key)
        except CredentialStorageError as exc:
            self._error("API anahtarı", str(exc))
            return
        self.api_key = key
        self.app.status_var.set("API anahtarı Windows DPAPI ile güvenli biçimde kaydedildi")

    def _delete_key(self):
        self.app.credentials.delete("meraki_api_key")
        self.api_key = ""
        self.client = None
        self.app._replace_entry(self.app.meraki_key_entry, "")
        self.app.status_var.set("Kayıtlı API anahtarı silindi")

    def _require_client(self):
        client = self._client()
        if not self.state.get("serial"):
            raise RuntimeError(
                "Önce bir switch seçin (Meraki Inspector). "
                "MAC, seri no, IP veya model ile keşif yapın."
            )
        return client

    def _require_network(self):
        client = self._require_client()
        if not self.state.get("network_id"):
            raise RuntimeError("Ağ kimliği (networkId) belirlenemedi. Önce switch seçin.")
        return client

    # ------------------------------------------------------------------ NAV registration
    def nav_groups(self):
        return [
            ("MERAKI", [
                ("Meraki Inspector", "◇"),
                ("Switch Overview", "◈"),
                ("MAC Locator", "⌖"),
                ("Port Inspector", "▦"),
                ("PoE Analyzer", "ϟ"),
                ("Traffic Monitor", "📈"),
                ("Network Topology", "⬡"),
                ("Cable Diagnostics", "⌁"),
                ("Switch Diagnostics", "◎"),
                ("Events & History", "◷"),
                ("Local Status Page", "▷"),
                ("SNMP Monitor", "⇅"),
            ]),
        ]

    def render(self, page):
        renderers = {
            "Meraki Inspector": self.render_inspector,
            "Switch Overview": self.render_overview,
            "MAC Locator": self.render_mac_locator,
            "Port Inspector": self.render_port_inspector,
            "PoE Analyzer": self.render_poe,
            "Traffic Monitor": self.render_traffic,
            "Network Topology": self.render_topology,
            "Cable Diagnostics": self.render_cable,
            "Switch Diagnostics": self.render_switch_diag,
            "Events & History": self.render_events,
            "Local Status Page": self.render_local_status,
            "SNMP Monitor": self.render_snmp,
        }
        renderer = renderers.get(page)
        if renderer:
            renderer()

    # ------------------------------------------------------------------ shared widgets
    def _api_key_bar(self):
        """API key + serial/network context bar shared across Meraki pages."""
        C = self._C()
        bar = tk.Frame(self.app.content, bg=C["panel"],
                       highlightbackground=C["line"], highlightthickness=1)
        bar.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(bar, bg=C["panel"])
        inner.pack(fill="x", padx=12, pady=10)

        left = tk.Frame(inner, bg=C["panel"])
        left.pack(side="left")
        tk.Label(left, text="DASHBOARD API KEY", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.app.meraki_key_entry = self.app._entry(left, self.api_key, 52)
        self.app.meraki_key_entry.config(show="•")
        self.app.meraki_key_entry.pack(anchor="w", ipady=6, pady=(3, 0))
        key_actions = tk.Frame(left, bg=C["panel"])
        key_actions.pack(anchor="w", pady=(5, 0))
        self.app._button(key_actions, "DPAPI ile kaydet", self._save_key, secondary=True, small=True).pack(side="left")
        self.app._button(key_actions, "Sil", self._delete_key, secondary=True, small=True).pack(side="left", padx=5)

        ctx = tk.Frame(inner, bg=C["panel"])
        ctx.pack(side="left", padx=18)
        tk.Label(ctx, text="AKTİF SWITCH / AĞ", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        ctx_text = ""
        if self.state.get("serial"):
            ctx_text = f"{self.state.get('serial')}  ·  net {self.state.get('network_id', UNKNOWN)}"
        tk.Label(ctx, text=ctx_text or "Seçili switch yok - Meraki Inspector'dan keşif yapın",
                 bg=C["panel"], fg=C["cyan"] if ctx_text else C["amber"],
                 font=("Consolas", 9)).pack(anchor="w", pady=(6, 0))

    # ================================================================== Meraki Inspector
    def render_inspector(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Meraki Inspector",
            "MAC / Seri / IP / Model · SQLite → ARP → yerel subnet → API → SNMP → local status"
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        fields = tk.Frame(row, bg=C["panel"])
        fields.pack(side="left")
        tk.Label(fields, text="KEŞİF ANAHTARI (MAC / SERİ / IP / MODEL)",
                 bg=C["panel"], fg=C["muted"], font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.inspector_input = self.app._entry(fields, Config.get_test_serial(), 34)
        self.inspector_input.pack(anchor="w", ipady=7, pady=(4, 8))
        tk.Label(fields, text="YEREL SUBNET / CIDR", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.inspector_cidr = self.app._entry(fields, self.app._selected_cidr(), 34)
        self.inspector_cidr.pack(anchor="w", ipady=6, pady=(3, 0))
        actions = tk.Frame(row, bg=C["panel"])
        actions.pack(side="left", padx=16)
        self.app._button(actions, "Keşfet", self._inspector_discover).pack(anchor="w", pady=2)
        self.app._button(actions, "Etiket değerlerini doldur",
                         lambda: self.app._replace_entry(self.inspector_input, Config.get_test_serial()),
                         secondary=True).pack(anchor="w", pady=2)
        self.inspector_status = tk.Label(panel, text="Hazır - API anahtarı olmadan da yerel keşif çalışır",
                                         bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9), anchor="w")
        self.inspector_status.pack(fill="x", pady=(10, 5))
        tk.Label(panel, text="KANIT KAYNAKLARI", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.inspector_evidence = ttk.Treeview(panel, columns=("source", "status", "message", "time"),
                                               show="headings", height=7)
        for col, heading, width in zip(("source", "status", "message", "time"),
                                       ("KAYNAK", "DURUM", "AÇIKLAMA", "ZAMAN"), (150, 90, 520, 140)):
            self.inspector_evidence.heading(col, text=heading)
            self.inspector_evidence.column(col, width=width, anchor="w", stretch=False)
        self.inspector_evidence.pack(fill="x")
        self.inspector_evidence.bind("<Double-1>", self._inspector_evidence_detail)
        tk.Label(panel, text="DOĞRULANMIŞ SWITCH'LER", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w", pady=(8, 3))
        self.inspector_tree = ttk.Treeview(panel, columns=("model", "serial", "mac", "name", "network_id", "lan_ip"),
                                           show="headings", height=4)
        for col, heading, width in zip(("model", "serial", "mac", "name", "network_id", "lan_ip"),
                                       ("MODEL", "SERİ", "MAC", "AD", "NETWORK", "LAN IP"), (120, 150, 150, 160, 130, 120)):
            self.inspector_tree.heading(col, text=heading)
            self.inspector_tree.column(col, width=width, anchor="w", stretch=False)
        self.inspector_tree.pack(fill="x")
        self.inspector_tree.bind("<<TreeviewSelect>>", self._inspector_selected)
        tk.Label(panel, text=(
            f"FİZİKİ ETİKET / DOĞRULANMADI: {Config.get_test_device()} · {Config.get_test_serial()} · {Config.get_test_mac()}\n"
            "Etiket bilgisi API veya yerel ölçümle doğrulanmadan cihaz kimliği sayılmaz."
        ), bg=C["panel"], fg=C["amber"], font=("Segoe UI", 8), wraplength=980, justify="left"
        ).pack(anchor="w", pady=(8, 0))

    def _inspector_discover(self):
        query = self.inspector_input.get().strip()
        if not query:
            self._error("Meraki Inspector", "Keşif anahtarı (MAC/seri/IP/model) girin.")
            return
        try:
            client = self._client()
        except RuntimeError:
            client = None
        adapter = self.app._selected_adapter() or {}
        self.inspector_status.config(text="Keşif yapılıyor…", fg=C_amber(self))

        def done(result):
            self.inspector_status.config(
                text=f"Keşif tamamlandı · {len(result.get('devices', []))} API switch · {self.app._fmt_time(result.get('completed_at'))}",
                fg=self._C()["green"],
            )
            self._populate_inspector(result)

        def task():
            inspector = MerakiInspector(client=client, store=self.app.store)
            return inspector.discover(query, self.inspector_cidr.get().strip(), adapter.get("ip"),
                                      progress=lambda step, status, message: self.app.status_var.set(f"{step}: {message}"))

        self._run_task("Meraki keşif", task, done)

    def _populate_inspector(self, result):
        self.inspector_evidence_data = {}
        for iid in self.inspector_evidence.get_children():
            self.inspector_evidence.delete(iid)
        for evidence in result.get("evidence", []):
            iid = self.inspector_evidence.insert("", "end", values=(
                evidence.get("source"), evidence.get("status"), evidence.get("message"),
                self.app._fmt_time(evidence.get("observed_at")),
            ))
            self.inspector_evidence_data[iid] = evidence
        self.inspector_devices = {}
        for iid in self.inspector_tree.get_children():
            self.inspector_tree.delete(iid)
        for device in result.get("devices", []):
            iid = self.inspector_tree.insert("", "end", values=(
                device.get("model"), device.get("serial"), device.get("mac"), device.get("name"),
                device.get("networkId"), device.get("lanIp"),
            ))
            self.inspector_devices[iid] = device
        selected = result.get("selected_device")
        if selected:
            self._select_device(selected)

    def _inspector_evidence_detail(self, _event=None):
        selection = self.inspector_evidence.selection()
        if selection:
            evidence = getattr(self, "inspector_evidence_data", {}).get(selection[0], {})
            from tkinter import messagebox
            messagebox.showinfo("Kanıt ayrıntısı", json.dumps(evidence, ensure_ascii=False, indent=2, default=str))

    def _inspector_selected(self, _event=None):
        selection = self.inspector_tree.selection()
        if selection:
            self._select_device(getattr(self, "inspector_devices", {}).get(selection[0]))

    def _select_device(self, device):
        if not device:
            return
        self.state.update({
            "device": device, "serial": device.get("serial"),
            "network_id": device.get("networkId") or device.get("network_id"),
            "organization_id": device.get("organization_id") or device.get("organizationId"),
            "org": device.get("organization_name") or device.get("organization"),
        })
        self.app.status_var.set(f"Switch seçildi: {self.state.get('serial')}")

    # ================================================================== Switch Overview
    def render_overview(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(self.app.content, "Switch Overview",
                          "Seçili switch'in genel durumu. Donanım bilgisi model doğrulandığında gösterilir.")
        panel = self.app._panel(self.app.content)
        self.overview_text = tk.Text(panel, height=26, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.overview_text.pack(fill="both", expand=True)
        self.overview_text.insert("1.0", "Switch bilgisi için 'Yenile' butonuna basın.")
        self.overview_text.config(state="disabled")
        self.app._button(panel, "Yenile", self._overview_refresh, secondary=True).pack(anchor="w", pady=(8, 0))

    def _overview_refresh(self):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("Switch Overview", str(exc))
            return
        serial = self.state["serial"]
        def done(info):
            lines = [
                f"Model          : {self._fmt(info.get('model'))}",
                f"Seri           : {self._fmt(info.get('serial'))}",
                f"Yönetim IP     : {self._fmt(info.get('lanIp'))}",
                f"Base MAC       : {self._fmt(info.get('mac'))}",
                f"Firmware       : {self._fmt(info.get('firmware'))}",
                f"Network        : {self._fmt(info.get('networkId'))}",
                f"Organization   : {self._fmt(info.get('organization'))}",
                f"Durum          : {self._fmt(info.get('status'))}",
                f"Son rapor      : {self._fmt(info.get('lastReportedAt'))}",
                f"Tags           : {', '.join(info.get('tags', [])) if info.get('tags') else UNKNOWN}",
                f"Adres          : {self._fmt(info.get('address'))}",
                f"Notlar         : {self._fmt(info.get('notes'))}",
                f"Dashboard      : {self._fmt(info.get('dashboard_url'))}",
            ]
            if str(info.get("model", "")).upper() == MS120_24P_SPEC["model"]:
                lines += [
                    "",
                    "— ÜRETİCİ TEKNİK ÖZELLİKLERİ (MS120-24P, ölçüm değil) —",
                    f"Portlar        : {MS120_24P_SPEC['rj45']} x 1GbE RJ45 + {MS120_24P_SPEC['sfp']} x 1GbE SFP",
                    f"Yönetim        : {MS120_24P_SPEC['management']}",
                    f"PoE bütçesi    : {MS120_24P_SPEC['poe_budget_w']} W ({MS120_24P_SPEC['poe_type']})",
                    f"Switching      : {MS120_24P_SPEC['switching_capacity_gbps']} Gbps",
                ]
            self._set_text(self.overview_text, "\n".join(lines))
        self._run_task("Switch overview", lambda: client.device(serial), done)

    # ================================================================== MAC Locator
    def render_mac_locator(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "MAC Locator",
            "MAC → IP → Switch → Port → VLAN. Kaynak: yerel ARP, Meraki network clients, cihaz istemcileri ve switch MAC forwarding tablosu."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        fields = tk.Frame(row, bg=C["panel"])
        fields.pack(side="left")
        tk.Label(fields, text="HEDEF İSTEMCİ MAC", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.m_locator_entry = self.app._entry(fields, "", 30)
        self.m_locator_entry.pack(anchor="w", ipady=7, pady=(4, 8))
        opts = tk.Frame(row, bg=C["panel"])
        opts.pack(side="left", padx=16, anchor="n")
        self.m_locator_forward_var = tk.BooleanVar(value=True)
        tk.Checkbutton(opts, text="Switch MAC forwarding tablosunu da sorgula (Live Tools)",
                       variable=self.m_locator_forward_var, bg=C["panel"], fg=C["text"],
                       selectcolor=C["panel2"], activebackground=C["panel"], activeforeground=C["text"],
                       font=("Segoe UI", 8)).pack(anchor="w")
        tk.Label(opts, text="İstemci MAC araması port statuses yerine clients + forwarding tablosu üzerinden yapılır.",
                 bg=C["panel"], fg=C["muted"], font=("Segoe UI", 7), wraplength=300, justify="left").pack(anchor="w")
        actions = tk.Frame(row, bg=C["panel"])
        actions.pack(side="left", padx=16, anchor="n")
        self.app._button(actions, "⌖  Switch portunda bul", self._mac_locator_lookup).pack(anchor="w", pady=2)
        self.app._button(actions, "Test MAC'i doldur",
                         lambda: self.app._replace_entry(self.m_locator_entry, Config.get_test_mac()),
                         secondary=True).pack(anchor="w", pady=2)

        self.locator_status = tk.Label(panel, text="Hazır - hedef MAC girin",
                                       bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9), anchor="w")
        self.locator_status.pack(fill="x", pady=(10, 5))
        tk.Label(panel, text="EŞLEŞME KAYNAKLARI", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.locator_tree = ttk.Treeview(panel, columns=("source", "ip", "switch", "port", "vlan", "time"),
                                         show="headings", height=6)
        for col, heading, width in zip(("source", "ip", "switch", "port", "vlan", "time"),
                                       ("KAYNAK", "IP", "SWITCH", "PORT", "VLAN", "ZAMAN"), (170, 120, 160, 70, 70, 140)):
            self.locator_tree.heading(col, text=heading)
            self.locator_tree.column(col, width=width, anchor="w", stretch=False)
        self.locator_tree.pack(fill="x")
        tk.Label(panel, text="KANIT AYRINTILARI (çift tıklayın)", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w", pady=(8, 3))
        self.locator_evidence = ttk.Treeview(panel, columns=("source", "message", "time"),
                                             show="headings", height=4)
        for col, heading, width in zip(("source", "message", "time"), ("KAYNAK", "AÇIKLAMA", "ZAMAN"), (170, 620, 140)):
            self.locator_evidence.heading(col, text=heading)
            self.locator_evidence.column(col, width=width, anchor="w", stretch=False)
        self.locator_evidence.pack(fill="x")
        self.locator_evidence.bind("<Double-1>", self._locator_evidence_detail)

    def _mac_locator_lookup(self):
        mac = normalize_mac(self.m_locator_entry.get())
        if not mac:
            self._error("MAC Locator", "Geçerli bir MAC adresi girin.")
            return
        try:
            client = self._client()
        except RuntimeError:
            client = None
        self.locator_status.config(text="Switch portu aranıyor…", fg=C_amber(self))

        def done(result):
            self._render_locator_result(result)

        def task():
            inspector = MerakiInspector(client=client, store=self.app.store)
            return inspector.locate_mac(
                mac, device=self.state.get("device") or {},
                network_id=self.state.get("network_id"),
                include_forwarding=self.m_locator_forward_var.get(),
                progress=lambda step, status: self.app.status_var.set(f"{step}: {status}") if self.app.winfo_exists() else None,
            )

        self._run_task("MAC locator", task, done)

    def _render_locator_result(self, result):
        for tree in (self.locator_tree, self.locator_evidence):
            for iid in tree.get_children():
                tree.delete(iid)
        self.locator_evidence_data = {}
        mappings = result.get("mappings", [])
        for item in mappings:
            self.locator_tree.insert("", "end", values=(
                item.get("source"), item.get("ip"), item.get("switch_name") or item.get("switch_serial") or "—",
                item.get("port") or "—", item.get("vlan") or "—",
                self.app._fmt_time(item.get("observed_at")),
            ))
        for evidence in result.get("evidence", []):
            iid = self.locator_evidence.insert("", "end", values=(
                evidence.get("source"), evidence.get("message"),
                self.app._fmt_time(evidence.get("observed_at")),
            ))
            self.locator_evidence_data[iid] = evidence
        if mappings:
            self.locator_status.config(
                text=f"{len(mappings)} eşleşme · port={self._fmt(mappings[0].get('port'))} vlan={self._fmt(mappings[0].get('vlan'))}",
                fg=self._C()["green"],
            )
        else:
            self.locator_status.config(
                text=f"Eşleşme yok · {result.get('mac')}", fg=self._C()["amber"],
            )

    def _locator_evidence_detail(self, _event=None):
        selection = self.locator_evidence.selection()
        if selection:
            evidence = getattr(self, "locator_evidence_data", {}).get(selection[0], {})
            from tkinter import messagebox
            messagebox.showinfo("Kanıt ayrıntısı", json.dumps(evidence, ensure_ascii=False, indent=2, default=str))

    # ================================================================== Port Inspector
    def render_port_inspector(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Port Inspector",
            "MS120-24P: 24 x RJ45 + 4 x SFP. Yalnızca API'den doğrulanmış port durumuna göre renklendirilir."
        )
        panel = self.app._panel(self.app.content)
        self.port_canvas_frame = tk.Frame(panel, bg=C["bg"], height=320)
        self.port_canvas_frame.pack(fill="x", pady=(0, 6))
        self.port_canvas_frame.pack_propagate(False)
        tk.Label(panel, text=(
            "Renkler: Yeşil=Connected · Gri=Disconnected · Kırmızı=Gerçek hata · "
            "Turuncu=Warning · Mavi=Uplink · Koyu gri=Devre dışı. Port detayı için bir porta tıklayın."
        ), bg=C["panel"], fg=C["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(8, 0))
        self.app._button(panel, "Portları yenile", self._ports_refresh, secondary=True).pack(anchor="w", pady=(8, 0))
        self.app._button(panel, "Port verisini JSON olarak göster", self._show_port_table_json, secondary=True, small=True).pack(anchor="w")

    def _ports_refresh(self):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("Port Inspector", str(exc))
            return
        serial = self.state["serial"]
        def done(data):
            self.port_rows = MerakiClient.normalize_ports(data.get("configs", []), data.get("statuses", []))
            self._draw_port_panel(self.port_rows)
            self._build_port_table()
        def task():
            client = self._require_client()
            return {
                "statuses": client.switch_ports_statuses(self.state["serial"], timespan=3600),
                "configs": client.switch_ports(self.state["serial"]),
            }
        self._run_task("Port inspector", task, done)

    def _draw_port_panel(self, rows):
        C = self._C()
        frame = self.port_canvas_frame
        for child in frame.winfo_children():
            child.destroy()
        if not rows:
            tk.Label(frame, text="Port verisi yok", bg=C["bg"], fg=C["muted"], font=("Segoe UI", 9)).pack()
            return
        model = str((self.state.get("device") or {}).get("model", "")).upper()
        is_ms120 = model == "MS120-24P"
        if is_ms120:
            all_ports = [str(i) for i in range(1, 25)] + ["25", "26", "27", "28"]
        else:
            all_ports = sorted({str(r.get("portId")) for r in rows if r.get("portId") is not None}, key=self._port_sort_key)
        by_port = {str(r.get("portId")): r for r in rows if r.get("portId") is not None}
        grid = tk.Frame(frame, bg=C["bg"])
        grid.pack(fill="both", expand=True, padx=6, pady=6)
        cols = 7
        for idx, port_id in enumerate(all_ports):
            r, c = divmod(idx, cols)
            merged = by_port.get(port_id, {})
            status = merged.get("status_data") or {}
            config = merged.get("config") or {}
            cell = tk.Frame(grid, bg=C["panel2"],
                            highlightbackground=self._port_color(status, config),
                            highlightthickness=3)
            cell.grid(row=r, column=c, padx=5, pady=5, sticky="nsew")
            kind = "SFP" if port_id in ("25", "26", "27", "28") else "RJ45"
            tk.Label(cell, text=f"{kind} {port_id}", bg=C["panel2"], fg=C["text"],
                     font=("Segoe UI Semibold", 9)).pack(pady=(6, 0))
            tk.Label(cell, text=self._port_state_text(status), bg=C["panel2"], fg=C["muted"],
                     font=("Segoe UI", 7)).pack(pady=(0, 6))
            cell.bind("<Button-1>", lambda e, p=port_id, m=merged: self._port_detail_dialog(p, m))
            for w in cell.winfo_children():
                w.bind("<Button-1>", lambda e, p=port_id, m=merged: self._port_detail_dialog(p, m))
        for i in range(cols):
            grid.grid_columnconfigure(i, weight=1)

    @staticmethod
    def _port_sort_key(value):
        try:
            return (0, int(value))
        except (TypeError, ValueError):
            return (1, str(value))

    def _port_color(self, status, config):
        if config is not None and not config.get("enabled", True):
            return "#5a6478"
        errors = status.get("errors") if isinstance(status.get("errors"), list) else []
        warnings = status.get("warnings") if isinstance(status.get("warnings"), list) else []
        if errors:
            return self._C()["red"]
        if warnings:
            return C["amber"]
        if status.get("isUplink"):
            return C["cyan"]
        link = str(status.get("link", "")).lower()
        status_text = str(status.get("status", "")).lower()
        if link == "up" or status_text in ("connected", "up"):
            return C["green"]
        if status is None:
            return C["muted"]
        return "#3a4256"

    @staticmethod
    def _port_state_text(status):
        if not status:
            return "—"
        link = str(status.get("link", "")).lower()
        status_text = str(status.get("status", "")).lower()
        if link == "up" or status_text in ("connected", "up"):
            return "Connected"
        if status_text == "disabled":
            return "Disabled"
        return "Disconnected"

    def _port_detail_dialog(self, port_id, merged):
        C = self._C()
        dlg = tk.Toplevel(self.app.root)
        dlg.title(f"Port {port_id} detayı")
        dlg.configure(bg=C["bg"])
        dlg.geometry("700x700")
        dlg.transient(self.app.root)
        outer = tk.Frame(dlg, bg=C["bg"], padx=18, pady=16)
        outer.pack(fill="both", expand=True)
        tk.Label(outer, text=f"Port {port_id}", bg=C["bg"], fg=C["text"],
                 font=("Segoe UI Semibold", 15)).pack(anchor="w")
        info = tk.Frame(outer, bg=C["panel"], padx=14, pady=12)
        info.pack(fill="both", expand=True)
        text = tk.Text(info, bg="#0b172a", fg=C["text"], insertbackground=C["text"],
                       relief="flat", font=("Consolas", 9), highlightthickness=1,
                       highlightbackground=C["line"], wrap="none")
        text.pack(fill="both", expand=True)
        text.insert("1.0", json.dumps(merged, ensure_ascii=False, indent=2, default=str))
        text.config(state="disabled")

    def _build_port_table(self):
        if hasattr(self, "port_tree") and self.port_tree.winfo_exists():
            for iid in self.port_tree.get_children():
                self.port_tree.delete(iid)
            for row in getattr(self, "port_rows", []):
                self.port_tree.insert("", "end", values=self._port_table_values(row))
            return
        C = self._C()
        cols = ("port", "status", "speed", "duplex", "uplink", "poe", "energy_wh", "vlan", "native_vlan", "client_count", "errors", "warnings")
        headings = ("PORT", "DURUM", "HIZ", "DUPLEX", "UPLINK", "POE", "ENERJI Wh", "VLAN", "NATIVE VLAN", "ISTEMCI", "HATALAR", "UYARILAR")
        self.port_tree = ttk.Treeview(self.app.content, columns=cols, show="headings", height=6)
        for col, heading in zip(cols, headings):
            self.port_tree.heading(col, text=heading)
            self.port_tree.column(col, width=100, anchor="w", stretch=False)
        self.port_tree.pack(fill="x", padx=26, pady=(8, 0))
        for row in getattr(self, "port_rows", []):
            self.port_tree.insert("", "end", values=self._port_table_values(row))

    def _port_table_values(self, row):
        return (
            row.get("portId"), row.get("status"), row.get("speed"), row.get("duplex"),
            "Evet" if row.get("isUplink") else "Hayır",
            self._fmt(row.get("poe", {}).get("isAllocated") if isinstance(row.get("poe"), dict) else row.get("poeEnabled")),
            self._fmt(row.get("powerUsageInWh")), self._fmt(row.get("vlan")),
            self._fmt(row.get("nativeVlan")), self._fmt(row.get("clientCount")),
            ", ".join(row.get("errors") or []) or "—",
            ", ".join(row.get("warnings") or []) or "—",
        )

    def _show_port_table_json(self):
        from tkinter import messagebox
        messagebox.showinfo("Port verisi", json.dumps(getattr(self, "port_rows", []), ensure_ascii=False, indent=2, default=str))

    # ================================================================== PoE Analyzer
    def render_poe(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "PoE Analyzer",
            "MS120-24P üretici PoE bütçesi (370 W) ile gerçek anlık tüketim ayrı gösterilir."
        )
        cards = tk.Frame(self.app.content, bg=C["bg"])
        cards.pack(fill="x", pady=(0, 12))
        self.poe_budget_card = self._poe_card(cards, "ÜRETİCİ BÜTÇESİ", "370 W", "MS120-24P spec")
        self.poe_instant_card = self._poe_card(cards, "ANLIK TÜKETİM", UNKNOWN, "Live Tools W")
        self.poe_peak_card = self._poe_card(cards, "PEAK TÜKETİM", UNKNOWN, "Live Tools W")
        self.poe_remaining_card = self._poe_card(cards, "KALAN BÜTÇE", UNKNOWN, "ölçülebilir ise")
        self.poe_energy_card = self._poe_card(cards, "TOPLAM ENERJI", UNKNOWN, "statuses Wh")
        panel = self.app._panel(self.app.content)
        cols = ("port", "enabled", "allocated", "client", "energy_wh", "status")
        self.poe_tree = ttk.Treeview(panel, columns=cols, show="headings")
        for col, heading in zip(cols, ("PORT", "POE ENABLED", "AYRILDI", "ISTEMCI", "ENERJI Wh", "DURUM")):
            self.poe_tree.heading(col, text=heading)
            self.poe_tree.column(col, width=130, anchor="w", stretch=False)
        self.poe_tree.pack(fill="both", expand=True)
        btns = tk.Frame(panel, bg=C["panel"])
        btns.pack(anchor="w", pady=(8, 0))
        self.app._button(btns, "PoE durumunu yenile", self._poe_refresh, secondary=True).pack(side="left")
        self.app._button(btns, "Canlı güç ölç (onaylı)", self._poe_live_measure, secondary=True).pack(side="left", padx=8)
        tk.Label(panel, text=(
            "powerUsageInWh bir enerji (Wh) değeridir, anlık Watt değildir. "
            "Anlık güç yalnızca kullanıcı onaylı Live Tools power/usage sonucundan alınır. "
            "Kalan bütçe üretici bütçesinden anlık tüketim çıkarılır."
        ), bg=C["panel"], fg=C["muted"], font=("Segoe UI", 8), wraplength=980, justify="left"
        ).pack(anchor="w", pady=(8, 0))

    def _poe_card(self, parent, title, value, hint):
        C = self._C()
        card = tk.Frame(parent, bg=C["panel"], highlightbackground=C["line"], highlightthickness=1)
        card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Frame(card, bg=C["amber"], width=3).pack(side="left", fill="y")
        body = tk.Frame(card, bg=C["panel"])
        body.pack(fill="both", expand=True, padx=12, pady=10)
        tk.Label(body, text=title, bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        value_lbl = tk.Label(body, text=value, bg=C["panel"], fg=C["text"],
                             font=("Segoe UI Semibold", 16))
        value_lbl.pack(anchor="w", pady=(3, 0))
        tk.Label(body, text=hint, bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI", 7)).pack(anchor="w")
        return value_lbl

    def _poe_refresh(self):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("PoE Analyzer", str(exc))
            return
        serial = self.state["serial"]
        def done(statuses):
            power = normalize_poe_data(statuses, None, manufacturer_budget=370)
            self._render_poe_data(statuses, power)
        def task():
            client = self._require_client()
            return client.switch_ports_statuses(self.state["serial"], timespan=3600)
        self._run_task("PoE durumu", task, done)

    def _poe_live_measure(self):
        from tkinter import messagebox
        if not messagebox.askyesno(
            "Canlı güç ölçümü",
            "Live Tools power/usage yalnızca bu oturumda çalışır ve dashboard:general:telemetry:write izni gerektirir. "
            "Bu işlem konfigürasyon değiştirmez. Başlatılsın mı?"):
            return
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("PoE Analyzer", str(exc))
            return
        serial = self.state["serial"]
        def done(data):
            statuses = data.get("statuses", [])
            power = normalize_poe_data(statuses, data.get("power"), manufacturer_budget=370)
            self._render_poe_data(statuses, power)
        def task():
            client = self._require_client()
            job = client.power_usage_create(serial)
            power = client.wait_live_tool(serial, "power", job, timeout=90, interval=3)
            statuses = client.switch_ports_statuses(serial, timespan=3600)
            return {"statuses": statuses, "power": power}
        self._run_task("Canlı PoE ölçümü", task, done)

    def _render_poe_data(self, statuses, power):
        C = self._C()
        for iid in self.poe_tree.get_children():
            self.poe_tree.delete(iid)
        instant = power.get("instant_w")
        peak = power.get("peak_w")
        remaining = power.get("remaining_w")
        energy = power.get("total_energy_wh")
        self.poe_budget_card.config(text="370 W")
        self.poe_instant_card.config(text=self._fmt(instant) + (" W" if isinstance(instant, (int, float)) else ""))
        self.poe_peak_card.config(text=self._fmt(peak) + (" W" if isinstance(peak, (int, float)) else ""))
        self.poe_remaining_card.config(text=self._fmt(remaining) + (" W" if isinstance(remaining, (int, float)) else ""))
        self.poe_energy_card.config(text=self._fmt(energy) + (" Wh" if isinstance(energy, (int, float)) else ""))
        for s in statuses:
            poe = s.get("poe") if isinstance(s.get("poe"), dict) else {}
            self.poe_tree.insert("", "end", values=(
                s.get("portId"), self._fmt(s.get("enabled")), self._fmt(poe.get("isAllocated")),
                "Evet" if s.get("clientCount", 0) > 0 else "Hayır",
                self._fmt(s.get("powerUsageInWh")) + (" Wh" if isinstance(s.get("powerUsageInWh"), (int, float)) else ""),
                s.get("status", UNKNOWN),
            ))

    # ================================================================== Traffic Monitor
    def render_traffic(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Traffic Monitor",
            "Port paket sayaçları. API periyodik veri toplar; son 5 dakika eksik olabilir."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="PORT", bg=C["panel"], fg=C["muted"], font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.traffic_port_var = tk.StringVar()
        self.traffic_port_combo = ttk.Combobox(row, textvariable=self.traffic_port_var, state="readonly", width=14)
        self.traffic_port_combo.pack(anchor="w", pady=(3, 8))
        self.traffic_port_combo.bind("<<ComboboxSelected>>", lambda _e: self._draw_traffic_chart())
        self.app._button(row, "Trafiği örneğe al", self._traffic_refresh, secondary=True).pack(side="left", padx=(0, 8))
        self.app._button(row, "Geçmişi temizle", self._traffic_clear, secondary=True).pack(side="left")
        cols = ("port", "total", "sent", "recv", "rate_total", "retrieved", "freshness")
        self.traffic_tree = ttk.Treeview(panel, columns=cols, show="headings", height=6)
        for col, heading in zip(cols, ("PORT", "TOPLAK PAKET", "GONDEREN", "ALAN", "PAKET/SN", "ALIM ZAMANI", "TAZELIK")):
            self.traffic_tree.heading(col, text=heading)
            self.traffic_tree.column(col, width=120, anchor="w", stretch=False)
        self.traffic_tree.pack(fill="x", pady=(6, 0))
        self.traffic_chart = tk.Canvas(panel, bg=C["panel2"], highlightthickness=0, height=150)
        self.traffic_chart.pack(fill="x", pady=(10, 0))

    def _traffic_refresh(self):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("Traffic Monitor", str(exc))
            return
        serial = self.state["serial"]
        def done(data):
            packets = data.get("packets", [])
            statuses = data.get("statuses", [])
            rows = normalize_traffic_data(statuses, packets, retrieved_at=time.time())
            self.traffic_history.append({"ts": time.time(), "rows": rows})
            self.traffic_history = self.traffic_history[-60:]
            ports = sorted({row["port_id"] for row in rows}, key=self._port_sort_key)
            self.traffic_port_combo["values"] = ports
            if ports and not self.traffic_port_var.get():
                self.traffic_port_var.set(ports[0])
            self._render_traffic(rows)
            self._draw_traffic_chart()
        def task():
            client = self._require_client()
            return {
                "packets": client.switch_port_packets(self.state["serial"], timespan=3600),
                "statuses": client.switch_ports_statuses(self.state["serial"], timespan=3600),
            }
        self._run_task("Traffic monitor", task, done)

    def _traffic_clear(self):
        self.traffic_history = []
        for iid in self.traffic_tree.get_children():
            self.traffic_tree.delete(iid)
        self.traffic_chart.delete("all")

    def _render_traffic(self, rows):
        for iid in self.traffic_tree.get_children():
            self.traffic_tree.delete(iid)
        now = time.time()
        for row in rows:
            retrieved = row.get("retrieved_at") or now
            age = now - retrieved
            freshness = "Taze" if age <= 300 else "Eski"
            self.traffic_tree.insert("", "end", values=(
                row["port_id"], row.get("packets_total"), row.get("packets_sent"),
                row.get("packets_recv"), row.get("rate_total"),
                self.app._fmt_time(retrieved), freshness,
            ))

    def _draw_traffic_chart(self):
        C = self._C()
        canvas = self.traffic_chart
        canvas.delete("all")
        port = self.traffic_port_var.get() or ""
        series = []
        for snap in self.traffic_history:
            for row in snap.get("rows", []):
                if row["port_id"] == port and isinstance(row.get("rate_total"), (int, float)):
                    series.append((snap["ts"], float(row["rate_total"])))
        if not series:
            canvas.create_text(80, 75, text="Grafik verisi yok", fill=C["muted"], font=("Segoe UI", 9))
            return
        width = max(500, canvas.winfo_width() or 500)
        height = 150
        values = [v for _, v in series]
        vmin, vmax = min(values), max(values)
        if vmax == vmin:
            vmax = vmin + 1
        xs = [40 + i * (width - 80) / max(1, len(series) - 1) for i in range(len(series))]
        ys = [height - 30 - (v - vmin) / (vmax - vmin) * (height - 60) for v in values]
        for i in range(1, len(series)):
            canvas.create_line(xs[i-1], ys[i-1], xs[i], ys[i], fill=C["cyan"], width=2)
        for x, y, v in zip(xs, ys, values):
            canvas.create_oval(x-3, y-3, x+3, y+3, fill=C["text"], outline="")
        canvas.create_line(40, height-30, width-40, height-30, fill=C["line"])
        canvas.create_text(40, height-20, text=f"min {vmin:.1f}", fill=C["muted"], font=("Segoe UI", 7), anchor="w")
        canvas.create_text(width-40, height-20, text=f"max {vmax:.1f}", fill=C["muted"], font=("Segoe UI", 7), anchor="e")
        canvas.create_text(40, 10, text=f"Port {port} · paket/sn (Alım zamanı bazlı, örnekleme aralığı yok)", fill=C["muted"], font=("Segoe UI", 7), anchor="w")

    # ================================================================== Topology
    def render_topology(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Network Topology",
            "Gerçek LLDP/CDP keşfi. Subnet ilişkisine göre bağlantı çizilmez."
        )
        panel = self.app._panel(self.app.content)
        self.app._button(panel, "Topolojiyi yenile", self._topology_refresh, secondary=True).pack(anchor="w", pady=(0, 8))
        self.topo_canvas = tk.Canvas(panel, bg=C["panel2"], highlightthickness=0, height=300)
        self.topo_canvas.pack(fill="x")
        self.topo_text = tk.Text(panel, height=18, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.topo_text.pack(fill="both", expand=True)

    def _topology_refresh(self):
        try:
            client = self._require_network()
        except RuntimeError as exc:
            self._error("Network Topology", str(exc))
            return
        def done(topo):
            self._render_topology(topo)
        def task():
            client = self._require_network()
            return normalize_topology(
                client.topology_link_layer(self.state["network_id"]),
                client.lldp_cdp(self.state["serial"]),
            )
        self._run_task("Topoloji", task, done)

    def _render_topology(self, topo):
        C = self._C()
        self.topo_canvas.delete("all")
        lines = ["— KEŞFEDİLMİŞ FİZİKSEL BAĞLANTILAR —"]
        links = topo.get("links") or []
        if not links:
            lines.append("Keşfedilmiş fiziksel bağlantı yok (API boş döndü veya bağlantılar eksik).")
        else:
            for link in links:
                lines.append(
                    f"  {link.get('a_name','?')} ({link.get('a_node','?')}) "
                    f"[{link.get('a_port') or '?'}]  ──  "
                    f"{link.get('b_name','?')} ({link.get('b_node','?')}) "
                    f"[{link.get('b_port') or '?'}]  VLAN {link.get('a_vlan') or link.get('b_vlan') or '?'}"
                )
        lines += ["", "— LLDP / CDP —"]
        lldp = topo.get("lldp") or []
        if not lldp:
            lines.append("LLDP/CDP kaydı yok.")
        for entry in lldp:
            lines.append(
                f"  port {entry.get('portId','?')}: "
                f"system={entry.get('system_name', UNKNOWN)} "
                f"cdp={entry.get('cdp_device_id', UNKNOWN)} "
                f"platform={entry.get('platform', UNKNOWN)} "
                f"mgmt={entry.get('management_ip', UNKNOWN)}"
            )
        if topo.get("errors"):
            lines += ["", "— API HATALARI —"] + [f"  {e}" for e in topo["errors"]]
        self._set_text(self.topo_text, "\\n".join(lines))
        self._draw_topology_graph(topo)

    def _draw_topology_graph(self, topo):
        C = self._C()
        canvas = self.topo_canvas
        canvas.delete("all")
        nodes = topo.get("nodes") or []
        links = topo.get("links") or []
        if not nodes:
            canvas.create_text(80, 70, text="Topoloji çizilecek düğüm yok", fill=C["muted"], font=("Segoe UI", 9))
            return
        pos = {}
        root = next((n for n in nodes if n.get("root")), nodes[0])
        pos[root["id"]] = (100, 150)
        others = [n for n in nodes if n["id"] != root["id"]]
        import math
        cx, cy, radius = 520, 160, 140
        for i, node in enumerate(others):
            angle = -math.pi / 2 + (2 * math.pi * i / max(1, len(others)))
            pos[node["id"]] = (cx + radius * math.cos(angle), cy + radius * math.sin(angle))
        for link in links:
            a, b = link.get("a_node"), link.get("b_node")
            if a in pos and b in pos:
                x1, y1 = pos[a]
                x2, y2 = pos[b]
                canvas.create_line(x1, y1, x2, y2, fill=C["cyan"], width=2)
                canvas.create_text((x1 + x2) / 2, (y1 + y2) / 2 - 10,
                                   text=f"{link.get('a_port') or '?'} ─ {link.get('b_port') or '?'}",
                                   fill=C["muted"], font=("Segoe UI", 7))
        for node in nodes:
            x, y = pos[node["id"]]
            color = C["green"] if node.get("root") else C["panel"]
            canvas.create_oval(x-22, y-16, x+22, y+16, fill=color, outline=C["line"])
            canvas.create_text(x, y, text=node.get("label", node["id"]), fill=C["text"],
                               font=("Segoe UI Semibold", 8))

    # ================================================================== Cable Diagnostics
    def render_cable(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Cable Diagnostics",
            "Bakır kablo testi (Live Tools). Kullanıcı açıkça başlatmalı; test bağlantıyı etkileyebilir."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="PORTLAR (virgülle, ör. 1,2,3)", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.cable_ports_entry = self.app._entry(row, "1,2,3,4", 24)
        self.cable_ports_entry.pack(anchor="w", ipady=6, pady=(3, 10))
        tk.Label(panel, text=(
            "UYARI: Kablo testi seçili portlarda kısa süreli kesintiye yol açabilir. "
            "Yalnızca yetkili erişiminiz olan switch'lerde ve kullanıcı onayıyla çalıştırın."
        ), bg=C["panel"], fg=C["amber"], font=("Segoe UI", 8),
           wraplength=980, justify="left").pack(anchor="w", pady=(0, 8))
        self.app._button(panel, "Kablo testini başlat", self._cable_start, secondary=True).pack(anchor="w")
        self.cable_text = tk.Text(panel, height=12, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.cable_text.pack(fill="both", expand=True, pady=(10, 0))

    def _cable_start(self):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("Cable Diagnostics", str(exc))
            return
        raw = self.cable_ports_entry.get().strip()
        try:
            ports = [int(p) for p in raw.replace(" ", "").split(",") if p]
        except ValueError:
            self._error("Cable Diagnostics", "Port listesi sayısal olmalı (ör. 1,2,3).")
            return
        if not ports:
            self._error("Cable Diagnostics", "En az bir port girin.")
            return
        from tkinter import messagebox
        if not messagebox.askyesno("Kablo testi", f"{ports} portlarında kablo testi başlatılsın mı? Bağlantı etkilenebilir."):
            return
        serial = self.state["serial"]
        def done(status):
            self._set_text(self.cable_text, self._format_cable(status))
        def task():
            client = self._require_client()
            job = client.cable_test_create(serial, ports)
            return client.wait_live_tool(serial, "cable", job, timeout=90, interval=3)
        self._run_task("Kablo testi", task, done)

    def _format_cable(self, status):
        lines = []
        for result in status.get("results", [status]):
            lines.append(
                f"port {result.get('port','?')}: length={result.get('cableLength', UNKNOWN)} "
                f"pairs={result.get('pairsStatus', UNKNOWN)} speed={result.get('speed', UNKNOWN)} "
                f"status={result.get('status', UNKNOWN)} error={result.get('error', '')}"
            )
        return "\\n".join(lines) or "Test sonucu boş."

    # ================================================================== Switch Diagnostics
    def render_switch_diag(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Switch Diagnostics",
            "Canlı testler: Ping, Trace Route, Throughput. Yalnızca kullanıcı başlatır; konfigürasyon değiştirmez."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="HEDEF (IP / hostname)", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.diag_target = self.app._entry(row, "8.8.8.8", 26)
        self.diag_target.pack(anchor="w", ipady=6, pady=(3, 10))
        btns = tk.Frame(row, bg=C["panel"])
        btns.pack(anchor="w")
        self.app._button(btns, "Ping", lambda: self._diag("ping")).pack(side="left")
        self.app._button(btns, "Trace Route", lambda: self._diag("trace"), secondary=True).pack(side="left", padx=6)
        self.app._button(btns, "Throughput", lambda: self._diag("throughput"), secondary=True).pack(side="left")
        self.diag_text = tk.Text(panel, height=16, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.diag_text.pack(fill="both", expand=True, pady=(10, 0))
        tk.Label(panel, text=(
            "Throughput testi switch ile Meraki Cloud arasındaki yaklaşık performansı ölçer. "
            "Bu testler telemetry/write izni gerektirir; konfigürasyon değiştirmez."
        ), bg=C["panel"], fg=C["muted"], font=("Segoe UI", 8), wraplength=980, justify="left"
        ).pack(anchor="w", pady=(8, 0))

    def _diag(self, kind):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("Switch Diagnostics", str(exc))
            return
        serial = self.state["serial"]
        target = self.diag_target.get().strip()
        if kind in ("ping", "trace") and not target:
            self._error("Switch Diagnostics", "Hedef IP/hostname girin.")
            return
        from tkinter import messagebox
        if not messagebox.askyesno("Switch testi", f"{kind.upper()} testi başlatılsın mı?"):
            return
        def done(status):
            self._set_text(self.diag_text, self._format_diag(status, kind))
        def task():
            client = self._require_client()
            if kind == "ping":
                job = client.ping_create(serial, target)
            elif kind == "trace":
                job = client.trace_route_create(serial, target)
            else:
                job = client.throughput_create(serial)
            return client.wait_live_tool(serial, kind, job, timeout=90, interval=3)
        self._run_task(f"diag-{kind}", task, done)

    def _format_diag(self, status, kind):
        if kind == "ping":
            results = status.get("results", [])
            return "\\n".join(f"  {r}" for r in results) or json.dumps(status, ensure_ascii=False)[:600]
        if kind == "trace":
            hops = status.get("results", [])
            return "\\n".join(f"  hop {i+1}: {h}" for i, h in enumerate(hops)) or json.dumps(status, ensure_ascii=False)[:600]
        return json.dumps(status, ensure_ascii=False, indent=2)[:1200]

    # ================================================================== Events & History
    def render_events(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Events & History",
            "Ağ olayları ve cihaz availability değişim geçmişi. Olay yoksa boş liste gösterilir."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="FİLTRE (isteğe bağlı: clientMac / clientIp / productType)",
                 bg=C["panel"], fg=C["muted"], font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.events_filter = self.app._entry(row, "", 40)
        self.events_filter.pack(anchor="w", ipady=6, pady=(3, 10))
        self.app._button(panel, "Olayları yenile", self._events_refresh, secondary=True).pack(anchor="w")
        self.events_tree = self.app._create_table(panel, compact=True)

    def _events_refresh(self):
        try:
            client = self._require_network()
        except RuntimeError as exc:
            self._error("Events & History", str(exc))
            return
        net = self.state["network_id"]
        raw = self.events_filter.get().strip()
        filt = {}
        if raw:
            if ":" in raw and normalize_mac(raw):
                filt["clientMac"] = normalize_mac(raw)
            elif raw.replace(".", "").isdigit():
                filt["clientIp"] = raw
            else:
                filt["productType"] = raw
        def done(data):
            events = data.get("events", [])
            self._render_events(events)
        def task():
            client = self._require_network()
            events = client.network_events(net, filt)
            combined = [dict(e, source="network_events") for e in events]
            org_id = self.state.get("organization_id")
            if org_id:
                try:
                    history = client.availability_change_history(org_id)
                    for h in history:
                        combined.append(dict(h, source="availability_history"))
                except MerakiAPIError:
                    pass
            return {"events": combined}
        self._run_task("Olaylar", task, done)

    def _render_events(self, events):
        tree = self.events_tree
        for iid in tree.get_children():
            tree.delete(iid)
        for e in events:
            tree.insert("", "end", values=(
                e.get("ts", UNKNOWN), e.get("eventType") or e.get("eventType", UNKNOWN),
                e.get("source", UNKNOWN), e.get("deviceSerial") or e.get("clientMac") or UNKNOWN,
                str(e.get("description", UNKNOWN))[:80],
            ))

    # ================================================================== Local Status Page
    def render_local_status(self):
        C = self._C()
        self.app._section(
            self.app.content, "Local Status Page",
            "Dashboard API olmadan yerel Meraki kurulum sayfası. DNS, TCP bağlantısı ve HTTP yanıtı kontrol edilir."
        )
        panel = self.app._panel(self.app.content)
        pages = [
            ("switch.meraki.com", "http://switch.meraki.com"),
            ("setup.meraki.com", "http://setup.meraki.com"),
            ("my.meraki.com", "http://my.meraki.com"),
        ]
        for name, url in pages:
            row = tk.Frame(panel, bg=C["panel"])
            row.pack(fill="x", pady=4)
            tk.Label(row, text=url, bg=C["panel"], fg=C["cyan"],
                     font=("Consolas", 9), width=30, anchor="w").pack(side="left")
            self.app._button(row, "DNS/TCP", lambda u=url: self._local_check_one(u), secondary=True, small=True).pack(side="left", padx=4)
            self.app._button(row, "Aç", lambda u=url: self._open_local(u), secondary=True, small=True).pack(side="left", padx=4)
        self.local_status_text = tk.Text(panel, height=12, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.local_status_text.pack(fill="both", expand=True, pady=(10, 0))
        self._set_text(self.local_status_text,
            "Bir sayfa seçip DNS/TCP denetleyin.\n"
            "Giriş bilgisi gerekiyorsa kullanıcı tarafından girilir; otomatik deneme yapılmaz.\n"
            "Local Status Page: Connection, Uplink, Switch port status/configuration bilgisi içerebilir.\n"
            "Packet capture özelliği Cloud'a özel filtreler ve firmware sınırı taşır - genel amaçlı değildir.")
        self.app._button(panel, "Tümünü denetle", self._local_check_all, secondary=True).pack(anchor="w", pady=(8, 0))

    def _open_local(self, url):
        self._set_text(self.local_status_text, f"{url} varsayılan tarayıcıda açılıyor…")
        try:
            webbrowser.open(url)
        except Exception as exc:  # noqa: BLE001
            self._set_text(self.local_status_text, f"Açılamadı: {exc}")

    def _local_check_all(self):
        results = []
        for _, url in [("switch.meraki.com", "http://switch.meraki.com"),
                       ("setup.meraki.com", "http://setup.meraki.com"),
                       ("my.meraki.com", "http://my.meraki.com")]:
            results.append(self._format_local_result(probe_local_status_page(url)))
        self._set_text(self.local_status_text, "\\n".join(results))

    def _local_check_one(self, url):
        self._set_text(self.local_status_text, self._format_local_result(probe_local_status_page(url)))

    @staticmethod
    def _format_local_result(result):
        lines = [f"{result['url']}:", f"  DNS: {', '.join(result['addresses']) or 'çözümlenemedi'}",
                 f"  Bağlantı: {'var' if result['reachable'] else 'yok'}",
                 f"  HTTP: {result['http_status'] or '—'}"]
        if result.get("error"):
            lines.append(f"  Hata: {result['error']}")
        return "\\n".join(lines)

    # ================================================================== SNMP Monitor
    def render_snmp(self):
        C = self._C()
        self.app._section(
            self.app.content, "SNMP Monitor",
            "Yerel SNMP (v1/v2c ve opsiyonel v3). Yalnızca GET/GETNEXT; SET/yapılandırma değişikliği yok."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        fields = tk.Frame(row, bg=C["panel"])
        fields.pack(side="left")
        tk.Label(fields, text="SNMP HEDEF IP", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.snmp_host = self.app._entry(fields, "", 20)
        self.snmp_host.pack(anchor="w", ipady=6, pady=(3, 4))
        tk.Label(fields, text="SÜRÜM", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.snmp_version = ttk.Combobox(fields, values=("1", "2c", "3"), state="readonly", width=6)
        self.snmp_version.set("2c")
        self.snmp_version.pack(anchor="w", pady=(3, 4))
        tk.Label(fields, text="COMMUNITY / v3 KULLANICI", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.snmp_cred = self.app._entry(fields, "public", 20)
        self.snmp_cred.pack(anchor="w", ipady=6, pady=(3, 4))
        tk.Label(fields, text="v3 AUTH / PRIV ANAHTARI", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.snmp_authkey = self.app._entry(fields, "", 20)
        self.snmp_authkey.pack(anchor="w", ipady=6, pady=(3, 4))
        self.app._button(row, "SNMP sorgula", self._snmp_query, secondary=True).pack(side="left", padx=14)
        self.snmp_text = tk.Text(panel, height=16, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.snmp_text.pack(fill="both", expand=True, pady=(10, 0))
        self._set_text(self.snmp_text,
            "SNMP yapılandırması Meraki Dashboard üzerinde önceden yapılmış olmalıdır.\n"
            "Standart MIB: SNMPv2-MIB, IF-MIB. Desteklenmeyen OID için timeout/Bilinmiyor.\n"
            "Meraki proprietary Cloud Controller MIB'i yerel switch MIB'i gibi kullanılmaz.\n"
            "SET / konfigürasyon değiştirme yoktur - yalnızca GET / GETNEXT.\n"
            "SNMPv3 için 'pysnmp' paketi gereklidir.")

    def _snmp_query(self):
        host = self.snmp_host.get().strip()
        if not host:
            self._error("SNMP Monitor", "SNMP hedef IP girin.")
            return
        version = self.snmp_version.get()
        cred = self.snmp_cred.get().strip()
        try:
            from ..network.snmp import SnmpClient, query_v3, snmp_v3_available
        except Exception as exc:  # noqa: BLE001
            self._set_text(self.snmp_text, f"SNMP modülü kullanılamıyor: {exc}")
            return
        def done(info):
            lines = [f"sysDescr  : {info.get('sysDescr', UNKNOWN)}",
                     f"sysName   : {info.get('sysName', UNKNOWN)}",
                     f"sysUpTime : {info.get('sysUpTime', UNKNOWN)}", "", "— IF-MIB arayüzleri —"]
            for iface in info.get("interfaces", []):
                lines.append(
                    f"  {iface.get('ifName','?')} status={iface.get('ifOperStatus','?')} "
                    f"speed={iface.get('ifSpeed','?')} in={iface.get('ifInOctets','?')} out={iface.get('ifOutOctets','?')}")
            self._set_text(self.snmp_text, "\\n".join(lines))
        def task():
            if version == "3":
                if not snmp_v3_available():
                    raise RuntimeError("SNMPv3 için 'pysnmp' paketi gereklidir.")
                auth_key = self.snmp_authkey.get().strip()
                priv_key = self.snmp_authkey.get().strip()
                return query_v3(host, cred or "admin", auth_key, priv_key)
            return SnmpClient(host, credential=cred or "public", version=2 if version == "2c" else 1).system_info()
        self._run_task("SNMP sorgu", task, done)

    # ------------------------------------------------------------------ util
    # ------------------------------------------------------------------ util
    @staticmethod
    def _set_text(widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")


def C_amber(app):
    return app.C["amber"]
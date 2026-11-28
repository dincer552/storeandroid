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
from ..network.mac import normalize_mac
from ..network.meraki import MerakiClient

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
        self.state = {
            "org": None,
            "serial": None,
            "network_id": None,
        }

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
        key = ""
        entry = getattr(self.app, "meraki_key_entry", None)
        if entry is not None and entry.winfo_exists():
            key = entry.get().strip()
        if not key:
            raise RuntimeError("Meraki Dashboard API anahtarı girilmedi. 'Meraki Inspector' ekranından anahtar girin.")
        if self.client is None or self.client.api_key != key:
            self.client = MerakiClient(key)
        return self.client

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
        self.app.meraki_key_entry = self.app._entry(left, "", 52)
        self.app.meraki_key_entry.config(show="•")
        self.app.meraki_key_entry.pack(anchor="w", ipady=6, pady=(3, 0))

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
            "MAC / Seri / IP / Model ile Cisco Meraki switch keşfi. "
            "Öncelik: SQLite envanter → yerel ARP → Meraki Dashboard API."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")

        fields = tk.Frame(row, bg=C["panel"])
        fields.pack(side="left")
        tk.Label(fields, text="KEŞİF ANAHTARI (MAC / SERİ / IP / MODEL)",
                 bg=C["panel"], fg=C["muted"], font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.inspector_input = self.app._entry(fields, Config.get_test_mac(), 34)
        self.inspector_input.pack(anchor="w", ipady=7, pady=(4, 12))
        tk.Label(fields, text="Örnek: B8:AB:61:AB:DA:6E  ·  Q4DE-57E5-WTP9  ·  MS120-24P",
                 bg=C["panel"], fg=C["muted"], font=("Segoe UI", 8)).pack(anchor="w")

        actions = tk.Frame(row, bg=C["panel"])
        actions.pack(side="left", padx=16)
        self.app._button(actions, "Keşfet", self._inspector_discover).pack(anchor="w", pady=2)
        self.app._button(actions, "Test değerini doldur",
                         lambda: self.app._replace_entry(self.inspector_input, Config.get_test_mac()),
                         secondary=True).pack(anchor="w", pady=2)

        self.inspector_status = tk.Label(panel, text="Hazır - keşif anahtarı girin",
                                         bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9), anchor="w")
        self.inspector_status.pack(fill="x", pady=(12, 6))

        self.inspector_tree = self.app._create_table(panel, compact=False)
        self.inspector_tree.bind("<<TreeviewSelect>>", self._inspector_selected)

        tk.Label(panel, text=(
            "Güvenlik: salt-okunur. API anahtarı diske yazılmaz, EXE'ye gömülmez. "
            "Donanım bilgisi yalnızca model doğrulandığında gösterilir."
        ), bg=C["panel"], fg=C["muted"], font=("Segoe UI", 8), wraplength=980, justify="left"
        ).pack(anchor="w", pady=(8, 0))

    def _inspector_discover(self):
        key = self.inspector_input.get().strip()
        if not key:
            self._error("Meraki Inspector", "Keşif anahtarı (MAC/seri/IP/model) girin.")
            return
        try:
            client = self._client()
        except RuntimeError as exc:
            self._error("Meraki Inspector", str(exc))
            return
        self.inspector_status.config(text="Keşif yapılıyor…", fg=C_amber(self))
        def done(devices):
            self.inspector_status.config(text=f"{len(devices)} switch bulundu", fg=self._C()["green"])
            self._populate_inspector(devices)
        self._run_task("Meraki keşif", lambda: client.find_switch_by_identifier(key), done)

    def _populate_inspector(self, devices):
        tree = self.inspector_tree
        for iid in tree.get_children():
            tree.delete(iid)
        cols = tree["columns"]
        for dev in devices:
            vals = []
            for col in cols:
                vals.append(self._fmt(dev.get(col)))
            tree.insert("", "end", values=tuple(vals))

    def _inspector_selected(self, _event=None):
        sel = self.inspector_tree.selection()
        if not sel:
            return
        # Store the selected switch as active context
        values = self.inspector_tree.item(sel[0], "values")
        # columns: model, serial, mac, name, network_id, lan_ip, ...
        try:
            self.state["serial"] = values[1]
            self.state["network_id"] = values[4]
        except IndexError:
            pass
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
            "MAC → IP → Switch → Port → VLAN. Kaynak: network clients, device clients, MAC forwarding tablosu."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="HEDEF İSTEMCİ MAC", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.m_locator_entry = self.app._entry(row, Config.get_test_mac(), 30)
        self.m_locator_entry.pack(anchor="w", ipady=7, pady=(4, 12))
        actions = tk.Frame(row, bg=C["panel"])
        actions.pack(anchor="w")
        self.app._button(actions, "⌖  Switch portunda bul", self._mac_locator_lookup).pack(side="left")
        self.app._button(actions, "Test MAC'i doldur",
                         lambda: self.app._replace_entry(self.m_locator_entry, Config.get_test_mac()),
                         secondary=True).pack(side="left", padx=8)

        self.locator_status = tk.Label(panel, text="Hazır - hedef MAC girin",
                                       bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9), anchor="w")
        self.locator_status.pack(fill="x", pady=(10, 6))

        self.locator_tree = self.app._create_table(panel, compact=True)
        tk.Label(panel, text=(
            "ÖNEMLİ: switch port statuses yanıtındaki clientMac alanı var sayılmaz. "
            "Eşleşme network clients + MAC forwarding tablosu üzerinden yapılır. "
            "Farklı kaynaklar farklı sonuç verirse hepsi ve zamanı gösterilir."
        ), bg=C["panel"], fg=C["amber"], font=("Segoe UI", 8), wraplength=980, justify="left"
        ).pack(anchor="w", pady=(8, 0))

    def _mac_locator_lookup(self):
        mac = normalize_mac(self.m_locator_entry.get())
        if not mac:
            self._error("MAC Locator", "Geçerli bir MAC adresi girin.")
            return
        try:
            client = self._client()
        except RuntimeError as exc:
            self._error("MAC Locator", str(exc))
            return
        self.locator_status.config(text="Switch portu aranıyor (network clients + macTable)…", fg=C_amber(self))
        def done(result):
            self._render_locator_result(result)
        self._run_task("MAC locator", lambda: client.find_client_port_by_mac(mac), done)

    def _render_locator_result(self, result):
        tree = self.locator_tree
        for iid in tree.get_children():
            tree.delete(iid)
        sources = result.get("sources", [])
        if not sources:
            self.locator_status.config(
                text=f"Kaynaklarda eşleşme yok · {result.get('target_mac')}", fg=self._C()["amber"])
            return
        for src in sources:
            ts = src.get("last_seen") or src.get("first_seen") or ""
            row = (
                src.get("source", UNKNOWN),
                src.get("switchport") or src.get("port") or UNKNOWN,
                src.get("vlan") or src.get("vlan_id") or UNKNOWN,
                src.get("ip", UNKNOWN),
                src.get("mac", UNKNOWN),
                ts,
            )
            tree.insert("", "end", values=row)
        self.locator_status.config(
            text=f"{len(sources)} kaynak(lar) eşleşti · port={self._fmt(result['best_match'].get('switchport'))}",
            fg=self._C()["green"])

    # ================================================================== Port Inspector
    def render_port_inspector(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Port Inspector",
            "MS120-24P: 24 x RJ45 + 4 x SFP. Yalnızca API'den doğrulanmış port durumuna göre renklendirilir."
        )
        panel = self.app._panel(self.app.content)
        self.port_canvas_frame = tk.Frame(panel, bg=C["bg"])
        self.port_canvas_frame.pack(fill="both", expand=True)
        tk.Label(panel, text=(
            "Renkler: Yeşil=Connected · Gri=Disconnected · Kırmızı=Gerçek hata · "
            "Turuncu=Warning · Mavi=Uplink. Port detayı için bir porta tıklayın."
        ), bg=C["panel"], fg=C["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(8, 0))
        self.app._button(panel, "Portları yenile", self._ports_refresh, secondary=True).pack(anchor="w", pady=(8, 0))

    def _ports_refresh(self):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("Port Inspector", str(exc))
            return
        serial = self.state["serial"]
        def done(data):
            statuses = data.get("statuses", [])
            configs = data.get("configs", [])
            self._draw_port_panel(configs, statuses)
        def task():
            client = self._require_client()
            return {
                "statuses": client.switch_ports_statuses(self.state["serial"]),
                "configs": client.switch_ports(self.state["serial"]),
            }
        self._run_task("Port inspector", task, done)

    def _draw_port_panel(self, configs, statuses):
        C = self._C()
        frame = self.port_canvas_frame
        for child in frame.winfo_children():
            child.destroy()

        status_by_port = {str(s.get("portId")): s for s in statuses if s.get("portId") is not None}
        config_by_port = {str(c.get("portId")): c for c in configs if c.get("portId") is not None}

        # Determine physical layout from MS120-24P spec: 24 RJ45 then 4 SFP.
        all_ports = [str(i) for i in range(1, 25)] + ["25", "26", "27", "28"]

        grid = tk.Frame(frame, bg=C["bg"])
        grid.pack(fill="both", expand=True, padx=6, pady=6)

        def port_color(status, config):
            if config and not config.get("enabled", True):
                return C["red"]  # disabled shown as red-ish only if explicitly disabled
            if status is None:
                return C["muted"]  # unknown / no data
            link = str(status.get("link", "")).lower()
            if status.get("isUplink"):
                return C["cyan"]  # blue-ish uplink
            if link == "up" or str(status.get("status", "")).lower() in ("connected", "up"):
                return C["green"]
            if status.get("warnings"):
                return C["amber"]
            if status.get("errors"):
                return C["red"]
            return "#3a4256"  # disconnected grey

        for idx, port_id in enumerate(all_ports):
            r, c = divmod(idx, 7)
            cell = tk.Frame(grid, bg=C["panel2"],
                            highlightbackground=port_color(status_by_port.get(port_id), config_by_port.get(port_id)),
                            highlightthickness=3)
            cell.grid(row=r, column=c, padx=5, pady=5, sticky="nsew")
            status = status_by_port.get(port_id)
            config = config_by_port.get(port_id)
            kind = "SFP" if port_id in ("25", "26", "27", "28") else "RJ45"
            label = f"{kind} {port_id}"
            tk.Label(cell, text=label, bg=C["panel2"], fg=C["text"],
                     font=("Segoe UI Semibold", 9)).pack(pady=(6, 0))
            state_text = self._port_state_text(status, config)
            tk.Label(cell, text=state_text, bg=C["panel2"], fg=C["muted"],
                     font=("Segoe UI", 7)).pack(pady=(0, 6))
            cell.bind("<Button-1>", lambda e, p=port_id: self._port_detail_dialog(p, status, config))
            for w in cell.winfo_children():
                w.bind("<Button-1>", lambda e, p=port_id: self._port_detail_dialog(p, status, config))
        for i in range(7):
            grid.grid_columnconfigure(i, weight=1)

    @staticmethod
    def _port_state_text(status, config):
        if status is None and config is None:
            return "—"
        if status is None:
            return "No status"
        link = str(status.get("link", "")).lower()
        if link == "up":
            return "Connected"
        return "Down"

    def _port_detail_dialog(self, port_id, status, config):
        C = self._C()
        dlg = tk.Toplevel(self.app.root)
        dlg.title(f"Port {port_id} detayı")
        dlg.configure(bg=C["bg"])
        dlg.geometry("560x620")
        dlg.transient(self.app.root)
        outer = tk.Frame(dlg, bg=C["bg"], padx=18, pady=16)
        outer.pack(fill="both", expand=True)
        tk.Label(outer, text=f"Port {port_id}", bg=C["bg"], fg=C["text"],
                 font=("Segoe UI Semibold", 15)).pack(anchor="w")
        fields = []
        if status:
            for k in ("portId", "status", "link", "speed", "duplex", "isUplink",
                      "poeEnabled", "powerUsageInWh", "vlan", "nativeVlan",
                      "clientCount", "warnings", "errors"):
                if k in status:
                    fields.append((k, status.get(k)))
        if config:
            for k in ("enabled", "type", "vlan", "voiceVlan", "allowedVlans",
                      "accessPolicy", "description", "poeEnabled"):
                if k in config:
                    fields.append((f"cfg.{k}", config.get(k)))
        if not fields:
            fields.append(("veri", "API bu port için veri döndürmedi"))
        info = tk.Frame(outer, bg=C["panel"], padx=14, pady=12)
        info.pack(fill="both", expand=True)
        for label, value in fields:
            line = tk.Frame(info, bg=C["panel"])
            line.pack(fill="x", pady=2)
            tk.Label(line, text=label, bg=C["panel"], fg=C["muted"],
                     width=20, anchor="w", font=("Segoe UI", 8)).pack(side="left")
            tk.Label(line, text=self._fmt(value), bg=C["panel"], fg=C["text"],
                     anchor="w", font=("Segoe UI", 8), wraplength=380, justify="left").pack(side="left")

    # ================================================================== PoE Analyzer
    def render_poe(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "PoE Analyzer",
            "MS120-24P üretici PoE bütçesi (370 W) ile gerçek anlık tüketim ayrı gösterilir."
        )
        # Summary cards
        cards = tk.Frame(self.app.content, bg=C["bg"])
        cards.pack(fill="x", pady=(0, 12))
        self.poe_budget_card = self._poe_card(cards, "ÜRETİCİ BÜTÇESİ", "370 W", "MS120-24P spec")
        self.poe_usage_card = self._poe_card(cards, "ANLIK TÜKETİM", UNKNOWN, "ölçülen")
        self.poe_remaining_card = self._poe_card(cards, "KALAN BÜTÇE", UNKNOWN, "ölçülebilir ise")
        panel = self.app._panel(self.app.content)
        cols = ("port", "enabled", "allocated", "usage", "client")
        self.poe_tree = ttk.Treeview(panel, columns=cols, show="headings")
        for col, heading in zip(cols, ("PORT", "POE ENABLED", "ALLOCATED", "USAGE", "CLIENT")):
            self.poe_tree.heading(col, text=heading)
            self.poe_tree.column(col, width=140, anchor="w", stretch=False)
        self.poe_tree.pack(fill="both", expand=True)
        self.app._button(panel, "PoE durumunu yenile", self._poe_refresh, secondary=True).pack(anchor="w", pady=(8, 0))
        tk.Label(panel, text=(
            "powerUsageInWh bir enerji (Wh) değeridir, anlık Watt değildir. "
            "Anlık güç için Live Tools power/usage kullanılır; yoksa 'Bilinmiyor' gösterilir."
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
        def done(data):
            statuses = data.get("statuses", [])
            power = data.get("power")
            self._render_poe(statuses, power)
        def task():
            client = self._require_client()
            result = {"statuses": client.switch_ports_statuses(self.state["serial"]), "power": None}
            try:
                job = client.power_usage_create(self.state["serial"])
                jid = job.get("id") or job.get("jobId") or job.get("powerUsageId")
                if jid:
                    for _ in range(15):
                        time.sleep(1)
                        status = client.power_usage_get(self.state["serial"], jid)
                        st = str(status.get("status", "")).lower()
                        if st in ("complete", "completed", "success"):
                            result["power"] = status
                            break
                        if st == "failed":
                            break
            except RuntimeError:
                result["power"] = None
            return result
        self._run_task("PoE analizi", task, done)

    def _render_poe(self, statuses, power):
        C = self._C()
        for iid in self.poe_tree.get_children():
            self.poe_tree.delete(iid)
        allocated_total = 0.0
        for s in statuses:
            port = s.get("portId", UNKNOWN)
            enabled = s.get("poeEnabled", UNKNOWN)
            allocated = s.get("powerAllocatedInWatts")
            usage = s.get("powerUsageInWh")
            client = "Evet" if str(s.get("link", "")).lower() == "up" else "Hayır"
            if isinstance(allocated, (int, float)):
                allocated_total += allocated
            self.poe_tree.insert("", "end", values=(
                port, self._fmt(enabled), self._fmt(allocated), self._fmt(usage), client))

        budget = MS120_24P_SPEC["poe_budget_w"]
        instant = None
        peak = None
        if power:
            instant = power.get("instant") or power.get("instantWatts")
            peak = power.get("peak") or power.get("peakWatts")
        if isinstance(instant, (int, float)):
            self.poe_usage_card.config(text=f"{instant:.1f} W")
            remaining = budget - instant
            self.poe_remaining_card.config(text=f"{remaining:.1f} W" if remaining >= 0 else "Aşıldı")
        else:
            self.poe_usage_card.config(text=UNKNOWN)
            self.poe_remaining_card.config(text=UNKNOWN)

    # ================================================================== Traffic Monitor
    def render_traffic(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Traffic Monitor",
            "Port paket sayaçları. API periyodik veri toplar; son 5 dk eksik olabilir."
        )
        panel = self.app._panel(self.app.content)
        cols = ("port", "total", "sent", "received", "pps", "freshness")
        self.traffic_tree = ttk.Treeview(panel, columns=cols, show="headings")
        for col, heading in zip(cols, ("PORT", "TOTAL PKT", "SENT", "RECEIVED", "PKT/S", "VERİ TAZELİĞİ")):
            self.traffic_tree.heading(col, text=heading)
            self.traffic_tree.column(col, width=150, anchor="w", stretch=False)
        self.traffic_tree.pack(fill="both", expand=True)
        self.app._button(panel, "Trafiği yenile", self._traffic_refresh, secondary=True).pack(anchor="w", pady=(8, 0))

    def _traffic_refresh(self):
        try:
            client = self._require_client()
        except RuntimeError as exc:
            self._error("Traffic Monitor", str(exc))
            return
        serial = self.state["serial"]
        def done(packets):
            self._render_traffic(packets)
        self._run_task("Traffic monitor", lambda: client.switch_ports_packets(serial), done)

    def _render_traffic(self, packets):
        for iid in self.traffic_tree.get_children():
            self.traffic_tree.delete(iid)
        now = time.time()
        for p in packets:
            port = p.get("portId", UNKNOWN)
            total = p.get("totalPackets", UNKNOWN)
            sent = p.get("sentPackets", UNKNOWN)
            recv = p.get("recvPackets", p.get("receivedPackets", UNKNOWN))
            pps = p.get("packetsPerSecond", UNKNOWN)
            ts = p.get("ts") or p.get("timestamp")
            freshness = UNKNOWN
            if isinstance(ts, (int, float)):
                age = now - ts
                freshness = "Taze" if age < 300 else "Eski"
            self.traffic_tree.insert("", "end", values=(
                port, self._fmt(total), self._fmt(sent), self._fmt(recv), self._fmt(pps), freshness))

    # ================================================================== Topology
    def render_topology(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Network Topology",
            "Gerçek LLDP/CDP keşfi. Subnet ilişkisine göre bağlantı çizilmez."
        )
        panel = self.app._panel(self.app.content)
        self.topology_text = tk.Text(panel, height=24, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.topology_text.pack(fill="both", expand=True)
        self.app._button(panel, "Topolojiyi yenile", self._topology_refresh, secondary=True).pack(anchor="w", pady=(8, 0))

    def _topology_refresh(self):
        try:
            client = self._require_network()
        except RuntimeError as exc:
            self._error("Network Topology", str(exc))
            return
        serial = self.state["serial"]
        net = self.state["network_id"]
        def done(data):
            link_layer = data.get("link_layer", {})
            lldp = data.get("lldp", [])
            lines = ["— LINK LAYER TOPOLOGY —"]
            links = link_layer.get("links", []) if isinstance(link_layer, dict) else []
            if not links:
                lines.append("Keşfedilmiş fiziksel bağlantı yok (API boş döndü).")
            for link in links:
                lines.append(
                    f"  {link.get('sourceDevice','?')} :{link.get('sourcePort','?')}  →  "
                    f"{link.get('targetDevice','?')} :{link.get('targetPort','?')}")
            lines += ["", "— LLDP / CDP —"]
            if not lldp:
                lines.append("LLDP/CDP kaydı yok.")
            for entry in lldp:
                lines.append(
                    f"  port {entry.get('portId','?')}: "
                    f"systemName={entry.get('systemName', UNKNOWN)} "
                    f"mgmtIP={entry.get('managementIp', UNKNOWN)} "
                    f"platform={entry.get('platform', UNKNOWN)}")
            self._set_text(self.topology_text, "\n".join(lines))
        def task():
            client = self._require_network()
            return {
                "link_layer": client.topology_link_layer(self.state["network_id"]),
                "lldp": client.lldp_cdp(self.state["serial"]),
            }
        self._run_task("Topoloji", task, done)

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
        warn = ("UYARI: Kablo testi seçili portlarda kısa süreli kesintiye yol açabilir. "
                "Yalnızca yetkili erişiminiz olan switch'lerde ve kullanıcı onayıyla çalıştırın.")
        tk.Label(panel, text=warn, bg=C["panel"], fg=C["amber"], font=("Segoe UI", 8),
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
        serial = self.state["serial"]
        from tkinter import messagebox
        if not messagebox.askyesno("Kablo testi", "Seçili portlarda kablo testi başlatılsın mı? Bağlantı etkilenebilir."):
            return
        def done(job):
            self._cable_poll(serial, job)
        self._run_task("Kablo testi", lambda: client.cable_test_create(serial, ports), done)

    def _cable_poll(self, serial, job):
        client = self._require_client()
        jid = job.get("id") or job.get("cableTestId")
        if not jid:
            self._set_text(self.cable_text, "Test başlatılamadı (job ID yok).")
            return
        def tick():
            try:
                status = client.cable_test_get(serial, jid)
            except RuntimeError as exc:
                self._set_text(self.cable_text, f"Hata: {exc}")
                return
            st = str(status.get("status", "")).lower()
            if st in ("complete", "completed", "success"):
                self._set_text(self.cable_text, self._format_cable(status))
                return
            if st == "failed":
                self._set_text(self.cable_text, f"Test başarısız: {status.get('error', '')}")
                return
            self.app.root.after(1500, tick)
        self.app.root.after(1500, tick)

    def _format_cable(self, status):
        lines = []
        for result in status.get("results", [status]):
            lines.append(
                f"port {result.get('port','?')}: length={result.get('cableLength', UNKNOWN)} "
                f"pairs={result.get('pairsStatus', UNKNOWN)} speed={result.get('speed', UNKNOWN)} "
                f"status={result.get('status', UNKNOWN)}")
        return "\n".join(lines) or "Test sonucu boş."

    # ================================================================== Switch Diagnostics
    def render_switch_diag(self):
        C = self._C()
        self._api_key_bar()
        self.app._section(
            self.app.content, "Switch Diagnostics",
            "Canlı testler: Ping, Trace Route, Throughput. Yalnızca kullanıcı başlatır."
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

        def start_and_poll():
            if kind == "ping":
                job = client.ping_create(serial, target)
                jid = job.get("id") or job.get("pingId")
                getter = client.ping_get
            elif kind == "trace":
                job = client.trace_route_create(serial, target)
                jid = job.get("id") or job.get("traceRouteId")
                getter = client.trace_route_get
            else:
                job = client.throughput_create(serial)
                jid = job.get("id") or job.get("throughputTestId")
                getter = client.throughput_get
            return jid, getter

        def done(job_tuple):
            jid, getter = job_tuple
            if not jid:
                self._set_text(self.diag_text, "Test başlatılamadı.")
                return
            self._poll_diag(serial, getter, jid, kind)
        self._run_task(f"diag-{kind}", start_and_poll, done)

    def _poll_diag(self, serial, getter, jid, kind):
        client = self._require_client()
        def tick():
            try:
                status = getter(serial, jid)
            except RuntimeError as exc:
                self._set_text(self.diag_text, f"Hata: {exc}")
                return
            st = str(status.get("status", "")).lower()
            if st in ("complete", "completed", "success"):
                self._set_text(self.diag_text, self._format_diag(status, kind))
                return
            if st == "failed":
                self._set_text(self.diag_text, f"Test başarısız: {status.get('error', '')}")
                return
            self.app.root.after(1500, tick)
        self.app.root.after(1500, tick)

    def _format_diag(self, status, kind):
        if kind == "ping":
            results = status.get("results", [])
            return "\n".join(f"  {r}" for r in results) or json.dumps(status, ensure_ascii=False)[:600]
        if kind == "trace":
            hops = status.get("results", [])
            return "\n".join(f"  hop {i+1}: {h}" for i, h in enumerate(hops)) or json.dumps(status, ensure_ascii=False)[:600]
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
        org = self.state.get("organization_id") or (self.state.get("serial") and None)
        filt = {}
        raw = self.events_filter.get().strip()
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
            return {"events": client.events(self.state["network_id"], **filt)}
        self._run_task("Olaylar", task, done)

    def _render_events(self, events):
        tree = self.events_tree
        for iid in tree.get_children():
            tree.delete(iid)
        for e in events:
            tree.insert("", "end", values=(
                e.get("ts", UNKNOWN),
                e.get("eventType", UNKNOWN),
                e.get("deviceSerial") or e.get("clientMac") or UNKNOWN,
                e.get("description", UNKNOWN)[:60],
            ))

    # ================================================================== Local Status Page
    def render_local_status(self):
        C = self._C()
        self.app._section(
            self.app.content, "Local Status Page",
            "Dashboard API olmadan yerel Meraki kurulum sayfası. DNS + bağlantı kontrolü yapılır."
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
            self.app._button(row, "Aç", lambda u=url, n=name: self._open_local(u, n), secondary=True, small=True).pack(side="left", padx=6)
        self.local_status_text = tk.Text(panel, height=12, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.local_status_text.pack(fill="both", expand=True, pady=(10, 0))
        self._set_text(self.local_status_text,
            "DNS çözümleme ve yerel bağlantı kontrolü için bir sayfa seçin.\n"
            "Giriş bilgisi gerekiyorsa kullanıcı tarafından girilir; otomatik deneme yapılmaz.\n"
            "Local Status Page: Connection, Uplink, Switch port status/configuration bilgisi içerebilir.\n"
            "Packet capture özelliği Cloud'a özel filtreler ve firmware sınırı taşır - genel amaçlı değildir.")
        self._button(panel, "DNS / bağlantı kontrolü", self._local_check, secondary=True).pack(anchor="w", pady=(8, 0))

    def _open_local(self, url, name):
        self._set_text(self.local_status_text, f"{url} varsayılan tarayıcıda açılıyor…")
        try:
            webbrowser.open(url)
        except Exception as exc:  # noqa: BLE001
            self._set_text(self.local_status_text, f"Açılamadı: {exc}")

    def _local_check(self):
        results = []
        for name, url in [("switch.meraki.com", "http://switch.meraki.com"),
                          ("setup.meraki.com", "http://setup.meraki.com"),
                          ("my.meraki.com", "http://my.meraki.com")]:
            host = name
            try:
                ip = socket.gethostbyname(host)
                dns = f"OK ({ip})"
            except OSError:
                dns = "Çözümlenemedi"
            results.append(f"{host:22} DNS: {dns}")
        self._set_text(self.local_status_text, "\n".join(results))

    # ================================================================== SNMP Monitor
    def render_snmp(self):
        C = self._C()
        self.app._section(
            self.app.content, "SNMP Monitor",
            "Yerel SNMP (v1/v2c/v3). Öncelik SNMPv3 + SHA-2 + AES-128. Yalnızca GET/GETNEXT."
        )
        panel = self.app._panel(self.app.content)
        row = tk.Frame(panel, bg=C["panel"])
        row.pack(fill="x")
        fields = tk.Frame(row, bg=C["panel"])
        fields.pack(side="left")
        tk.Label(fields, text="SNMP HEDEF IP", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.snmp_host = self.app._entry(fields, "", 22)
        self.snmp_host.pack(anchor="w", ipady=6, pady=(3, 8))
        tk.Label(fields, text="COMMUNITY / v3 KULLANICI", bg=C["panel"], fg=C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.snmp_cred = self.app._entry(fields, "", 22)
        self.snmp_cred.config(show="•")
        self.snmp_cred.pack(anchor="w", ipady=6, pady=(3, 8))
        self.app._button(row, "SNMP sorgula", self._snmp_query, secondary=True).pack(side="left", padx=14)
        self.snmp_text = tk.Text(panel, height=16, bg="#0b172a", fg=C["text"],
            insertbackground=C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=C["line"], wrap="word")
        self.snmp_text.pack(fill="both", expand=True, pady=(10, 0))
        self._set_text(self.snmp_text,
            "SNMP yapılandırması Meraki Dashboard üzerinde önceden yapılmış olmalıdır.\n"
            "Standart MIB: SNMPv2-MIB, IF-MIB. Desteklenmeyen OID için timeout/Bilinmiyor.\n"
            "Meraki proprietary Cloud Controller MIB'i yerel switch MIB'i gibi kullanılmaz.\n"
            "SET / konfigürasyon değiştirme yoktur - yalnızca GET / GETNEXT.")

    def _snmp_query(self):
        host = self.snmp_host.get().strip()
        if not host:
            self._error("SNMP Monitor", "SNMP hedef IP girin.")
            return
        cred = self.snmp_cred.get().strip()
        try:
            from ..network.snmp import SnmpClient
        except Exception as exc:  # noqa: BLE001
            self._set_text(self.snmp_text, f"SNMP modülü kullanılamıyor: {exc}")
            return
        def done(info):
            lines = [f"sysDescr  : {info.get('sysDescr', UNKNOWN)}",
                     f"sysName   : {info.get('sysName', UNKNOWN)}",
                     f"sysUpTime : {info.get('sysUpTime', UNKNOWN)}",
                     "", "— IF-MIB arayüzleri —"]
            for iface in info.get("interfaces", []):
                lines.append(
                    f"  {iface.get('ifName','?' )} status={iface.get('ifOperStatus','?')} "
                    f"speed={iface.get('ifSpeed','?')} in={iface.get('ifInOctets','?')} out={iface.get('ifOutOctets','?')}")
            self._set_text(self.snmp_text, "\n".join(lines))
        def task():
            return SnmpClient(host, credential=cred).system_info()
        self._run_task("SNMP sorgu", task, done)

    # ------------------------------------------------------------------ util
    @staticmethod
    def _set_text(widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")


def C_amber(app):
    return app.C["amber"]
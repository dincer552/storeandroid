"""MAC Finder Pro: local network discovery and persistent device inventory."""
import csv
import json
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

from ..config import Config
from ..inventory import InventoryStore
from ..network.adapter import get_active_adapters, get_adapter_stats
from ..network.mac import normalize_mac
from ..network.meraki import MerakiClient
from ..network.scanner import ARPScanner


class MACFinderApp:
    C = {
        "bg": "#0a1020", "sidebar": "#0d172b", "panel": "#121f35",
        "panel2": "#182a46", "line": "#263a58", "text": "#eaf1ff",
        "muted": "#91a3c0", "accent": "#60a5fa", "cyan": "#43d9d0",
        "green": "#36d399", "amber": "#f5bd50", "red": "#fb7185",
        "purple": "#ad95ff",
    }
    NAV = [
        ("GENEL", [("Dashboard", "◈"), ("Cihaz Envanteri", "▤")]),
        ("KEŞİF", [("Tek MAC Ara", "⌗"), ("Tüm Ağı Tara", "⌕")]),
        ("SİSTEM", [("Adaptörler", "▦"), ("Meraki API", "◇"), ("Ayarlar", "⚙")]),
    ]
    COLUMNS = (
        "mac", "ip", "custom_name", "hostname", "vendor", "gateway",
        "interface", "method", "first_seen", "last_seen", "online"
    )
    HEADINGS = (
        "MAC ADRESİ", "IP ADRESİ", "ÖZEL İSİM", "HOSTNAME", "ÜRETİCİ",
        "GATEWAY", "INTERFACE", "YÖNTEM", "İLK GÖRÜLME", "SON GÖRÜLME", "DURUM"
    )

    def __init__(self, root):
        self.root = root
        self.root.title("MAC Finder Pro | Local Network Inventory")
        self.root.geometry("1400x840")
        self.root.minsize(1120, 700)
        self.root.configure(bg=self.C["bg"])
        self.store = InventoryStore()
        self.adapters = []
        self.adapter_map = {}
        self.devices = []
        self.visible_rows = {}
        self.events = queue.Queue()
        self.worker = None
        self.active_scanner = None
        self.current_page = "Dashboard"
        self.current_cidr = ""
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="Tümü")
        self.notify_var = tk.BooleanVar(value=self.store.get_setting("notify_new", "0") == "1")
        self._setup_styles()
        self._build_shell()
        self.refresh_adapters()
        self.show_page("Dashboard")
        self.root.after(100, self._poll_events)

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background=self.C["panel"], fieldbackground=self.C["panel"],
            foreground=self.C["text"], rowheight=29, borderwidth=0,
            font=("Segoe UI", 8))
        style.configure("Treeview.Heading",
            background=self.C["panel2"], foreground=self.C["muted"],
            font=("Segoe UI Semibold", 8), relief="flat", padding=(7, 8))
        style.map("Treeview", background=[("selected", "#244c78")],
                  foreground=[("selected", "#ffffff")])
        style.configure("TCombobox", fieldbackground="#0e1a2e",
                        background=self.C["panel2"], foreground=self.C["text"],
                        arrowcolor=self.C["text"], padding=6)
        style.configure("Horizontal.TProgressbar",
                        troughcolor=self.C["panel2"], background=self.C["accent"],
                        borderwidth=0)

    def _build_shell(self):
        self.sidebar = tk.Frame(self.root, bg=self.C["sidebar"], width=228)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=self.C["sidebar"])
        brand.pack(fill="x", padx=18, pady=(22, 22))
        tk.Label(brand, text="M", bg="#1c416b", fg=self.C["cyan"],
                 font=("Segoe UI Black", 19), width=2, height=1).pack(side="left", padx=(0, 10))
        brand_text = tk.Frame(brand, bg=self.C["sidebar"])
        brand_text.pack(side="left", anchor="center")
        tk.Label(brand_text, text="MAC FINDER", bg=self.C["sidebar"],
                 fg=self.C["text"], font=("Segoe UI Semibold", 13)).pack(anchor="w")
        tk.Label(brand_text, text="PRO  /  NETWORK INVENTORY", bg=self.C["sidebar"],
                 fg=self.C["muted"], font=("Segoe UI", 7)).pack(anchor="w", pady=(2, 0))
        tk.Frame(self.sidebar, bg=self.C["line"], height=1).pack(fill="x", padx=15, pady=(0, 12))

        self.nav_buttons = {}
        for group, items in self.NAV:
            tk.Label(self.sidebar, text=group, bg=self.C["sidebar"], fg="#657b99",
                     font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=20, pady=(12, 6))
            for name, glyph in items:
                button = tk.Button(
                    self.sidebar, text=f"   {glyph}     {name}", anchor="w",
                    bd=0, bg=self.C["sidebar"], fg=self.C["muted"],
                    activebackground=self.C["panel2"], activeforeground=self.C["text"],
                    font=("Segoe UI", 9), padx=9, pady=10,
                    command=lambda page=name: self.show_page(page),
                    cursor="hand2", highlightthickness=0, relief="flat"
                )
                button.pack(fill="x", padx=10, pady=1)
                self.nav_buttons[name] = button

        foot = tk.Frame(self.sidebar, bg=self.C["sidebar"])
        foot.pack(side="bottom", fill="x", padx=18, pady=18)
        tk.Frame(foot, bg=self.C["line"], height=1).pack(fill="x", pady=(0, 11))
        tk.Label(foot, text="●  LOCAL NETWORK MODE", bg=self.C["sidebar"],
                 fg=self.C["green"], font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(foot, text="SQLite inventory · Offline-first", bg=self.C["sidebar"],
                 fg=self.C["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(5, 0))

        self.main = tk.Frame(self.root, bg=self.C["bg"])
        self.main.pack(side="left", fill="both", expand=True)
        top = tk.Frame(self.main, bg=self.C["bg"], height=76)
        top.pack(fill="x", padx=26, pady=(15, 5))
        self.page_title = tk.Label(top, text="Dashboard", bg=self.C["bg"],
                                   fg=self.C["text"], font=("Segoe UI Semibold", 19))
        self.page_title.pack(side="left", anchor="w")
        right = tk.Frame(top, bg=self.C["bg"])
        right.pack(side="right")
        tk.Label(right, text="NETWORK ADAPTER", bg=self.C["bg"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.adapter_var = tk.StringVar()
        self.adapter_combo = ttk.Combobox(right, textvariable=self.adapter_var,
                                           state="readonly", width=34)
        self.adapter_combo.pack(side="left", padx=(0, 8), pady=(4, 0))
        self.adapter_combo.bind("<<ComboboxSelected>>", self._on_adapter_changed)
        self._button(right, "↻", self.refresh_adapters, secondary=True, small=True).pack(side="left", pady=(4, 0))

        self.content = tk.Frame(self.main, bg=self.C["bg"])
        self.content.pack(fill="both", expand=True, padx=26, pady=(7, 10))
        self.status_var = tk.StringVar(value="Hazır · Yerel ağ envanteri")
        status = tk.Frame(self.main, bg=self.C["sidebar"])
        status.pack(fill="x", side="bottom")
        self.status_label = tk.Label(status, textvariable=self.status_var,
            bg=self.C["sidebar"], fg=self.C["muted"], font=("Segoe UI", 8), anchor="w")
        self.status_label.pack(side="left", padx=17, pady=7)
        self.activity_label = tk.Label(status, text="READY", bg=self.C["sidebar"],
            fg=self.C["green"], font=("Segoe UI Semibold", 8))
        self.activity_label.pack(side="right", padx=17)

    def _button(self, parent, text, command, secondary=False, small=False):
        return tk.Button(
            parent, text=text, command=command, bd=0, cursor="hand2",
            padx=10 if small else 14, pady=6 if small else 9,
            bg=self.C["panel2"] if secondary else self.C["accent"],
            fg=self.C["text"] if secondary else "#071428",
            activebackground=self.C["line"], activeforeground=self.C["text"],
            font=("Segoe UI Semibold", 8 if small else 9),
            highlightthickness=0, relief="flat"
        )

    def _section(self, parent, title, subtitle=""):
        bar = tk.Frame(parent, bg=self.C["bg"])
        bar.pack(fill="x", pady=(0, 10))
        tk.Label(bar, text=title, bg=self.C["bg"], fg=self.C["text"],
                 font=("Segoe UI Semibold", 12)).pack(anchor="w")
        if subtitle:
            tk.Label(bar, text=subtitle, bg=self.C["bg"], fg=self.C["muted"],
                     font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))

    def _panel(self, parent, padx=14, pady=13):
        outer = tk.Frame(parent, bg=self.C["panel"],
                         highlightbackground=self.C["line"], highlightthickness=1)
        outer.pack(fill="both", expand=True)
        inner = tk.Frame(outer, bg=self.C["panel"])
        inner.pack(fill="both", expand=True, padx=padx, pady=pady)
        return inner

    def _label(self, parent, text, color=None, size=9, bold=False):
        return tk.Label(parent, text=text, bg=self.C["panel"],
                        fg=color or self.C["muted"],
                        font=("Segoe UI Semibold" if bold else "Segoe UI", size))

    def _entry(self, parent, value="", width=28):
        entry = tk.Entry(parent, bg="#0b172a", fg=self.C["text"],
            insertbackground=self.C["text"], relief="flat", width=width,
            highlightthickness=1, highlightbackground=self.C["line"],
            highlightcolor=self.C["accent"], font=("Consolas", 9))
        entry.insert(0, value)
        return entry

    def refresh_adapters(self):
        try:
            self.adapters = get_active_adapters()
            self.adapter_map = {
                f"{item['name']}  ·  {item['ip']} / {item['prefixlen']}": item
                for item in self.adapters
            }
            values = list(self.adapter_map)
            self.adapter_combo["values"] = values
            if values:
                if self.adapter_var.get() not in self.adapter_map:
                    self.adapter_var.set(values[0])
                self.status_var.set(f"{len(values)} aktif IPv4 adaptörü bulundu")
            else:
                self.adapter_var.set("")
                self.status_var.set("Aktif IPv4 adaptörü bulunamadı")
        except Exception as exc:
            self.adapters = []
            self.adapter_combo["values"] = []
            self.adapter_var.set("")
            self.status_var.set(f"Adaptör algılama hatası: {exc}")

    def _selected_adapter(self):
        return self.adapter_map.get(self.adapter_var.get())

    def _selected_cidr(self):
        adapter = self._selected_adapter()
        return adapter.get("network") if adapter else ""

    def _on_adapter_changed(self, _event=None):
        adapter = self._selected_adapter()
        if adapter:
            self.status_var.set(f"{adapter['name']} · {adapter['ip']} / {adapter['prefixlen']}")
            if hasattr(self, "cidr_entry") and self.cidr_entry.winfo_exists():
                self._replace_entry(self.cidr_entry, adapter["network"])
            if hasattr(self, "mac_cidr_entry") and self.mac_cidr_entry.winfo_exists():
                self._replace_entry(self.mac_cidr_entry, adapter["network"])

    @staticmethod
    def _replace_entry(entry, value):
        entry.delete(0, "end")
        entry.insert(0, value)

    def show_page(self, page):
        self.current_page = page
        self.page_title.config(text=page)
        for name, button in self.nav_buttons.items():
            selected = name == page
            button.config(bg="#1b3658" if selected else self.C["sidebar"],
                          fg=self.C["text"] if selected else self.C["muted"])
        for child in self.content.winfo_children():
            child.destroy()
        renderers = {
            "Dashboard": self._page_dashboard,
            "Cihaz Envanteri": self._page_inventory,
            "Tek MAC Ara": self._page_mac_lookup,
            "Tüm Ağı Tara": self._page_full_scan,
            "Adaptörler": self._page_adapters,
            "Meraki API": self._page_meraki,
            "Ayarlar": self._page_settings,
        }
        renderers[page]()

    def _metric(self, parent, title, value, hint, accent):
        card = tk.Frame(parent, bg=self.C["panel"],
                        highlightbackground=self.C["line"], highlightthickness=1)
        tk.Frame(card, bg=accent, width=3).pack(side="left", fill="y")
        body = tk.Frame(card, bg=self.C["panel"])
        body.pack(fill="both", expand=True, padx=13, pady=11)
        tk.Label(body, text=title.upper(), bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        tk.Label(body, text=str(value), bg=self.C["panel"], fg=self.C["text"],
                 font=("Segoe UI Semibold", 18)).pack(anchor="w", pady=(4, 0))
        tk.Label(body, text=hint, bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(anchor="w")
        return card

    def _page_dashboard(self):
        records = self.store.get_all()
        online = sum(1 for row in records if row["online"])
        adapter = self._selected_adapter() or {}
        cards = tk.Frame(self.content, bg=self.C["bg"])
        cards.pack(fill="x", pady=(0, 16))
        metrics = [
            ("Kayıtlı cihaz", len(records), "SQLite kalıcı envanter", self.C["accent"]),
            ("Online", online, "Son taramada görülen", self.C["green"]),
            ("Offline", len(records) - online, "Daha önce kaydedilen", self.C["amber"]),
            ("Aktif adaptör", len(self.adapters), adapter.get("name", "Bağlı adaptör yok"), self.C["cyan"]),
        ]
        for index, metric in enumerate(metrics):
            self._metric(cards, *metric).grid(row=0, column=index, sticky="nsew",
                padx=(0 if index == 0 else 9, 0))
            cards.grid_columnconfigure(index, weight=1)
        lower = tk.Frame(self.content, bg=self.C["bg"])
        lower.pack(fill="both", expand=True)
        left = tk.Frame(lower, bg=self.C["bg"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(lower, bg=self.C["bg"], width=260)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        self._section(left, "Son görülen cihazlar", "Envanterden alınan gerçek kayıtlar")
        panel = self._panel(left)
        self._create_table(panel, compact=True)
        self._populate_table(records[:12])
        self._section(right, "Hızlı işlemler", "Yerel ağ keşif araçları")
        actions = self._panel(right)
        for label, page in [
            ("⌕   Tüm ağı tara", "Tüm Ağı Tara"),
            ("⌗   MAC adresi bul", "Tek MAC Ara"),
            ("▤   Envanteri aç", "Cihaz Envanteri"),
            ("▦   Adaptör bilgileri", "Adaptörler"),
        ]:
            self._button(actions, label, lambda p=page: self.show_page(p), secondary=True).pack(fill="x", pady=4)
        tk.Label(actions, text="AKTİF AĞ", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w", pady=(17, 5))
        tk.Label(actions, text=f"{adapter.get('ip', '—')}  /  {adapter.get('prefixlen', '—')}\nGateway  {adapter.get('gateway', '—')}",
                 bg=self.C["panel"], fg=self.C["text"], justify="left",
                 font=("Consolas", 9)).pack(anchor="w")
        history = self.store.get_history(1)
        if history:
            tk.Label(actions, text="SON TARAMA", bg=self.C["panel"], fg=self.C["muted"],
                     font=("Segoe UI Semibold", 7)).pack(anchor="w", pady=(17, 4))
            tk.Label(actions, text=f"{history[0]['scan_type']} · {history[0]['found_count']} cihaz",
                     bg=self.C["panel"], fg=self.C["cyan"], font=("Segoe UI", 8)).pack(anchor="w")

    def _create_table(self, parent, compact=False):
        frame = tk.Frame(parent, bg=self.C["panel"])
        frame.pack(fill="both", expand=True)
        if compact:
            columns = ("mac", "ip", "custom_name", "vendor", "online")
            headings = ("MAC", "IP", "ÖZEL İSİM", "ÜRETİCİ", "DURUM")
            widths = (150, 110, 140, 125, 75)
        else:
            columns, headings = self.COLUMNS, self.HEADINGS
            widths = (135, 110, 130, 145, 125, 110, 125, 90, 135, 135, 80)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=70, anchor="w", stretch=False)
        tree.tag_configure("online", foreground=self.C["green"])
        tree.tag_configure("offline", foreground=self.C["muted"])
        vscroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hscroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vscroll.grid(row=0, column=1, sticky="ns")
        hscroll.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        tree.bind("<Double-1>", lambda event, widget=tree: self._open_selected_details(widget))
        return tree

    @staticmethod
    def _fmt_time(value):
        try:
            return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            return "—"

    def _populate_table(self, records):
        if not hasattr(self, "device_tree") or not self.device_tree.winfo_exists():
            return
        tree = self.device_tree
        for iid in tree.get_children():
            tree.delete(iid)
        self.visible_rows = {}
        compact = len(tree["columns"]) == 5
        for row in records:
            online = bool(row.get("online"))
            if compact:
                values = (row["mac"], row["ip"], row.get("custom_name", ""),
                          row.get("vendor", ""), "ONLINE" if online else "OFFLINE")
            else:
                values = (
                    row["mac"], row["ip"], row.get("custom_name", ""),
                    row.get("hostname", ""), row.get("vendor", ""),
                    row.get("gateway", ""), row.get("interface", ""),
                    row.get("method", ""), self._fmt_time(row.get("first_seen")),
                    self._fmt_time(row.get("last_seen")),
                    "ONLINE" if online else "OFFLINE"
                )
            iid = tree.insert("", "end", values=values,
                              tags=("online" if online else "offline",))
            self.visible_rows[iid] = row

    def _page_inventory(self):
        self._section(self.content, "Cihaz Envanteri",
            "MAC adresi anahtarlı kalıcı kayıtlar · özel isim ve notları çift tıklayarak düzenleyin")
        toolbar = tk.Frame(self.content, bg=self.C["bg"])
        toolbar.pack(fill="x", pady=(0, 10))
        self.search_var = tk.StringVar()
        search = self._entry(toolbar, "", 34)
        search.pack(side="left", ipady=7)
        search.insert(0, "MAC, IP, hostname, vendor, isim veya not ara…")
        search.config(fg=self.C["muted"])
        def focus_in(_event):
            if search.get() == "MAC, IP, hostname, vendor, isim veya not ara…":
                search.delete(0, "end")
                search.config(fg=self.C["text"])
        def focus_out(_event):
            if not search.get().strip():
                search.delete(0, "end")
                search.insert(0, "MAC, IP, hostname, vendor, isim veya not ara…")
                search.config(fg=self.C["muted"])
        search.bind("<FocusIn>", focus_in)
        search.bind("<FocusOut>", focus_out)
        self.filter_combo = ttk.Combobox(toolbar, textvariable=self.filter_var,
            state="readonly", values=("Tümü", "Online", "Offline"), width=12)
        self.filter_combo.pack(side="left", padx=8)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_inventory())
        self._button(toolbar, "↻ Yenile", self._refresh_inventory, secondary=True).pack(side="left")
        self._button(toolbar, "CSV", lambda: self._export_inventory("csv"), secondary=True).pack(side="right", padx=(6, 0))
        self._button(toolbar, "JSON", lambda: self._export_inventory("json"), secondary=True).pack(side="right")
        self.search_widget = search
        self.device_tree = self._create_table(self.content)
        self.device_tree.bind("<<TreeviewSelect>>", self._selection_changed)
        bottom = tk.Frame(self.content, bg=self.C["bg"])
        bottom.pack(fill="x", pady=(8, 0))
        self.inventory_count = tk.Label(bottom, text="", bg=self.C["bg"],
            fg=self.C["muted"], font=("Segoe UI", 8))
        self.inventory_count.pack(side="left")
        self._button(bottom, "MAC kopyala", self._copy_selected_mac, secondary=True, small=True).pack(side="right", padx=(6, 0))
        self._button(bottom, "IP kopyala", self._copy_selected_ip, secondary=True, small=True).pack(side="right")
        self._button(bottom, "Detay / Düzenle", lambda: self._open_selected_details(self.device_tree), secondary=True, small=True).pack(side="right", padx=(6, 0))
        self._refresh_inventory()

    def _refresh_inventory(self):
        if not hasattr(self, "device_tree") or not self.device_tree.winfo_exists():
            return
        query = self.search_widget.get().strip()
        if query.startswith("MAC, IP, hostname"):
            query = ""
        records = self.store.get_all(query)
        mode = self.filter_var.get()
        if mode == "Online":
            records = [row for row in records if row["online"]]
        elif mode == "Offline":
            records = [row for row in records if not row["online"]]
        self._populate_table(records)
        self.inventory_count.config(
            text=f"{len(records)} kayıt gösteriliyor · Veritabanı: {self.store.path}"
        )

    def _selection_changed(self, _event=None):
        pass

    def _selected_record(self, tree):
        selection = tree.selection()
        if not selection:
            return None
        return self.visible_rows.get(selection[0])

    def _copy_text(self, value, label):
        if not value:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(str(value))
        self.status_var.set(f"{label} panoya kopyalandı")

    def _copy_selected_mac(self):
        row = self._selected_record(self.device_tree)
        if row:
            self._copy_text(row["mac"], "MAC adresi")

    def _copy_selected_ip(self):
        row = self._selected_record(self.device_tree)
        if row:
            self._copy_text(row["ip"], "IP adresi")

    def _open_selected_details(self, tree):
        row = self._selected_record(tree)
        if not row:
            return
        self._show_details(row)

    def _show_details(self, row):
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Cihaz Detayı · {row['mac']}")
        dialog.configure(bg=self.C["bg"])
        dialog.geometry("620x570")
        dialog.transient(self.root)
        dialog.grab_set()
        outer = tk.Frame(dialog, bg=self.C["bg"], padx=20, pady=18)
        outer.pack(fill="both", expand=True)
        tk.Label(outer, text=row.get("custom_name") or row.get("hostname") or "Ağ cihazı",
                 bg=self.C["bg"], fg=self.C["text"],
                 font=("Segoe UI Semibold", 17)).pack(anchor="w")
        tk.Label(outer, text=row["mac"], bg=self.C["bg"], fg=self.C["cyan"],
                 font=("Consolas", 10)).pack(anchor="w", pady=(3, 12))
        info = tk.Frame(outer, bg=self.C["panel"], padx=14, pady=12)
        info.pack(fill="x")
        fields = [
            ("IP Address", row.get("ip")), ("Hostname", row.get("hostname")),
            ("Vendor", row.get("vendor")), ("Gateway", row.get("gateway")),
            ("Interface", row.get("interface")), ("Discovery method", row.get("method")),
            ("First seen", self._fmt_time(row.get("first_seen"))),
            ("Last seen", self._fmt_time(row.get("last_seen"))),
            ("Status", "Online" if row.get("online") else "Offline")
        ]
        for label, value in fields:
            line = tk.Frame(info, bg=self.C["panel"])
            line.pack(fill="x", pady=2)
            tk.Label(line, text=label, bg=self.C["panel"], fg=self.C["muted"],
                     width=17, anchor="w", font=("Segoe UI", 8)).pack(side="left")
            tk.Label(line, text=str(value or "Bilinmiyor"), bg=self.C["panel"],
                     fg=self.C["text"], anchor="w", font=("Segoe UI", 8)).pack(side="left")
        tk.Label(outer, text="Özel cihaz adı", bg=self.C["bg"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", pady=(13, 4))
        custom_name = self._entry(outer, row.get("custom_name", ""), 50)
        custom_name.pack(fill="x", ipady=6)
        tk.Label(outer, text="Notlar", bg=self.C["bg"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", pady=(10, 4))
        notes = tk.Text(outer, height=4, bg="#0b172a", fg=self.C["text"],
                        insertbackground=self.C["text"], relief="flat",
                        font=("Segoe UI", 9), highlightthickness=1,
                        highlightbackground=self.C["line"])
        notes.pack(fill="x")
        notes.insert("1.0", row.get("notes", ""))
        actions = tk.Frame(outer, bg=self.C["bg"])
        actions.pack(fill="x", pady=(13, 0))
        self._button(actions, "MAC kopyala", lambda: self._copy_text(row["mac"], "MAC")).pack(side="left")
        self._button(actions, "IP kopyala", lambda: self._copy_text(row["ip"], "IP"), secondary=True).pack(side="left", padx=7)
        def save():
            self.store.update_custom_fields(row["mac"], custom_name.get(), notes.get("1.0", "end").strip())
            dialog.destroy()
            self._refresh_if_inventory()
            self.status_var.set("Cihaz özel adı ve notları kaydedildi")
        self._button(actions, "Kaydet", save).pack(side="right")

    def _refresh_if_inventory(self):
        if self.current_page == "Cihaz Envanteri":
            self._refresh_inventory()
        elif self.current_page == "Dashboard":
            self.show_page("Dashboard")

    def _page_mac_lookup(self):
        self._section(self.content, "Tek MAC Adresi Ara",
            "Önce ARP önbelleği, isteğe bağlı Scapy ARP ve son olarak kontrollü ping + ARP yenileme")
        panel = self._panel(self.content)
        row = tk.Frame(panel, bg=self.C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="HEDEF MAC", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.mac_entry = self._entry(row, Config.get_test_mac(), 26)
        self.mac_entry.pack(anchor="w", ipady=7, pady=(4, 12))
        tk.Label(row, text="IPv4 SUBNET / CIDR", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.mac_cidr_entry = self._entry(row, self._selected_cidr(), 26)
        self.mac_cidr_entry.pack(anchor="w", ipady=7, pady=(4, 12))
        actions = tk.Frame(row, bg=self.C["panel"])
        actions.pack(anchor="w")
        self._button(actions, "⌗  MAC adresini bul", self._start_mac_lookup).pack(side="left")
        self._button(actions, "Test MAC'i doldur", lambda: self._replace_entry(
            self.mac_entry, Config.get_test_mac()), secondary=True).pack(side="left", padx=8)
        self._scan_progress(panel)
        self.mac_result_label = tk.Label(panel, text="Hazır · Hedef MAC girerek aramayı başlatın",
            bg=self.C["panel"], fg=self.C["muted"], font=("Segoe UI", 9), anchor="w")
        self.mac_result_label.pack(fill="x", pady=(12, 0))
        self._label(panel,
            "Not: ARP MAC eşleşmesi aynı Layer-2/VLAN segmentinde yapılabilir. Başka VLAN'daki cihaz için router/switch envanter erişimi gerekir.",
            self.C["amber"], 8).pack(anchor="w", pady=(10, 0))

    def _page_full_scan(self):
        self._section(self.content, "Tüm Ağı Tara",
            "Seçili adaptörün yerel IPv4 subnet'ini keşfet ve cihazları kalıcı envantere kaydet")
        panel = self._panel(self.content)
        row = tk.Frame(panel, bg=self.C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="SUBNET / CIDR", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.cidr_entry = self._entry(row, self._selected_cidr(), 30)
        self.cidr_entry.pack(anchor="w", ipady=7, pady=(4, 12))
        actions = tk.Frame(row, bg=self.C["panel"])
        actions.pack(anchor="w")
        self._button(actions, "⌕  Tüm ağı tara", self._start_full_scan).pack(side="left")
        self.cancel_button = self._button(actions, "Durdur", self._cancel_scan, secondary=True)
        self.cancel_button.pack(side="left", padx=8)
        self._scan_progress(panel)
        self.scan_summary = tk.Label(panel, text="Henüz tarama başlatılmadı",
            bg=self.C["panel"], fg=self.C["muted"], font=("Segoe UI", 9), anchor="w")
        self.scan_summary.pack(fill="x", pady=(10, 0))
        self._label(panel,
            "Güvenlik sınırı: yalnızca seçilen IPv4 subnet'i taranır; maksimum 4.096 host. Port taraması, paket enjeksiyonu, deauth veya saldırı işlemi yoktur.",
            self.C["muted"], 8).pack(anchor="w", pady=(12, 0))

    def _scan_progress(self, parent):
        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(parent, variable=self.progress_var,
                                         maximum=100, style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(18, 0))
        self.progress_text = tk.Label(parent, text="Beklemede", bg=self.C["panel"],
                                      fg=self.C["muted"], font=("Segoe UI", 8), anchor="w")
        self.progress_text.pack(fill="x", pady=(5, 0))

    def _start_worker(self, task_name, function):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("İşlem devam ediyor", "Önce devam eden taramanın bitmesini bekleyin.")
            return
        self.status_var.set(f"Çalışıyor · {task_name}")
        self.activity_label.config(text="RUNNING", fg=self.C["amber"])
        if hasattr(self, "progress_var"):
            self.progress_var.set(0)
            self.progress_text.config(text="İşlem başlatıldı…")
        def run():
            try:
                result = function()
                self.events.put(("result", task_name, result))
            except Exception as exc:
                self.events.put(("error", task_name, str(exc)))
        self.worker = threading.Thread(target=run, name="MACFinderWorker", daemon=True)
        self.worker.start()

    def _progress_callback(self, done, total):
        self.events.put(("progress", done, total))

    def _start_mac_lookup(self):
        mac = normalize_mac(self.mac_entry.get())
        if not mac:
            messagebox.showerror("Geçersiz MAC", "Geçerli bir MAC adresi girin.")
            return
        cidr = self.mac_cidr_entry.get().strip()
        selected = self._selected_adapter()
        self.active_scanner = ARPScanner(target_mac=mac)
        scanner = self.active_scanner
        selected_ip = selected["ip"] if selected else None
        def task():
            found = scanner.find_mac(mac, cidr, selected_ip, self._progress_callback)
            if found:
                new = self.store.save_scan_results([found], scan_type="mac_lookup", target=mac)
                return {"device": found, "new_count": new, "mac": mac}
            self.store.mark_offline(mac)
            self.store.save_scan_results([], scan_type="mac_lookup", target=mac)
            return {"device": None, "new_count": 0, "mac": mac}
        self._start_worker("MAC arama", task)

    def _start_full_scan(self):
        cidr = self.cidr_entry.get().strip()
        selected = self._selected_adapter()
        selected_ip = selected["ip"] if selected else None
        self.active_scanner = ARPScanner()
        scanner = self.active_scanner
        def task():
            devices = scanner.scan_network(cidr, selected_ip, self._progress_callback)
            new_count = self.store.save_scan_results(
                devices, cidr=cidr, scan_type="full_scan", target=cidr
            )
            return {"devices": devices, "new_count": new_count, "cidr": cidr}
        self._start_worker("Tüm ağ taraması", task)

    def _cancel_scan(self):
        if self.active_scanner:
            self.active_scanner.cancel()
            self.status_var.set("Tarama durduruluyor…")

    def _poll_events(self):
        try:
            while True:
                item = self.events.get_nowait()
                kind = item[0]
                if kind == "progress":
                    done, total = item[1], item[2]
                    pct = (done / total * 100) if total else 100
                    if hasattr(self, "progress_var"):
                        self.progress_var.set(pct)
                        self.progress_text.config(text=f"Kontrol edilen: {done:,} / {total:,} host  ·  %{pct:.0f}")
                    self.status_var.set(f"Ağ keşfi · {done:,} / {total:,} host")
                elif kind == "error":
                    task, error = item[1], item[2]
                    self.activity_label.config(text="ERROR", fg=self.C["red"])
                    self.status_var.set(f"{task}: {error}")
                    if hasattr(self, "progress_text") and self.progress_text.winfo_exists():
                        self.progress_text.config(text="Hata: " + error)
                    messagebox.showerror("İşlem hatası", error)
                elif kind == "result":
                    task, result = item[1], item[2]
                    self.activity_label.config(text="COMPLETE", fg=self.C["green"])
                    if task == "MAC arama":
                        device = result["device"]
                        if device:
                            label = f"BULUNDU  ·  {device['ip']}  ·  {device['mac']}"
                            self.mac_result_label.config(text=label, fg=self.C["green"])
                            if result["new_count"] and self.notify_var.get():
                                self.root.bell()
                            self.status_var.set("MAC adresi bulundu ve envantere kaydedildi")
                        else:
                            self.mac_result_label.config(
                                text=f"Bulunamadı · {result['mac']} · Bu subnet içinde eşleşen ARP kaydı alınamadı",
                                fg=self.C["amber"])
                            self.status_var.set("MAC adresi bu yerel subnet'te bulunamadı")
                        self.progress_var.set(100)
                        self.progress_text.config(text="MAC arama tamamlandı")
                    elif task == "Tüm ağ taraması":
                        devices = result["devices"]
                        self.devices = devices
                        self.scan_summary.config(
                            text=f"Tamamlandı · {len(devices)} cihaz bulundu · {result['new_count']} yeni cihaz · {result['cidr']}",
                            fg=self.C["green"])
                        self.progress_var.set(100)
                        self.progress_text.config(text="Tarama tamamlandı")
                        if result["new_count"] and self.notify_var.get():
                            self.root.bell()
                        self.status_var.set(
                            f"Tarama tamamlandı · {len(devices)} cihaz · {result['new_count']} yeni kayıt")
                    self._refresh_visible_data()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _refresh_visible_data(self):
        if self.current_page == "Cihaz Envanteri":
            self._refresh_inventory()
        elif self.current_page == "Dashboard":
            self.show_page("Dashboard")

    def _export_records(self):
        query = ""
        if self.current_page == "Cihaz Envanteri" and hasattr(self, "search_widget"):
            query = self.search_widget.get().strip()
            if query.startswith("MAC, IP, hostname"):
                query = ""
        records = self.store.get_all(query)
        if self.current_page == "Cihaz Envanteri":
            mode = self.filter_var.get()
            if mode == "Online":
                records = [row for row in records if row["online"]]
            elif mode == "Offline":
                records = [row for row in records if not row["online"]]
        return records

    def _export_inventory(self, kind):
        records = self._export_records()
        if not records:
            messagebox.showinfo("Boş envanter", "Dışa aktarılacak cihaz kaydı yok.")
            return
        types = [("CSV", "*.csv")] if kind == "csv" else [("JSON", "*.json")]
        path = filedialog.asksaveasfilename(
            defaultextension="." + kind, filetypes=types,
            initialfile=f"macfinder_inventory.{kind}"
        )
        if not path:
            return
        if kind == "json":
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(records, handle, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)
        self.status_var.set(f"{len(records)} cihaz {kind.upper()} olarak dışa aktarıldı")

    def _page_adapters(self):
        self._section(self.content, "Ağ Adaptörleri",
            "psutil ve Windows ağ yığınından okunan gerçek arayüz bilgileri")
        panel = self._panel(self.content)
        if not self.adapters:
            self._label(panel, "Aktif IPv4 adaptörü bulunamadı", self.C["amber"]).pack(anchor="w")
            return
        counters = get_adapter_stats()
        for adapter in self.adapters:
            card = tk.Frame(panel, bg=self.C["panel2"], padx=15, pady=12)
            card.pack(fill="x", pady=5)
            tk.Label(card, text=adapter["name"], bg=self.C["panel2"], fg=self.C["text"],
                     font=("Segoe UI Semibold", 11)).pack(anchor="w")
            tk.Label(card,
                text=f"IPv4  {adapter['ip']} / {adapter['prefixlen']}     MAC  {adapter['mac']}",
                bg=self.C["panel2"], fg=self.C["cyan"], font=("Consolas", 9)).pack(anchor="w", pady=5)
            tk.Label(card,
                text=f"Subnet  {adapter['network']}     Gateway  {adapter['gateway']}",
                bg=self.C["panel2"], fg=self.C["text"], font=("Segoe UI", 8)).pack(anchor="w")
            tk.Label(card,
                text=f"Link  {adapter['speed_mbps']} Mbps     MTU  {adapter['mtu']}     Duplex  {adapter['duplex']}",
                bg=self.C["panel2"], fg=self.C["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(5, 0))
            counter = counters.get(adapter["name"])
            if counter:
                tk.Label(card,
                    text=f"RX {counter.bytes_recv:,} bytes   ·   TX {counter.bytes_sent:,} bytes",
                    bg=self.C["panel2"], fg=self.C["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(4, 0))

    def _page_meraki(self):
        self._section(self.content, "Cisco Meraki API",
            "İsteğe bağlı salt-okunur Dashboard API sorgusu · API anahtarı diske kaydedilmez")
        panel = self._panel(self.content)
        tk.Label(panel, text="DASHBOARD API KEY", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.meraki_key_entry = self._entry(panel, "", 65)
        self.meraki_key_entry.config(show="•")
        self.meraki_key_entry.pack(anchor="w", ipady=7, pady=(4, 12))
        tk.Label(panel, text="ARANACAK İSTEMCİ MAC", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.meraki_mac_entry = self._entry(panel, Config.get_test_mac(), 30)
        self.meraki_mac_entry.pack(anchor="w", ipady=7, pady=(4, 12))
        self._button(panel, "Meraki switch portlarında ara", self._start_meraki_lookup).pack(anchor="w")
        self.meraki_status = tk.Label(panel, text="API bağlantısı yapılmadı",
            bg=self.C["panel"], fg=self.C["muted"], font=("Segoe UI", 9), anchor="w")
        self.meraki_status.pack(fill="x", pady=(15, 8))
        self.meraki_result = tk.Text(panel, height=12, bg="#0b172a", fg=self.C["text"],
            insertbackground=self.C["text"], relief="flat", font=("Consolas", 9),
            highlightthickness=1, highlightbackground=self.C["line"], wrap="word")
        self.meraki_result.pack(fill="both", expand=True)
        self.meraki_result.insert("1.0",
            "Bu özellik, erişiminiz olan Meraki kuruluşlarını ve switch port status kayıtlarını sorgular.\n"
            "Port/client MAC alanı API tarafından döndürülmüyorsa eşleşme bulunamaz.\n"
            "API key yalnızca bellekte tutulur; ayarlara veya SQLite veritabanına yazılmaz.")
        self.meraki_result.config(state="disabled")

    def _start_meraki_lookup(self):
        key = self.meraki_key_entry.get().strip()
        mac = normalize_mac(self.meraki_mac_entry.get())
        if not key:
            messagebox.showwarning("API key gerekli", "Cisco Meraki Dashboard API anahtarını girin.")
            return
        if not mac:
            messagebox.showerror("Geçersiz MAC", "Geçerli bir MAC adresi girin.")
            return
        def task():
            return MerakiClient(key).find_switch_port(mac)
        self._start_worker("Meraki port arama", task)

    def _page_settings(self):
        self._section(self.content, "Ayarlar", "Envanter ve tarama tercihleri")
        panel = self._panel(self.content)
        check = tk.Checkbutton(panel, text="Yeni cihaz bulunduğunda sesli uyarı ver",
            variable=self.notify_var, command=lambda: self.store.set_setting(
                "notify_new", "1" if self.notify_var.get() else "0"),
            bg=self.C["panel"], fg=self.C["text"], selectcolor=self.C["panel2"],
            activebackground=self.C["panel"], activeforeground=self.C["text"],
            font=("Segoe UI", 9))
        check.pack(anchor="w", pady=(0, 14))
        tk.Label(panel, text="SQLite veritabanı konumu", bg=self.C["panel"],
                 fg=self.C["muted"], font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(panel, text=str(self.store.path), bg=self.C["panel"],
                 fg=self.C["cyan"], font=("Consolas", 9), wraplength=850,
                 justify="left").pack(anchor="w", pady=(5, 14))
        tk.Label(panel,
            text="Ağ taraması sadece seçilen IPv4 subnet'iyle sınırlıdır (maksimum 4.096 host). "
                 "Port tarama, packet injection, monitor mode, deauth veya saldırı özelliği bulunmaz.",
            bg=self.C["panel"], fg=self.C["muted"], font=("Segoe UI", 8),
            wraplength=900, justify="left").pack(anchor="w")

    def _poll_events(self):
        try:
            while True:
                item = self.events.get_nowait()
                kind = item[0]
                if kind == "progress":
                    done, total = item[1], item[2]
                    percent = (done / total * 100) if total else 0
                    if hasattr(self, "progress") and self.progress.winfo_exists():
                        self.progress.configure(mode="determinate")
                        self.progress["maximum"] = 100
                        self.progress["value"] = percent
                        self.progress_text.config(
                            text=f"Kontrol edilen host: {done:,} / {total:,}  ·  %{percent:.0f}")
                    self.status_var.set(f"Tarama devam ediyor · {done:,}/{total:,} host")
                elif kind == "error":
                    task, error = item[1], item[2]
                    self.activity_label.config(text="ERROR", fg=self.C["red"])
                    self.status_var.set(f"{task}: {error}")
                    if hasattr(self, "progress_text") and self.progress_text.winfo_exists():
                        self.progress_text.config(text="Hata: " + error)
                    messagebox.showerror("İşlem hatası", error)
                elif kind == "result":
                    task, result = item[1], item[2]
                    self.activity_label.config(text="COMPLETE", fg=self.C["green"])
                    if task == "MAC arama":
                        device = result["device"]
                        if device:
                            self.mac_result_label.config(
                                text=f"BULUNDU  ·  {device['ip']}  ·  {device['mac']}",
                                fg=self.C["green"])
                            if result["new_count"] and self.notify_var.get():
                                self.root.bell()
                            self.status_var.set("MAC eşleşti ve kalıcı envantere kaydedildi")
                        else:
                            self.mac_result_label.config(
                                text=f"Bulunamadı · {result['mac']} · Seçilen yerel subnet'te ARP eşleşmesi yok",
                                fg=self.C["amber"])
                            self.status_var.set("Hedef MAC bu subnet'te bulunamadı")
                        if hasattr(self, "progress_var"):
                            self.progress_var.set(100)
                            self.progress_text.config(text="MAC arama tamamlandı")
                    elif task == "Tüm ağ taraması":
                        self.scan_summary.config(
                            text=(f"Tamamlandı · {len(result['devices'])} cihaz · "
                                  f"{result['new_count']} yeni kayıt · {result['cidr']}"),
                            fg=self.C["green"])
                        if result["new_count"] and self.notify_var.get():
                            self.root.bell()
                        if hasattr(self, "progress_var"):
                            self.progress_var.set(100)
                            self.progress_text.config(text="Tamamlandı")
                        self.status_var.set(
                            f"Ağ taraması tamamlandı · {len(result['devices'])} cihaz bulundu")
                    elif task == "Meraki port arama":
                        self._show_meraki_result(result)
                    self._refresh_visible_data()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _show_meraki_result(self, result):
        self.meraki_result.config(state="normal")
        self.meraki_result.delete("1.0", "end")
        if result:
            lines = [
                f"Organization : {result.get('organization')}",
                f"Switch       : {result.get('switch_name')}",
                f"Model        : {result.get('model')}",
                f"Serial       : {result.get('serial')}",
                f"Switch MAC   : {result.get('switch_mac')}",
                f"Port         : {result.get('port_id')}",
                f"Client MAC   : {result.get('client_mac')}",
                f"Status       : {result.get('status')}",
                f"VLAN         : {result.get('vlan')}",
                f"PoE enabled  : {result.get('poe_enabled')}",
                f"Power usage  : {result.get('power_usage')}",
                f"Network ID   : {result.get('network_id')}",
            ]
            self.meraki_result.insert("1.0", "\n".join(lines))
            self.meraki_status.config(text="İstemci MAC adresi switch portunda bulundu",
                                      fg=self.C["green"])
        else:
            self.meraki_result.insert("1.0",
                "Eşleşen client MAC içeren switch port durumu bulunamadı.\n"
                "Olası nedenler: cihaz başka VLAN'da, clientMac alanı API'de yok, "
                "API anahtarının izinleri yetersiz veya cihaz şu anda porta bağlı değil.")
            self.meraki_status.config(text="Port eşleşmesi bulunamadı", fg=self.C["amber"])
        self.meraki_result.config(state="disabled")

    def _refresh_visible_data(self):
        if self.current_page == "Cihaz Envanteri":
            self._refresh_inventory()
        elif self.current_page == "Dashboard":
            self.show_page("Dashboard")

    def _export_records(self):
        if self.current_page == "Cihaz Envanteri" and hasattr(self, "search_widget"):
            query = self.search_widget.get().strip()
            if query.startswith("MAC, IP, hostname"):
                query = ""
        else:
            query = ""
        records = self.store.get_all(query)
        if self.current_page == "Cihaz Envanteri":
            mode = self.filter_var.get()
            if mode == "Online":
                records = [row for row in records if row["online"]]
            elif mode == "Offline":
                records = [row for row in records if not row["online"]]
        return records

    def _export_inventory(self, kind):
        records = self._export_records()
        if not records:
            messagebox.showinfo("Envanter boş", "Dışa aktarılacak cihaz kaydı yok.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension="." + kind,
            filetypes=[("CSV", "*.csv")] if kind == "csv" else [("JSON", "*.json")],
            initialfile=f"macfinder_inventory.{kind}"
        )
        if not path:
            return
        if kind == "json":
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(records, handle, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)
        self.status_var.set(f"{len(records)} kayıt {kind.upper()} olarak dışa aktarıldı")

    def on_close(self):
        if self.active_scanner:
            self.active_scanner.cancel()
        self.root.destroy()

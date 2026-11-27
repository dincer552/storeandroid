"""Modern dark desktop UI for MAC Finder Pro."""
import csv
import ipaddress
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from ..config import Config
from ..network.adapter import get_active_adapters, get_adapter_stats
from ..network.arp import get_arp_table
from ..network.mac import normalize_mac
from ..network.scanner import ARPScanner
from ..network.tools import scan_tcp_ports, run_diagnostics


class MACFinderApp:
    C = {
        "bg": "#0b1020", "sidebar": "#0e1629", "panel": "#131e33", "panel2": "#182640",
        "line": "#263653", "text": "#e9f0ff", "muted": "#91a2bf", "accent": "#55a6ff",
        "cyan": "#42d6d0", "green": "#35d49a", "amber": "#f5b84b", "red": "#ff647c",
        "purple": "#a78bfa"
    }

    def __init__(self, root):
        self.root = root
        self.root.title("MAC Finder Pro | Network Infrastructure Toolbox")
        self.root.geometry("1240x790")
        self.root.minsize(1000, 660)
        self.root.configure(bg=self.C["bg"])
        self.events = queue.Queue()
        self.worker = None
        self.current_page = "Dashboard"
        self.adapters = []
        self.devices = []
        self.history = []
        self.meraki_devices = []
        self._setup_styles()
        self._build_shell()
        self.refresh_adapters()
        self.show_page("Dashboard")
        self.root.after(100, self._poll_events)

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=self.C["panel"], fieldbackground=self.C["panel"],
                        foreground=self.C["text"], rowheight=31, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=self.C["panel2"], foreground=self.C["muted"],
                        font=("Segoe UI Semibold", 9), relief="flat", padding=(8, 8))
        style.map("Treeview", background=[("selected", "#234b78")], foreground=[("selected", "#ffffff")])
        style.configure("Horizontal.TProgressbar", troughcolor=self.C["panel2"],
                        background=self.C["accent"], borderwidth=0)

    def _build_shell(self):
        self.sidebar = tk.Frame(self.root, bg=self.C["sidebar"], width=226)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        brand = tk.Frame(self.sidebar, bg=self.C["sidebar"])
        brand.pack(fill="x", padx=18, pady=(22, 24))
        tk.Label(brand, text="N", bg="#1d4270", fg=self.C["cyan"],
                 font=("Segoe UI Black", 18), width=2, height=1).pack(side="left", padx=(0, 10))
        tk.Label(brand, text="NETSCOPE", bg=self.C["sidebar"], fg=self.C["text"],
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        tk.Label(brand, text="INFRASTRUCTURE TOOLBOX", bg=self.C["sidebar"], fg=self.C["muted"],
                 font=("Segoe UI", 7)).pack(anchor="w")
        tk.Frame(self.sidebar, bg=self.C["line"], height=1).pack(fill="x", padx=16, pady=(0, 13))
        self.nav_buttons = {}
        groups = [
            ("OVERVIEW", [("Dashboard", "◈"), ("Network Map", "⌘")]),
            ("DISCOVERY", [("IP Scanner", "⌕"), ("MAC Finder", "⌗"), ("Network Scanner", "◎")]),
            ("INFRASTRUCTURE", [("Port Scanner", "⇄"), ("Ethernet Analyzer", "▤"), ("Switch Discovery", "▦")]),
            ("TOOLS", [("Diagnostics", "✚"), ("Scan History", "◷"), ("Settings", "⚙")])
        ]
        for group, items in groups:
            tk.Label(self.sidebar, text=group, bg=self.C["sidebar"], fg="#657895",
                     font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=20, pady=(9, 6))
            for name, glyph in items:
                btn = tk.Button(
                    self.sidebar, text=f"  {glyph}     {name}", anchor="w", bd=0,
                    bg=self.C["sidebar"], fg=self.C["muted"], activebackground=self.C["panel2"],
                    activeforeground=self.C["text"], font=("Segoe UI", 9), padx=10, pady=9,
                    command=lambda n=name: self.show_page(n), cursor="hand2",
                    highlightthickness=0, relief="flat", overrelief="flat"
                )
                btn.pack(fill="x", padx=11, pady=1)
                self.nav_buttons[name] = btn

        footer = tk.Frame(self.sidebar, bg=self.C["sidebar"])
        footer.pack(side="bottom", fill="x", padx=18, pady=18)
        tk.Frame(footer, bg=self.C["line"], height=1).pack(fill="x", pady=(0, 12))
        tk.Label(footer, text="LOCAL NETWORK MODE", bg=self.C["sidebar"], fg=self.C["green"],
                 font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(footer, text="v1.1  •  Windows 10/11", bg=self.C["sidebar"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(4, 0))

        self.main = tk.Frame(self.root, bg=self.C["bg"])
        self.main.pack(side="left", fill="both", expand=True)
        self.topbar = tk.Frame(self.main, bg=self.C["bg"], height=66)
        self.topbar.pack(fill="x", padx=28, pady=(14, 3))
        self.page_title = tk.Label(self.topbar, text="Dashboard", bg=self.C["bg"], fg=self.C["text"],
                                   font=("Segoe UI Semibold", 19))
        self.page_title.pack(side="left", anchor="w")
        self.top_right = tk.Frame(self.topbar, bg=self.C["bg"])
        self.top_right.pack(side="right")
        self.live_dot = tk.Label(self.top_right, text="●  LOCAL SCAN READY", bg=self.C["bg"],
                                 fg=self.C["green"], font=("Segoe UI Semibold", 8))
        self.live_dot.pack(side="right", padx=(12, 0), pady=9)
        self._button(self.top_right, "↻  Refresh", self.refresh_adapters, secondary=True).pack(side="right")
        self.content = tk.Frame(self.main, bg=self.C["bg"])
        self.content.pack(fill="both", expand=True, padx=28, pady=(7, 12))
        self.status_var = tk.StringVar(value="Ready · Local network tools")
        status = tk.Frame(self.main, bg=self.C["sidebar"], height=28)
        status.pack(fill="x", side="bottom")
        tk.Label(status, textvariable=self.status_var, bg=self.C["sidebar"], fg=self.C["muted"],
                 font=("Segoe UI", 8), anchor="w").pack(side="left", padx=18, pady=6)
        tk.Label(status, text="READ-ONLY NETWORK DISCOVERY", bg=self.C["sidebar"], fg="#607794",
                 font=("Segoe UI Semibold", 8)).pack(side="right", padx=18)

    def _button(self, parent, text, command, secondary=False):
        return tk.Button(parent, text=text, command=command, bd=0, cursor="hand2", padx=14, pady=8,
                         bg=self.C["panel2"] if secondary else self.C["accent"],
                         fg=self.C["text"] if secondary else "#061326",
                         activebackground=self.C["line"], activeforeground=self.C["text"],
                         font=("Segoe UI Semibold", 9), highlightthickness=0,
                         relief="flat", overrelief="flat")

    def _card(self, parent, title, value, detail, accent):
        card = tk.Frame(parent, bg=self.C["panel"], highlightbackground=self.C["line"], highlightthickness=1)
        tk.Frame(card, bg=accent, width=3).pack(side="left", fill="y")
        body = tk.Frame(card, bg=self.C["panel"])
        body.pack(fill="both", expand=True, padx=14, pady=12)
        tk.Label(body, text=title.upper(), bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(body, text=value, bg=self.C["panel"], fg=self.C["text"],
                 font=("Segoe UI Semibold", 18)).pack(anchor="w", pady=(5, 1))
        tk.Label(body, text=detail, bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(anchor="w")
        return card

    def _section(self, parent, title, subtitle=None):
        row = tk.Frame(parent, bg=self.C["bg"])
        row.pack(fill="x", pady=(0, 10))
        tk.Label(row, text=title, bg=self.C["bg"], fg=self.C["text"],
                 font=("Segoe UI Semibold", 12)).pack(anchor="w")
        if subtitle:
            tk.Label(row, text=subtitle, bg=self.C["bg"], fg=self.C["muted"],
                     font=("Segoe UI", 8)).pack(anchor="w", pady=(3, 0))

    def _panel(self, parent, padx=15, pady=13):
        panel = tk.Frame(parent, bg=self.C["panel"], highlightbackground=self.C["line"], highlightthickness=1)
        panel.pack(fill="both", expand=True)
        inner = tk.Frame(panel, bg=self.C["panel"])
        inner.pack(fill="both", expand=True, padx=padx, pady=pady)
        return inner

    def _label(self, parent, text, color=None, size=9, bold=False):
        tk.Label(parent, text=text, bg=self.C["panel"], fg=color or self.C["muted"],
                 font=("Segoe UI Semibold" if bold else "Segoe UI", size)).pack(anchor="w")

    def _entry(self, parent, default="", width=30):
        entry = tk.Entry(parent, bg="#0d172a", fg=self.C["text"], insertbackground=self.C["text"],
                         relief="flat", highlightthickness=1, highlightbackground=self.C["line"],
                         highlightcolor=self.C["accent"], font=("Consolas", 10), width=width)
        entry.insert(0, default)
        return entry

    def refresh_adapters(self):
        try:
            self.adapters = get_active_adapters()
            if hasattr(self, "status_var"):
                self.status_var.set(f"{len(self.adapters)} active IPv4 adapter(s) detected")
        except Exception as exc:
            self.adapters = []
            if hasattr(self, "status_var"):
                self.status_var.set(f"Adapter detection failed: {exc}")

    def _default_cidr(self):
        if self.adapters:
            adapter = self.adapters[0]
            try:
                return str(ipaddress.ip_network(f"{adapter['ip']}/{adapter['netmask']}", strict=False))
            except ValueError:
                pass
        return "192.168.1.0/24"

    def show_page(self, name):
        self.current_page = name
        self.page_title.config(text=name)
        for nav, button in self.nav_buttons.items():
            selected = nav == name
            button.config(bg="#1a3456" if selected else self.C["sidebar"],
                          fg=self.C["text"] if selected else self.C["muted"])
        for child in self.content.winfo_children():
            child.destroy()
        renderers = {
            "Dashboard": self._page_dashboard, "IP Scanner": self._page_ip_scanner,
            "MAC Finder": self._page_mac_finder, "Network Scanner": self._page_network_scanner,
            "Port Scanner": self._page_port_scanner, "Ethernet Analyzer": self._page_ethernet,
            "Switch Discovery": self._page_switch, "Network Map": self._page_map,
            "Diagnostics": self._page_diagnostics, "Scan History": self._page_history,
            "Settings": self._page_settings
        }
        renderers.get(name, self._page_dashboard)()

    def _page_dashboard(self):
        adapter = self.adapters[0] if self.adapters else {}
        arp = get_arp_table()
        neighbours = [e for e in arp if e.get("ip") not in (adapter.get("gateway"), adapter.get("ip"))]
        cards = tk.Frame(self.content, bg=self.C["bg"])
        cards.pack(fill="x", pady=(0, 18))
        metrics = [
            ("LOCAL IPV4", adapter.get("ip", "—"), adapter.get("name", "No active adapter"), self.C["accent"]),
            ("GATEWAY", adapter.get("gateway", "—"), "Default route", self.C["cyan"]),
            ("LINK SPEED", f"{adapter.get('speed_mbps', 0)} Mbps" if adapter else "—", "Reported adapter speed", self.C["purple"]),
            ("ARP NEIGHBOURS", str(len(neighbours)), "Cached neighbour entries", self.C["green"])
        ]
        for index, item in enumerate(metrics):
            self._card(cards, *item).grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 9, 0))
            cards.grid_columnconfigure(index, weight=1)
        lower = tk.Frame(self.content, bg=self.C["bg"])
        lower.pack(fill="both", expand=True)
        left = tk.Frame(lower, bg=self.C["bg"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right = tk.Frame(lower, bg=self.C["bg"], width=290)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        self._section(left, "Network overview", "Live data from the selected Windows network interfaces")
        panel = self._panel(left)
        self._draw_topology(panel, neighbours[:12])
        self._section(right, "Quick actions", "Start a focused network task")
        quick = self._panel(right, padx=13)
        for label, page in [
            ("⌕   Scan IP range", "IP Scanner"), ("⌗   Find a MAC address", "MAC Finder"),
            ("⇄   Check TCP ports", "Port Scanner"), ("▤   Ethernet details", "Ethernet Analyzer"),
            ("✚   Run diagnostics", "Diagnostics")
        ]:
            self._button(quick, label, lambda target=page: self.show_page(target), secondary=True).pack(fill="x", pady=4)
        tk.Label(quick, text="Adapter", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", pady=(16, 4))
        tk.Label(quick, text=f"{adapter.get('name', 'No adapter')}\n{adapter.get('ip', '—')} / {adapter.get('prefixlen', '—')}",
                 bg=self.C["panel"], fg=self.C["text"], justify="left", font=("Segoe UI", 9)).pack(anchor="w")

    def _draw_topology(self, parent, arp_entries):
        canvas = tk.Canvas(parent, bg=self.C["panel"], height=320, highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        canvas.create_text(18, 18, text="LOCAL SEGMENT VIEW", anchor="nw", fill=self.C["muted"],
                           font=("Segoe UI Semibold", 8))
        center = 340
        gateway = self.adapters[0].get("gateway", "—") if self.adapters else "—"
        canvas.create_line(center, 90, center, 145, fill=self.C["accent"], width=2, dash=(4, 4))
        canvas.create_oval(center-54, 42, center+54, 112, fill="#18385c", outline=self.C["accent"], width=2)
        canvas.create_text(center, 67, text="GATEWAY", fill=self.C["cyan"], font=("Segoe UI Semibold", 9))
        canvas.create_text(center, 84, text=gateway, fill=self.C["text"], font=("Consolas", 8))
        canvas.create_line(90, 175, 590, 175, fill=self.C["line"], width=2)
        for index, x in enumerate((105, 245, 385, 525)):
            canvas.create_line(center, 145, x, 175, fill=self.C["line"], width=1, dash=(3, 3))
            entry = arp_entries[index] if index < len(arp_entries) else None
            canvas.create_oval(x-34, 190, x+34, 258, fill="#172943",
                               outline=self.C["cyan"] if entry else self.C["line"], width=1)
            canvas.create_text(x, 214, text="NEIGHBOR" if entry else "—",
                               fill=self.C["text"], font=("Segoe UI Semibold", 8))
            if entry:
                canvas.create_text(x, 232, text=entry.get("ip", ""), fill=self.C["muted"],
                                   font=("Consolas", 7))
        canvas.create_text(center, 290,
            text="Logical neighbour view · physical switch links require LLDP/SNMP or controller data",
            fill=self.C["muted"], font=("Segoe UI", 8))

    def _tree(self, parent, columns, headings, widths=None, height=12):
        wrap = tk.Frame(parent, bg=self.C["panel"])
        wrap.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap, columns=columns, show="headings", height=height)
        for index, column in enumerate(columns):
            tree.heading(column, text=headings[index])
            tree.column(column, width=widths[index] if widths else 120, anchor="w")
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return tree

    def _scan_controls(self, parent, title, subtitle):
        self._section(parent, title, subtitle)
        return self._panel(parent, padx=14, pady=12)

    def _page_ip_scanner(self):
        panel = self._scan_controls(self.content, "IP Scanner",
            "Discover active IPv4 hosts and resolve their MAC addresses from the neighbour table")
        row = tk.Frame(panel, bg=self.C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="Network / CIDR", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(side="left")
        self.cidr_entry = self._entry(row, self._default_cidr(), 24)
        self.cidr_entry.pack(side="left", padx=10)
        self._button(row, "▶  Start scan", self._start_ip_scan).pack(side="left")
        self.progress = ttk.Progressbar(panel, mode="indeterminate", style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(12, 8))
        self.result_count = tk.Label(panel, text="Ready", bg=self.C["panel"], fg=self.C["muted"],
                                     font=("Segoe UI", 8))
        self.result_count.pack(anchor="w", pady=(0, 8))
        self.results_tree = self._tree(panel, ("ip", "mac", "hostname", "vendor", "method"),
            ("IP ADDRESS", "MAC ADDRESS", "HOSTNAME", "VENDOR", "DISCOVERY"),
            (125, 155, 190, 170, 120))
        actions = tk.Frame(panel, bg=self.C["panel"])
        actions.pack(fill="x", pady=(10, 0))
        self._button(actions, "Export CSV", self._export_devices, secondary=True).pack(side="right")

    def _page_network_scanner(self):
        self._page_ip_scanner()
        self.page_title.config(text="Network Scanner")

    def _page_mac_finder(self):
        panel = self._scan_controls(self.content, "MAC Finder",
            "Find a target MAC on the selected local IPv4 segment")
        row = tk.Frame(panel, bg=self.C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="Target MAC", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(side="left")
        self.mac_entry = self._entry(row, Config.get_test_mac(), 22)
        self.mac_entry.pack(side="left", padx=10)
        tk.Label(row, text="Subnet", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(side="left", padx=(8, 0))
        self.mac_cidr = self._entry(row, self._default_cidr(), 20)
        self.mac_cidr.pack(side="left", padx=8)
        self._button(row, "⌕  Find device", self._start_mac_scan).pack(side="left")
        self.mac_result = tk.Label(panel,
            text="Ready · Default test target is Cisco Meraki MS120-24P MAC label",
            bg=self.C["panel"], fg=self.C["muted"], font=("Segoe UI", 9), anchor="w")
        self.mac_result.pack(fill="x", pady=(18, 8))
        self.mac_tree = self._tree(panel, ("ip", "mac", "hostname", "vendor", "interface", "method"),
            ("IP ADDRESS", "MAC ADDRESS", "HOSTNAME", "VENDOR", "INTERFACE", "METHOD"),
            (120, 155, 170, 145, 150, 120), 8)

    def _page_port_scanner(self):
        panel = self._scan_controls(self.content, "TCP Port Scanner",
            "Check selected TCP ports on one host that you are authorized to assess")
        row = tk.Frame(panel, bg=self.C["panel"])
        row.pack(fill="x")
        tk.Label(row, text="Target IP / Host", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(side="left")
        gateway = self.adapters[0].get("gateway") if self.adapters else None
        self.port_host = self._entry(row, gateway if gateway and gateway != "Bilinmiyor" else "192.168.1.1", 22)
        self.port_host.pack(side="left", padx=9)
        tk.Label(row, text="Ports", bg=self.C["panel"], fg=self.C["muted"],
                 font=("Segoe UI", 8)).pack(side="left")
        self.port_entry = self._entry(row, "22,53,80,443,445,502,8080,3389", 34)
        self.port_entry.pack(side="left", padx=9)
        self._button(row, "▶  Scan ports", self._start_port_scan).pack(side="left")
        tk.Label(panel, text="Comma-separated ports; up to 512 ports per target. No exploit or credential checks are performed.",
                 bg=self.C["panel"], fg=self.C["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=12)
        self.port_tree = self._tree(panel, ("port", "service", "state", "latency"),
            ("PORT", "SERVICE", "RESULT", "LATENCY"), (120, 180, 180, 120))

    def _page_ethernet(self):
        self._section(self.content, "Ethernet Analyzer",
            "Read-only adapter status collected from Windows network interfaces")
        self.ethernet_body = self._panel(self.content)
        self._render_ethernet()

    def _render_ethernet(self):
        for child in self.ethernet_body.winfo_children():
            child.destroy()
        if not self.adapters:
            self._label(self.ethernet_body, "No active IPv4 adapter detected", self.C["amber"])
            return
        for adapter in self.adapters:
            card = tk.Frame(self.ethernet_body, bg=self.C["panel2"], padx=14, pady=12)
            card.pack(fill="x", pady=5)
            tk.Label(card, text=adapter["name"], bg=self.C["panel2"], fg=self.C["text"],
                     font=("Segoe UI Semibold", 11)).pack(anchor="w")
            tk.Label(card, text=f"IPv4  {adapter['ip']} / {adapter['prefixlen']}      Gateway  {adapter.get('gateway', '—')}",
                     bg=self.C["panel2"], fg=self.C["cyan"], font=("Consolas", 9)).pack(anchor="w", pady=5)
            tk.Label(card,
                text=f"Link speed  {adapter['speed_mbps']} Mbps     MTU  {adapter['mtu']}     Duplex  {adapter['duplex']}     MAC  {adapter['mac']}",
                bg=self.C["panel2"], fg=self.C["muted"], font=("Segoe UI", 9)).pack(anchor="w")
        counters = get_adapter_stats()
        self._label(self.ethernet_body, "Interface traffic counters", self.C["text"], 10, True)
        for name, counter in counters.items():
            if name in [a["name"] for a in self.adapters]:
                self._label(self.ethernet_body,
                    f"{name}   ↓ {counter.bytes_recv:,} bytes   ↑ {counter.bytes_sent:,} bytes   ·   {counter.packets_recv:,} RX / {counter.packets_sent:,} TX")
        self._label(self.ethernet_body,
            "Note: link speed and duplex are OS-reported adapter values. Cable category, remote switch port speed and PoE state require switch/NIC telemetry.",
            self.C["amber"], 8)

    def _page_diagnostics(self):
        panel = self._scan_controls(self.content, "Network Diagnostics",
            "Quick local configuration checks; tests report only what the OS can verify")
        self._button(panel, "▶  Run diagnostics", self._start_diagnostics).pack(anchor="w", pady=(0, 12))
        self.diag_tree = self._tree(panel, ("test", "result", "status"),
            ("CHECK", "RESULT", "STATUS"), (190, 540, 110))

    def _page_switch(self):
        panel = self._scan_controls(self.content, "Switch Discovery",
            "Meraki inventory lookup requires your own Dashboard API key")
        self._label(panel, "Meraki Dashboard API key", self.C["muted"])
        self.meraki_key = self._entry(panel, "", 54)
        self.meraki_key.pack(anchor="w", pady=7)
        self._label(panel,
            "API key stays in this window only; it is not embedded in the executable or written to source files.",
            self.C["amber"], 8)
        self._button(panel, "Connect to Meraki Dashboard", self._meraki_lookup).pack(anchor="w", pady=9)
        self.switch_status = tk.Label(panel, text="Not connected", bg=self.C["panel"],
                                       fg=self.C["muted"], font=("Segoe UI", 9))
        self.switch_status.pack(anchor="w", pady=5)
        self.switch_tree = self._tree(panel, ("name", "model", "serial", "mac", "network"),
            ("DEVICE", "MODEL", "SERIAL", "MAC", "NETWORK ID"),
            (190, 130, 170, 160, 150), 8)
        for device in self.meraki_devices:
            self.switch_tree.insert("", "end", values=(device["name"], device["model"],
                device["serial"], device["mac"], device["network"]))

    def _meraki_lookup(self):
        key = self.meraki_key.get().strip()
        if not key:
            messagebox.showwarning("API key required",
                "Enter your Meraki Dashboard API key. The key is used only for this session.")
            return
        self.switch_status.config(text="Connecting to Meraki Dashboard…")
        def work():
            import json
            import urllib.request
            headers = {"X-Cisco-Meraki-API-Key": key, "Accept": "application/json"}
            request = urllib.request.Request("https://api.meraki.com/api/v1/organizations", headers=headers)
            with urllib.request.urlopen(request, timeout=15) as response:
                organizations = json.loads(response.read().decode("utf-8"))
            if not organizations:
                raise RuntimeError("No organizations returned for this API key")
            devices = []
            for organization in organizations:
                url = f"https://api.meraki.com/api/v1/organizations/{organization['id']}/devices"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=20) as response:
                    inventory = json.loads(response.read().decode("utf-8"))
                for device in inventory:
                    devices.append({
                        "name": device.get("name") or device.get("model") or "Unnamed",
                        "model": device.get("model", "Unknown"), "serial": device.get("serial", ""),
                        "mac": device.get("mac", ""), "network": device.get("networkId", "")
                    })
            self.events.put(("meraki", devices))
        self._run_worker(work, "Meraki inventory")

    def _page_map(self):
        self._section(self.content, "Network Map",
            "Logical view from local ARP neighbours. Physical links are not inferred without LLDP/SNMP/controller evidence.")
        panel = self._panel(self.content)
        adapter = self.adapters[0] if self.adapters else {}
        excluded = (adapter.get("gateway"), adapter.get("ip"))
        neighbours = [entry for entry in get_arp_table() if entry.get("ip") not in excluded]
        self._draw_topology(panel, neighbours[:12])
        self._label(panel,
            "For true switch-to-port topology, enable LLDP/SNMP access or connect Meraki Dashboard API.",
            self.C["amber"], 8)

    def _page_history(self):
        self._section(self.content, "Scan History", "Recent discovery activity in this application session")
        panel = self._panel(self.content)
        self.history_tree = self._tree(panel, ("time", "type", "summary"),
            ("TIME", "TASK", "SUMMARY"), (170, 160, 530))
        for item in self.history:
            self.history_tree.insert("", "end", values=item)

    def _page_settings(self):
        panel = self._scan_controls(self.content, "Settings", "Local scan limits and application information")
        for text, color in [
            ("Maximum subnet size: 4,096 IPv4 addresses per scan", self.C["text"]),
            ("TCP checks: maximum 512 explicitly selected ports per host", self.C["text"]),
            ("Default test MAC: " + Config.get_test_mac(), self.C["text"]),
            ("No credentials are stored. Meraki API key is used only in the current session.", self.C["muted"])
        ]:
            self._label(panel, text, color)

    def _run_worker(self, function, label):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Task running", "Wait for the current task to finish.")
            return
        self.status_var.set(f"Running · {label}")
        self.live_dot.config(text="●  TASK RUNNING", fg=self.C["amber"])
        def wrapped():
            try:
                self.events.put(("done", function()))
            except Exception as exc:
                self.events.put(("error", f"{label}: {exc}"))
        self.worker = threading.Thread(target=wrapped, daemon=True)
        self.worker.start()

    def _start_ip_scan(self):
        cidr = self.cidr_entry.get().strip()
        self.progress.start(12)
        self._run_worker(lambda: ARPScanner().scan_network(cidr), "IP scan")

    def _start_mac_scan(self):
        mac = normalize_mac(self.mac_entry.get())
        if not mac:
            messagebox.showerror("Invalid MAC", "Enter a valid MAC address.")
            return
        cidr = self.mac_cidr.get().strip()
        self._run_worker(lambda: ARPScanner(mac).find_mac(mac, cidr), "MAC lookup")

    def _start_port_scan(self):
        host = self.port_host.get().strip()
        try:
            ports = [int(part.strip()) for part in self.port_entry.get().split(",") if part.strip()]
        except ValueError:
            messagebox.showerror("Invalid ports", "Ports must be comma-separated numbers.")
            return
        self._run_worker(lambda: scan_tcp_ports(host, ports), "TCP port scan")

    def _start_diagnostics(self):
        self._run_worker(run_diagnostics, "Diagnostics")

    def _poll_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "error":
                    try:
                        if self.progress.winfo_exists():
                            self.progress.stop()
                    except (AttributeError, tk.TclError):
                        pass
                    self.status_var.set(payload)
                    self.live_dot.config(text="●  TASK FAILED", fg=self.C["red"])
                    messagebox.showerror("Operation failed", payload)
                elif kind == "done":
                    try:
                        if self.progress.winfo_exists():
                            self.progress.stop()
                    except (AttributeError, tk.TclError):
                        pass
                    if self.current_page in ("IP Scanner", "Network Scanner"):
                        self.devices = payload
                        for row in self.results_tree.get_children():
                            self.results_tree.delete(row)
                        for device in payload:
                            self.results_tree.insert("", "end", values=(
                                device["ip"], device["mac"], device["hostname"],
                                device["vendor"], device["method"]))
                        self.result_count.config(text=f"{len(payload)} device(s) discovered")
                        self._add_history("IP scan", f"{len(payload)} device(s) in {self.cidr_entry.get()}")
                        self.status_var.set(f"IP scan complete · {len(payload)} devices")
                    elif self.current_page == "MAC Finder":
                        for row in self.mac_tree.get_children():
                            self.mac_tree.delete(row)
                        if payload:
                            self.mac_tree.insert("", "end", values=(
                                payload["ip"], payload["mac"], payload["hostname"],
                                payload["vendor"], payload["interface"], payload["method"]))
                            self.mac_result.config(
                                text=f"FOUND  ·  {payload['ip']}  ·  {payload['mac']}", fg=self.C["green"])
                            summary = f"{payload['mac']} → {payload['ip']}"
                        else:
                            self.mac_result.config(
                                text="Not found in the selected subnet / current neighbour table.",
                                fg=self.C["amber"])
                            summary = "Target MAC not found"
                        self._add_history("MAC lookup", summary)
                        self.status_var.set(summary)
                    elif self.current_page == "Port Scanner":
                        for row in self.port_tree.get_children():
                            self.port_tree.delete(row)
                        for item in payload:
                            self.port_tree.insert("", "end", values=(
                                item["port"], item["service"], item["state"], f"{item['latency_ms']} ms"))
                        opened = sum(1 for item in payload if item["state"] == "Açık")
                        self._add_history("Port scan", f"{self.port_host.get()} · {opened} open port(s)")
                        self.status_var.set(f"Port scan complete · {opened} open")
                    elif self.current_page == "Diagnostics":
                        for row in self.diag_tree.get_children():
                            self.diag_tree.delete(row)
                        for item in payload:
                            self.diag_tree.insert("", "end", values=(
                                item["test"], item["result"], "OK" if item["ok"] else "CHECK"))
                        self.status_var.set("Diagnostics complete")
                    self.live_dot.config(text="●  TASK COMPLETE", fg=self.C["green"])
                elif kind == "meraki":
                    self.meraki_devices = payload
                    if self.current_page == "Switch Discovery" and hasattr(self, "switch_tree"):
                        for row in self.switch_tree.get_children():
                            self.switch_tree.delete(row)
                        for device in payload:
                            self.switch_tree.insert("", "end", values=(
                                device["name"], device["model"], device["serial"], device["mac"], device["network"]))
                        self.switch_status.config(
                            text=f"Connected · {len(payload)} device(s) in organization inventory",
                            fg=self.C["green"])
                    self._add_history("Meraki inventory", f"{len(payload)} device(s) retrieved")
                    self.status_var.set(f"Meraki inventory · {len(payload)} devices")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _add_history(self, task, summary):
        self.history.insert(0, (time.strftime("%H:%M:%S"), task, summary))
        self.history = self.history[:100]

    def _export_devices(self):
        if not self.devices:
            messagebox.showinfo("No data", "Run an IP scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV", "*.csv")], title="Export scan results")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(self.devices[0].keys()))
            writer.writeheader()
            writer.writerows(self.devices)
        self.status_var.set(f"Exported {len(self.devices)} devices · {path}")

    def on_close(self):
        self.root.destroy()

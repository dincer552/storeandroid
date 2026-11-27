import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from ..network.adapter import get_active_adapters
from ..network.mac import normalize_mac, macs_match
from ..network.vendor import lookup_vendor
from ..network.scanner import ARPScanner


class MACFinderApp:
    """Main application class for MAC Finder."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("MAC Finder - Windows Network Device Locator")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Configure dark theme
        self._setup_styles()
        
        # Application state
        self.target_mac = Config.get_test_mac()
        self.scanner = None
        self.scan_job = None
        self.is_scanning = False
        
        # Initialize from config
        self._init_ui()
        self._update_adapters()
    
    def _setup_styles(self):
        """Setup dark theme styles."""
        style = ttk.Style()
        style.theme_use("clam")
        
        # Dark background colors
        bg_color = "#2b2b2b"
        fg_color = "#e0e0e0"
        entry_bg = "#3c3c3c"
        button_bg = "#3a7dff"
        button_fg = "#ffffff"
        
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color, font=("Segoe UI", 10))
        style.configure("TButton", background=button_bg, foreground=button_fg, font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground=entry_bg, foreground=fg_color)
        style.configure("TProgressbar", background=button_bg)
        style.configure("Treeview", background=bg_color, foreground=fg_color, fieldbackground=bg_color)
        style.configure("Treeview.Heading", background="#3c3c3c", foreground=fg_color, font=("Segoe UI", 10, "bold"))
        
        # Map button states
        style.map("TButton", background=[("active", "#2c8cff")])
        style.map("Treeview", background=[("selected", "#0078d7")])
    
    def _init_ui(self):
        """Initialize the user interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top control panel
        self._create_control_panel(main_frame)
        
        # Middle scan results panel
        self._create_results_panel(main_frame)
        
        # Bottom status bar
        self._create_status_bar(main_frame)
    
    def _create_control_panel(self, parent):
        """Create the top control panel."""
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Adapter selection
        ttk.Label(control_frame, text="Ağ Adaptörü:").pack(anchor=tk.W)
        self.adapter_combo = ttk.Combobox(control_frame, state="readonly", width=30)
        self.adapter_combo.pack(fill=tk.X, pady=2)
        
        # Target MAC input
        ttk.Label(control_frame, text="Hedef MAC Adresi:").pack(anchor=tk.W, pady=(10, 0))
        mac_frame = ttk.Frame(control_frame)
        mac_frame.pack(fill=tk.X, pady=2)
        
        self.mac_entry = ttk.Entry(mac_frame, width=40)
        self.mac_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.mac_entry.insert(0, Config.get_test_mac())
        
        # Buttons
        btn_frame = ttk.Frame(mac_frame)
        btn_frame.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.browse_btn = ttk.Button(btn_frame, text="Browse", command=self._on_browse)
        self.browse_btn.pack()
        
        self.use_test_btn = ttk.Button(control_frame, text="Test MAC'i Kullan", command=self._use_test_mac)
        self.use_test_btn.pack(fill=tk.X, pady=5)
        
        # Scan button
        self.scan_btn = ttk.Button(control_frame, text="Ağ Tarama Başlat", command=self._start_scan)
        self.scan_btn.pack(fill=tk.X, pady=10)
        
        # Clear button
        ttk.Button(control_frame, text="Temizle", command=self._clear_results).pack(fill=tk.X, pady=2)
    
    def _create_results_panel(self, parent):
        """Create the middle results panel."""
        results_frame = ttk.Frame(parent)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(results_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Results table
        columns = ("mac", "ip", "hostname", "vendor", "gateway", "interface", "method", "timestamp")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", selectmode="browse")
        
        # Define headings
        self.tree.heading("mac", text="MAC Adresi")
        self.tree.heading("ip", text="IP Adresi")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("vendor", text="Üretici")
        self.tree.heading("gateway", text="Gateway")
        self.tree.heading("interface", text="Arayüz")
        self.tree.heading("method", text="Yöntem")
        self.tree.heading("timestamp", text="Zaman")
        
        # Define columns width
        self.tree.column("mac", width=120, minwidth=120)
        self.tree.column("ip", width=110, minwidth=110)
        self.tree.column("hostname", width=180, minwidth=150)
        self.tree.column("vendor", width=130, minwidth=120)
        self.tree.column("gateway", width=110, minwidth=100)
        self.tree.column("interface", width=120, minwidth=100)
        self.tree.column("method", width=80, minwidth=80)
        self.tree.column("timestamp", width=120, minwidth=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind click event
        self.tree.bind("<ButtonRelease-1>", self._on_row_click)
        
        # Copy buttons frame
        copy_frame = ttk.Frame(parent)
        copy_frame.pack(fill=tk.X, pady=5)
        
        self.copy_mac_btn = ttk.Button(copy_frame, text="MAC Kopyala", command=self._copy_mac, state=tk.DISABLED)
        self.copy_mac_btn.pack(side=tk.LEFT, padx=5)
        
        self.copy_ip_btn = ttk.Button(copy_frame, text="IP Kopyala", command=self._copy_ip, state=tk.DISABLED)
        self.copy_ip_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(copy_frame, text="CSV Dışa Aktar", command=self._export_csv).pack(side=tk.RIGHT, padx=5)
    
    def _create_status_bar(self, parent):
        """Create the bottom status bar."""
        self.status_var = tk.StringVar(value="Hazır")
        status_bar = ttk.Label(parent, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
    
    def _use_test_mac(self):
        """Set the default test MAC address."""
        self.target_mac = Config.get_test_mac()
        self.mac_entry.delete(0, tk.END)
        self.mac_entry.insert(0, self.target_mac)
        self._update_status(f"Test MAC adresi ayarlanmıştır: {self.target_mac}")
    
    def _on_browse(self):
        """Handle browse button (placeholder)."""
        pass
    
    def _start_scan(self):
        """Start network scanning."""
        target = self.mac_entry.get().strip()
        norm_mac = normalize_mac(target)
        if not norm_mac:
            messagebox.showerror("Hata", "Geçersiz MAC adresi formatı")
            return
        
        self.target_mac = norm_mac
        self._update_status("Ağ adaptörleri tespit ediliyor...")
        
        # Get active adapters
        adapters = get_active_adapters()
        if not adapters:
            messagebox.showerror("Hata", "Ağ adaptörleri bulunamadı")
            return
        
        # Disable scan button during scan
        self.scan_btn.config(state=tk.DISABLED)
        self.is_scanning = True
        self.progress['value'] = 0
        
        # Initialize scanner
        self.scanner = ARPScanner(norm_mac)
        
        # Start scan in separate thread-like manner
        self._perform_scan(adapters[0])
    
    def _perform_scan(self, adapter):
        """Perform the actual scan."""
        ip = adapter["ip"]
        netmask = adapter["netmask"]
        
        try:
            results = self.scanner.scan_subnet(ip, netmask)
            self._update_results(results)
        except Exception as e:
            self._update_status(f"Tarama hatası: {str(e)}")
            messagebox.showerror("Tarama Hatası", f"Ağ tarama sırasında hata oluştu:\n{e}")
        finally:
            self.scan_btn.config(state=tk.NORMAL)
            self.is_scanning = False
            self.progress['value'] = 0
            self.status_var.set("Hazır")
    
    def _update_results(self, results):
        """Update the results table."""
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        for device in results:
            self.tree.insert("", tk.END, values=(
                device.get("mac", "Bilinmiyor"),
                device.get("ip", "Bilinmiyor"),
                device.get("hostname", "Bilinmiyor"),
                device.get("vendor", "Bilinmiyor"),
                device.get("gateway", "Bilinmiyor"),
                device.get("interface", "Bilinmiyor"),
                device.get("method", "Bilinmiyor"),
                device.get("timestamp", time.time())
            ))
        
        if results:
            self._update_status(f"Tarama tamamlandı! {len(results)} cihaz bulundu. Hedef MAC eşleşti!")
            self.copy_mac_btn.config(state=tk.NORMAL)
            self.copy_ip_btn.config(state=tk.NORMAL)
        else:
            self._update_status("Tarama tamamlandı - Hedef MAC bulunamadı")
            self.copy_mac_btn.config(state=tk.DISABLED)
            self.copy_ip_btn.config(state=tk.DISABLED)
    
    def _on_row_click(self, event):
        """Handle row click - show details."""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.tree.item(item, "values")
        
        # Show detailed info
        message = f"""Cihaz Detayları:

MAC Adresi: {values[0]}
IP Adresi: {values[1]}
Hostname: {values[2]}
Üretici: {values[3]}
Gateway: {values[4]}
Arayüz: {values[5]}
Yöntem: {values[6]}
Zaman: {values[7]}"""
        
        messagebox.showinfo("Cihaz Detayları", message)
    
    def _copy_mac(self):
        """Copy MAC address to clipboard."""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            values = self.tree.item(item, "values")
            self.root.clipboard_clear()
            self.root.clipboard_append(values[0])
            self._update_status("MAC adresi kopyalandı")
    
    def _copy_ip(self):
        """Copy IP address to clipboard."""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            values = self.tree.item(item, "values")
            self.root.clipboard_clear()
            self.root.clipboard_append(values[1])
            self._update_status("IP adresi kopyalandı")
    
    def _export_csv(self):
        """Export results to CSV."""
        from tkinter import filedialog
        import csv
        
        selection = self.tree.selection()
        if not selection:
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.txt")],
            title="CSV Olarak Kaydet"
        )
        
        if file_path:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["MAC Adresi", "IP Adresi", "Hostname", "Üretici", "Gateway", "Arayüz", "Yöntem", "Zaman"])
                
                for item in selection:
                    values = self.tree.item(item, "values")
                    writer.writerow(values)
            
            self._update_status(f"CSV dosyası kaydedildi: {file_path}")
    
    def _update_status(self, message):
        """Update status bar."""
        self.status_var.set(message)
    
    def _clear_results(self):
        """Clear all results."""
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.copy_mac_btn.config(state=tk.DISABLED)
        self.copy_ip_btn.config(state=tk.DISABLED)
        self._update_status("Temizlendi")


class Config:
    """Configuration class for MAC Finder."""
    
    # Default Meraki API key (empty means disabled)
    MERAKI_API_KEY = ""
    
    # Default test MAC address
    DEFAULT_TEST_MAC = "B8:AB:61:AB:DA:6E"
    
    # Default test device
    DEFAULT_DEVICE = "Cisco Meraki MS120-24P"
    
    # Default test serial number
    DEFAULT_SERIAL = "Q4DE-57E5-WTP9"
    
    @classmethod
    def get_test_mac(cls):
        """Get default test MAC address."""
        return cls.DEFAULT_TEST_MAC
    
    @classmethod
    def get_test_device(cls):
        """Get default test device name."""
        return cls.DEFAULT_DEVICE
    
    @classmethod
    def get_test_serial(cls):
        """Get default test serial number."""
        return cls.DEFAULT_SERIAL
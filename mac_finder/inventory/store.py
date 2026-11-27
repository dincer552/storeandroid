"""Persistent SQLite device inventory."""
import ipaddress
import os
import sqlite3
import threading
import time
from pathlib import Path


def default_database_path():
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    base = Path(root) if root else Path.home() / ".local" / "share"
    folder = base / "MACFinderPro"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "inventory.db"


class InventoryStore:
    def __init__(self, path=None):
        self.path = Path(path) if path else default_database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self):
        with self._lock, self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL DEFAULT '',
                    hostname TEXT NOT NULL DEFAULT '',
                    vendor TEXT NOT NULL DEFAULT '',
                    gateway TEXT NOT NULL DEFAULT '',
                    interface TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    online INTEGER NOT NULL DEFAULT 0,
                    custom_name TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    updated_at REAL NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at REAL NOT NULL,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    found_count INTEGER NOT NULL DEFAULT 0,
                    new_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)")

    @staticmethod
    def _clean(value):
        return str(value or "").strip()

    def upsert_device(self, device):
        mac = self._clean(device.get("mac")).upper().replace("-", ":")
        if len(mac) != 17 or mac.count(":") != 5:
            raise ValueError("Invalid MAC address for inventory record")
        now = time.time()
        with self._lock, self._connect() as db:
            exists = db.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone()
            db.execute("""
                INSERT INTO devices (
                    mac, ip, hostname, vendor, gateway, interface, method,
                    first_seen, last_seen, online, custom_name, notes, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip=excluded.ip,
                    hostname=CASE WHEN excluded.hostname='' THEN devices.hostname ELSE excluded.hostname END,
                    vendor=CASE WHEN excluded.vendor='' THEN devices.vendor ELSE excluded.vendor END,
                    gateway=excluded.gateway,
                    interface=excluded.interface,
                    method=excluded.method,
                    last_seen=excluded.last_seen,
                    online=excluded.online,
                    updated_at=excluded.updated_at
            """, (
                mac, self._clean(device.get("ip")), self._clean(device.get("hostname")),
                self._clean(device.get("vendor")), self._clean(device.get("gateway")),
                self._clean(device.get("interface")), self._clean(device.get("method")),
                now, now, 1 if device.get("online", True) else 0, now
            ))
            return exists is None

    def save_scan_results(self, devices, cidr=None, scan_type="full_scan", target=""):
        now = time.time()
        network = None
        if cidr:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                network = None
        new_count = 0
        with self._lock, self._connect() as db:
            if network:
                rows = db.execute("SELECT mac, ip FROM devices WHERE online=1").fetchall()
                offline_macs = []
                for row in rows:
                    try:
                        if row["ip"] and ipaddress.ip_address(row["ip"]) in network:
                            offline_macs.append(row["mac"])
                    except ValueError:
                        continue
                if offline_macs:
                    db.executemany("UPDATE devices SET online=0, updated_at=? WHERE mac=?",
                                   [(now, mac) for mac in offline_macs])
            for device in devices:
                mac = self._clean(device.get("mac")).upper().replace("-", ":")
                if len(mac) != 17:
                    continue
                exists = db.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone()
                if exists is None:
                    new_count += 1
                db.execute("""
                    INSERT INTO devices (
                        mac, ip, hostname, vendor, gateway, interface, method,
                        first_seen, last_seen, online, custom_name, notes, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        ip=excluded.ip,
                        hostname=CASE WHEN excluded.hostname='' THEN devices.hostname ELSE excluded.hostname END,
                        vendor=CASE WHEN excluded.vendor='' THEN devices.vendor ELSE excluded.vendor END,
                        gateway=excluded.gateway, interface=excluded.interface, method=excluded.method,
                        last_seen=excluded.last_seen, online=excluded.online, updated_at=excluded.updated_at
                """, (mac, self._clean(device.get("ip")), self._clean(device.get("hostname")),
                      self._clean(device.get("vendor")), self._clean(device.get("gateway")),
                      self._clean(device.get("interface")), self._clean(device.get("method")),
                      now, now, 1 if device.get("online", True) else 0, now))
            db.execute("""
                INSERT INTO scan_history(scanned_at, scan_type, target, found_count, new_count)
                VALUES (?, ?, ?, ?, ?)
            """, (now, scan_type, target, len(devices), new_count))
        return new_count

    def mark_offline(self, mac):
        with self._lock, self._connect() as db:
            db.execute("UPDATE devices SET online=0, updated_at=? WHERE mac=?",
                       (time.time(), self._clean(mac).upper().replace("-", ":")))

    def update_custom_fields(self, mac, custom_name, notes):
        with self._lock, self._connect() as db:
            db.execute("UPDATE devices SET custom_name=?, notes=?, updated_at=? WHERE mac=?",
                       (self._clean(custom_name), self._clean(notes), time.time(),
                        self._clean(mac).upper().replace("-", ":")))

    def get_all(self, query=None):
        with self._lock, self._connect() as db:
            if query:
                pattern = "%" + query.strip() + "%"
                rows = db.execute("""
                    SELECT * FROM devices
                    WHERE mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ?
                       OR custom_name LIKE ? OR notes LIKE ?
                    ORDER BY online DESC, last_seen DESC
                """, (pattern, pattern, pattern, pattern, pattern, pattern)).fetchall()
            else:
                rows = db.execute("""
                    SELECT * FROM devices ORDER BY online DESC, last_seen DESC
                """).fetchall()
            return [dict(row) for row in rows]

    def get_device(self, mac):
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM devices WHERE mac=?",
                             (self._clean(mac).upper().replace("-", ":"),)).fetchone()
            return dict(row) if row else None

    def get_history(self, limit=100):
        with self._lock, self._connect() as db:
            rows = db.execute("""
                SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ?
            """, (max(1, min(int(limit), 500)),)).fetchall()
            return [dict(row) for row in rows]

    def get_setting(self, key, default=""):
        with self._lock, self._connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key, value):
        with self._lock, self._connect() as db:
            db.execute("""
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, str(value)))

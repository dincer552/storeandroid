"""Persistent SQLite device inventory."""
import ipaddress
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
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

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA foreign_keys=ON")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _clean(value):
        return str(value or "").strip()

    @staticmethod
    def _mac(value):
        mac = str(value or "").strip().upper().replace("-", ":")
        parts = mac.split(":")
        if len(parts) != 6 or any(len(part) != 2 for part in parts):
            raise ValueError("Invalid MAC address for inventory record")
        if any(any(char not in "0123456789ABCDEF" for char in part) for part in parts):
            raise ValueError("Invalid MAC address for inventory record")
        return mac

    def _initialize(self):
        with self._lock, self._connection() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY, ip TEXT NOT NULL DEFAULT '',
                    hostname TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '',
                    gateway TEXT NOT NULL DEFAULT '', interface TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '', first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL, online INTEGER NOT NULL DEFAULT 0,
                    custom_name TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
                    updated_at REAL NOT NULL
                )
            """)
            db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at REAL NOT NULL,
                    scan_type TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
                    found_count INTEGER NOT NULL DEFAULT 0, new_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)")

    def _upsert(self, db, device, now):
        mac = self._mac(device.get("mac"))
        existing = db.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone()
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
        """, (
            mac, self._clean(device.get("ip")), self._clean(device.get("hostname")),
            self._clean(device.get("vendor")), self._clean(device.get("gateway")),
            self._clean(device.get("interface")), self._clean(device.get("method")),
            now, now, 1 if device.get("online", True) else 0, now
        ))
        return existing is None

    def upsert_device(self, device):
        now = time.time()
        with self._lock, self._connection() as db:
            return self._upsert(db, device, now)

    def save_scan_results(self, devices, cidr=None, scan_type="full_scan", target=""):
        now = time.time()
        network = None
        if cidr:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError("Invalid scan CIDR") from exc
        new_count = 0
        with self._lock, self._connection() as db:
            if network:
                rows = db.execute("SELECT mac, ip FROM devices WHERE online=1").fetchall()
                offline = []
                for row in rows:
                    try:
                        if row["ip"] and ipaddress.ip_address(row["ip"]) in network:
                            offline.append(row["mac"])
                    except ValueError:
                        continue
                if offline:
                    db.executemany("UPDATE devices SET online=0, updated_at=? WHERE mac=?",
                                   [(now, mac) for mac in offline])
            for device in devices:
                if device.get("mac"):
                    new_count += int(self._upsert(db, device, now))
            db.execute("""
                INSERT INTO scan_history(scanned_at, scan_type, target, found_count, new_count)
                VALUES (?, ?, ?, ?, ?)
            """, (now, self._clean(scan_type), self._clean(target), len(devices), new_count))
        return new_count

    def mark_offline(self, mac):
        with self._lock, self._connection() as db:
            db.execute("UPDATE devices SET online=0, updated_at=? WHERE mac=?",
                       (time.time(), self._mac(mac)))

    def update_custom_fields(self, mac, custom_name, notes):
        with self._lock, self._connection() as db:
            db.execute("UPDATE devices SET custom_name=?, notes=?, updated_at=? WHERE mac=?",
                       (self._clean(custom_name), self._clean(notes), time.time(), self._mac(mac)))

    def get_all(self, query=None):
        with self._lock, self._connection() as db:
            if query and query.strip():
                pattern = "%" + query.strip() + "%"
                rows = db.execute("""
                    SELECT * FROM devices
                    WHERE mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ?
                       OR custom_name LIKE ? OR notes LIKE ?
                    ORDER BY online DESC, last_seen DESC
                """, (pattern, pattern, pattern, pattern, pattern, pattern)).fetchall()
            else:
                rows = db.execute("SELECT * FROM devices ORDER BY online DESC, last_seen DESC").fetchall()
            return [dict(row) for row in rows]

    def get_device(self, mac):
        with self._lock, self._connection() as db:
            row = db.execute("SELECT * FROM devices WHERE mac=?", (self._mac(mac),)).fetchone()
            return dict(row) if row else None

    def get_history(self, limit=100):
        with self._lock, self._connection() as db:
            rows = db.execute("SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ?",
                              (max(1, min(int(limit), 500)),)).fetchall()
            return [dict(row) for row in rows]

    def get_setting(self, key, default=""):
        with self._lock, self._connection() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key, value):
        with self._lock, self._connection() as db:
            db.execute("""
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, str(value)))

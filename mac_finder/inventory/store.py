"""Persistent SQLite device inventory."""
import ipaddress
import json
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
            db.execute("""
                CREATE TABLE IF NOT EXISTS meraki_devices (
                    serial TEXT PRIMARY KEY, organization_id TEXT NOT NULL DEFAULT '',
                    organization_name TEXT NOT NULL DEFAULT '', network_id TEXT NOT NULL DEFAULT '',
                    network_name TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '', lan_ip TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL DEFAULT '', firmware TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]', address TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '', dashboard_url TEXT NOT NULL DEFAULT '',
                    last_reported TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '',
                    raw_json TEXT NOT NULL DEFAULT '{}', updated_at REAL NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS meraki_snapshots (
                    scope TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL, updated_at REAL NOT NULL,
                    PRIMARY KEY(scope, target, kind)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_mac ON meraki_devices(mac)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_meraki_network ON meraki_devices(network_id)")

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

    def save_meraki_device(self, device):
        serial = self._clean(device.get("serial"))
        if not serial:
            raise ValueError("Meraki device serial is required.")
        raw = device.get("raw") or device
        now = time.time()
        with self._lock, self._connection() as db:
            db.execute("""
                INSERT INTO meraki_devices (
                    serial, organization_id, organization_name, network_id, network_name,
                    mac, model, lan_ip, name, firmware, tags_json, address, notes,
                    dashboard_url, last_reported, status, raw_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(serial) DO UPDATE SET
                    organization_id=excluded.organization_id,
                    organization_name=excluded.organization_name,
                    network_id=excluded.network_id,
                    network_name=excluded.network_name,
                    mac=CASE WHEN excluded.mac='' THEN meraki_devices.mac ELSE excluded.mac END,
                    model=CASE WHEN excluded.model='' THEN meraki_devices.model ELSE excluded.model END,
                    lan_ip=CASE WHEN excluded.lan_ip='' THEN meraki_devices.lan_ip ELSE excluded.lan_ip END,
                    name=CASE WHEN excluded.name='' THEN meraki_devices.name ELSE excluded.name END,
                    firmware=CASE WHEN excluded.firmware='' THEN meraki_devices.firmware ELSE excluded.firmware END,
                    tags_json=excluded.tags_json, address=excluded.address, notes=excluded.notes,
                    dashboard_url=excluded.dashboard_url, last_reported=excluded.last_reported,
                    status=excluded.status, raw_json=excluded.raw_json, updated_at=excluded.updated_at
            """, (
                serial, self._clean(device.get("organization_id")),
                self._clean(device.get("organization_name")), self._clean(device.get("networkId")),
                self._clean(device.get("network_name")), self._clean(device.get("mac")),
                self._clean(device.get("model")), self._clean(device.get("lanIp")),
                self._clean(device.get("name")), self._clean(device.get("firmware")),
                json.dumps(device.get("tags") or [], ensure_ascii=False),
                self._clean(device.get("address")), self._clean(device.get("notes")),
                self._clean(device.get("url") or device.get("dashboard_url")),
                self._clean(device.get("lastReportedAt")), self._clean(device.get("status")),
                json.dumps(raw, ensure_ascii=False, default=str), now,
            ))

    @staticmethod
    def _meraki_row(row):
        item = dict(row)
        item["tags"] = json.loads(item.pop("tags_json", "[]") or "[]")
        item["raw"] = json.loads(item.pop("raw_json", "{}") or "{}")
        return item

    def get_meraki_device(self, serial):
        with self._lock, self._connection() as db:
            row = db.execute("SELECT * FROM meraki_devices WHERE serial=?", (self._clean(serial),)).fetchone()
            return self._meraki_row(row) if row else None

    def get_meraki_devices(self):
        with self._lock, self._connection() as db:
            rows = db.execute("SELECT * FROM meraki_devices ORDER BY updated_at DESC").fetchall()
            return [self._meraki_row(row) for row in rows]

    def find_inventory(self, query):
        value = self._clean(query)
        if not value:
            return [], []
        pattern = f"%{value}%"
        with self._lock, self._connection() as db:
            local_rows = db.execute("""
                SELECT * FROM devices
                WHERE mac LIKE ? OR ip LIKE ? OR hostname LIKE ? OR vendor LIKE ?
                   OR custom_name LIKE ? OR notes LIKE ?
                ORDER BY online DESC, last_seen DESC
            """, (pattern,) * 6).fetchall()
            meraki_rows = db.execute("""
                SELECT * FROM meraki_devices
                WHERE serial LIKE ? OR organization_id LIKE ? OR organization_name LIKE ?
                   OR network_id LIKE ? OR network_name LIKE ? OR mac LIKE ? OR model LIKE ?
                   OR lan_ip LIKE ? OR name LIKE ? OR firmware LIKE ? OR address LIKE ? OR notes LIKE ?
                ORDER BY updated_at DESC
            """, (pattern,) * 12).fetchall()
        return [dict(row) for row in local_rows], [self._meraki_row(row) for row in meraki_rows]

    def save_snapshot(self, scope, target, kind, payload):
        with self._lock, self._connection() as db:
            db.execute("""
                INSERT INTO meraki_snapshots(scope, target, kind, payload_json, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scope, target, kind) DO UPDATE SET
                    payload_json=excluded.payload_json, updated_at=excluded.updated_at
            """, (
                self._clean(scope), self._clean(target), self._clean(kind),
                json.dumps(payload, ensure_ascii=False, default=str), time.time(),
            ))

    def get_snapshot(self, scope, target, kind):
        with self._lock, self._connection() as db:
            row = db.execute("""
                SELECT payload_json, updated_at FROM meraki_snapshots
                WHERE scope=? AND target=? AND kind=?
            """, (self._clean(scope), self._clean(target), self._clean(kind))).fetchone()
        if not row:
            return None
        return {"payload": json.loads(row["payload_json"]), "updated_at": row["updated_at"], "stale": True}

import aiosqlite
import json
import logging
import os
import sqlite3
import time
from typing import List, Dict, Any, Optional
from config import Config

logger = logging.getLogger(__name__)

class Database:
    @classmethod
    def get_sync_connection(cls) -> sqlite3.Connection:
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        conn = sqlite3.connect(Config.DB_PATH, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
        except Exception:
            pass
        return conn

    @classmethod
    def init_db(cls):
        logger.debug("Initializing SQLite database at %s", Config.DB_PATH)
        with cls.get_sync_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discovered_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    open_ports TEXT,
                    UNIQUE(ip)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    rule TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    attacker_ip TEXT,
                    target_ip TEXT,
                    details TEXT,
                    is_active BOOLEAN DEFAULT 1
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'BLOCKED'
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT NOT NULL,
                    scan_results TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_packets INTEGER,
                    total_bytes INTEGER,
                    tcp_packets INTEGER,
                    udp_packets INTEGER,
                    icmp_packets INTEGER,
                    dns_packets INTEGER
                );
            """)
            conn.commit()

    @classmethod
    def save_blocked_ip_sync(cls, data: Dict[str, Any]):
        try:
            with cls.get_sync_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO blocked_ips (ip, reason, timestamp, status)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        reason = excluded.reason,
                        timestamp = excluded.timestamp,
                        status = excluded.status
                """, (data.get("ip"), data.get("reason", "Threat"), data.get("timestamp"), data.get("status", "BLOCKED")))
                conn.commit()
        except Exception as e:
            logger.debug("DB save blocked IP error: %s", e)

    @classmethod
    def remove_blocked_ip_sync(cls, ip: str):
        try:
            with cls.get_sync_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit()
        except Exception as e:
            logger.debug("DB remove blocked IP error: %s", e)

    @classmethod
    def get_all_blocked_ips_sync(cls) -> List[Dict[str, Any]]:
        try:
            with cls.get_sync_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM blocked_ips ORDER BY timestamp DESC")
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.debug("DB get all blocked IPs error: %s", e)
            return []

    @classmethod
    def upsert_device_sync(cls, device: Dict[str, Any]):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with cls.get_sync_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO discovered_devices (ip, mac, hostname, vendor, first_seen, last_seen, open_ports)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac = COALESCE(excluded.mac, discovered_devices.mac),
                        hostname = COALESCE(excluded.hostname, discovered_devices.hostname),
                        vendor = COALESCE(excluded.vendor, discovered_devices.vendor),
                        last_seen = ?,
                        open_ports = COALESCE(excluded.open_ports, discovered_devices.open_ports)
                """, (
                    device.get("ip"),
                    device.get("mac", "Unknown"),
                    device.get("hostname", "Unknown"),
                    device.get("vendor", "Unknown"),
                    now,
                    now,
                    json.dumps(device.get("open_ports", []))
                ))
                conn.commit()
        except Exception as e:
            logger.debug("DB upsert device error: %s", e)

    @classmethod
    def get_all_devices_sync(cls) -> List[Dict[str, Any]]:
        try:
            with cls.get_sync_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM discovered_devices ORDER BY last_seen DESC")
                rows = cursor.fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    d["open_ports"] = json.loads(d["open_ports"]) if d.get("open_ports") else []
                    results.append(d)
                return results
        except Exception as e:
            logger.debug("DB get all devices error: %s", e)
            return []

    @classmethod
    def save_alert_sync(cls, alert_data: Dict[str, Any]):
        try:
            with cls.get_sync_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO security_alerts (rule, severity, attacker_ip, target_ip, details, is_active)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    alert_data.get("rule_name") or alert_data.get("rule", "Unknown Threat"),
                    alert_data.get("severity", "MEDIUM"),
                    alert_data.get("attacker_ip", "0.0.0.0"),
                    alert_data.get("target_ip", "0.0.0.0"),
                    alert_data.get("description") or alert_data.get("details", ""),
                    1
                ))
                conn.commit()
        except Exception as e:
            logger.debug("DB save alert error: %s", e)

    @classmethod
    def get_recent_alerts_sync(cls, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            with cls.get_sync_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT ?", (limit,))
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.debug("DB get recent alerts error: %s", e)
            return []

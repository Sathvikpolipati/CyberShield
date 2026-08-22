import sqlite3
import os
import json
import time
from typing import List, Dict, Any, Optional

DB_PATH = "data/network_monitor.db"

class Database:
    @staticmethod
    def init_db():
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    risk_score INTEGER DEFAULT 100,
                    is_gateway INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    rule_name TEXT,
                    severity TEXT,
                    attacker_ip TEXT,
                    target_ip TEXT,
                    details TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    timestamp REAL,
                    blocked_by TEXT DEFAULT 'CyberShield Defense'
                )
            """)
            conn.commit()

    @staticmethod
    def save_blocked_ip_sync(ip: str, reason: str = "Threat Mitigated", blocked_by: str = "CyberShield Defense"):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("PRAGMA busy_timeout=5000;")
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO blocked_ips (ip, reason, timestamp, blocked_by)
                    VALUES (?, ?, ?, ?)
                """, (ip, reason, time.time(), blocked_by))
                conn.commit()
        except Exception:
            pass

    @staticmethod
    def remove_blocked_ip_sync(ip: str):
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("PRAGMA busy_timeout=5000;")
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit()
        except Exception:
            pass

    @staticmethod
    def get_all_blocked_ips_sync() -> List[Dict[str, Any]]:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("PRAGMA busy_timeout=5000;")
                cursor = conn.cursor()
                cursor.execute("SELECT ip, reason, timestamp, blocked_by FROM blocked_ips ORDER BY timestamp DESC")
                rows = cursor.fetchall()
                return [{"ip": r[0], "reason": r[1], "timestamp": r[2], "blocked_by": r[3]} for r in rows]
        except Exception:
            return []

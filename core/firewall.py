import logging
import os
import subprocess
import sys
import threading
import time
from typing import Dict, List, Set, Any
from config import Config
from core.db import Database

logger = logging.getLogger(__name__)

class FirewallManager:
    """
    Active Intrusion Defense & Dynamic Firewall Management.
    Provides dual-layer defense:
    1. In-Engine Packet Filtering: Instant zero-latency drop of blocked IPs.
    2. OS-Level Host Firewall Rules: Windows Firewall (netsh) and Linux (iptables).
    """
    _blocked_ips: Set[str] = set()
    _blocked_metadata: Dict[str, Dict[str, Any]] = {}
    _lock = threading.RLock()
    autoblock_enabled: bool = True

    @classmethod
    def init(cls):
        """Loads persistent blocked IPs from the database."""
        try:
            with cls._lock:
                db_blocked = Database.get_all_blocked_ips_sync()
                for b in db_blocked:
                    ip = b.get("ip")
                    if ip:
                        cls._blocked_ips.add(ip)
                        cls._blocked_metadata[ip] = b
        except Exception as e:
            logger.debug("Failed to load blocked IPs from DB: %s", e)

    @classmethod
    def is_ip_blocked(cls, ip: str) -> bool:
        with cls._lock:
            return ip in cls._blocked_ips

    @classmethod
    def get_blocked_ips(cls) -> List[str]:
        with cls._lock:
            return list(cls._blocked_ips)

    @classmethod
    def block_ip(cls, ip: str, reason: str = "Threat Detected / Admin Block") -> Dict[str, Any]:
        """Blocks an IP in memory, updates OS firewall, and records in SQLite."""
        if not ip or ip in ["127.0.0.1", "0.0.0.0", "localhost"]:
            return {"success": False, "message": "Cannot block localhost or invalid IP."}

        with cls._lock:
            cls._blocked_ips.add(ip)
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            meta = {
                "ip": ip,
                "reason": reason,
                "timestamp": now_str,
                "status": "BLOCKED"
            }
            cls._blocked_metadata[ip] = meta

        # Record in database
        try:
            Database.save_blocked_ip_sync(meta)
        except Exception as e:
            logger.debug("DB save blocked IP error: %s", e)

        # Attempt OS-level firewall rule in background thread
        def os_block_worker():
            rule_name = f"CyberShield_Block_{ip.replace('.', '_').replace(':', '_')}"
            try:
                if sys.platform == "win32":
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
                    ]
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logger.info("Added Windows Firewall inbound block rule for %s", ip)
                elif sys.platform.startswith("linux"):
                    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logger.info("Added Linux iptables drop rule for %s", ip)
            except Exception as e:
                logger.debug("OS firewall block attempt: %s", e)

        threading.Thread(target=os_block_worker, daemon=True).start()
        logger.warning("🛑 ACTIVE DEFENSE: IP %s has been BLOCKED (%s)", ip, reason)
        return {"success": True, "ip": ip, "reason": reason, "timestamp": now_str}

    @classmethod
    def unblock_ip(cls, ip: str) -> Dict[str, Any]:
        """Removes an IP block rule."""
        with cls._lock:
            if ip in cls._blocked_ips:
                cls._blocked_ips.remove(ip)
            cls._blocked_metadata.pop(ip, None)

        try:
            Database.remove_blocked_ip_sync(ip)
        except Exception as e:
            logger.debug("DB remove blocked IP error: %s", e)

        def os_unblock_worker():
            rule_name = f"CyberShield_Block_{ip.replace('.', '_').replace(':', '_')}"
            try:
                if sys.platform == "win32":
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elif sys.platform.startswith("linux"):
                    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.debug("OS firewall unblock attempt: %s", e)

        threading.Thread(target=os_unblock_worker, daemon=True).start()
        logger.info("Restored access for IP %s", ip)
        return {"success": True, "ip": ip, "message": f"IP {ip} unblocked successfully."}

    @classmethod
    def get_all_blocked(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            return list(cls._blocked_metadata.values())

import os
import sys
import subprocess
import logging
from typing import Dict, Any, List

logger = logging.getLogger("firewall")

class FirewallManager:
    autoblock_enabled: bool = True
    _blocked_ips: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def init(cls):
        from core.db import Database
        try:
            db_blocked = Database.get_all_blocked_ips_sync()
            for item in db_blocked:
                cls._blocked_ips[item["ip"]] = item
            logger.info("FirewallManager initialized with %d active blocked IPs", len(cls._blocked_ips))
        except Exception as e:
            logger.error("Error loading blocked IPs: %s", e)

    @classmethod
    def is_ip_blocked(cls, ip: str) -> bool:
        return ip in cls._blocked_ips

    @classmethod
    def block_ip(cls, ip: str, reason: str = "Threat Detected", blocked_by: str = "Admin") -> Dict[str, Any]:
        if not ip or ip in ["127.0.0.1", "0.0.0.0", "localhost"]:
            return {"success": False, "message": "Cannot block loopback/invalid address"}

        from core.db import Database
        record = {
            "ip": ip,
            "reason": reason,
            "blocked_by": blocked_by
        }
        cls._blocked_ips[ip] = record
        Database.save_blocked_ip_sync(ip, reason=reason, blocked_by=blocked_by)

        if sys.platform == "win32":
            rule_name = f"CyberShield_Block_{ip.replace(':', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            try:
                subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error("netsh error: %s", e)
        else:
            cmd = f'iptables -I INPUT -s {ip} -j DROP'
            try:
                subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error("iptables error: %s", e)

        logger.warning("BLOCKED IP: %s (Reason: %s)", ip, reason)
        return {"success": True, "message": f"Successfully blocked IP {ip}", "ip": ip}

    @classmethod
    def unblock_ip(cls, ip: str) -> Dict[str, Any]:
        if ip in cls._blocked_ips:
            del cls._blocked_ips[ip]

        from core.db import Database
        Database.remove_blocked_ip_sync(ip)

        if sys.platform == "win32":
            rule_name = f"CyberShield_Block_{ip.replace(':', '_')}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            try:
                subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error("netsh error: %s", e)
        else:
            cmd = f'iptables -D INPUT -s {ip} -j DROP'
            try:
                subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                logger.error("iptables error: %s", e)

        logger.info("UNBLOCKED IP: %s", ip)
        return {"success": True, "message": f"Successfully unblocked IP {ip}", "ip": ip}

    @classmethod
    def get_all_blocked(cls) -> List[Dict[str, Any]]:
        return list(cls._blocked_ips.values())

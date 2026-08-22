import concurrent.futures
import ipaddress
import logging
import os
import re
import shutil
import socket
import subprocess
import time
from typing import List, Dict, Any, Optional
from core.interface import NetworkInterfaceManager
from core.db import Database

logger = logging.getLogger(__name__)

MAC_VENDORS = {
    "00:50:56": "VMware Inc.",
    "08:00:27": "Oracle VirtualBox",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "00:1A:11": "Google LLC",
    "3C:5A:B4": "Google Nest",
    "F4:F5:D8": "Google Home",
    "A4:83:E7": "Apple Inc.",
    "F0:18:98": "Apple Inc.",
    "AC:DE:48": "Apple Inc.",
    "70:48:0F": "Apple iPhone",
    "50:BB:B5": "Realtek / Laptop NIC",
    "A0:AD:9F": "Realtek Semiconductor",
    "02:24:A6": "Wireless Gateway / AP",
    "E4:5F:01": "Raspberry Pi",
    "FC:EC:DA": "Ubiquiti Networks",
    "D8:07:B6": "Samsung Electronics",
    "E8:48:B8": "Samsung Electronics",
    "00:0C:29": "VMware ESXi",
    "00:15:5D": "Microsoft Hyper-V"
}

class HostDiscovery:
    @staticmethod
    def _lookup_vendor(mac: str) -> str:
        if not mac or mac == "Unknown":
            return "Unknown Vendor"
        clean_mac = mac.upper().replace("-", ":")
        prefix = ":".join(clean_mac.split(":")[:3])
        return MAC_VENDORS.get(prefix, "Network Device / OEM")

    @staticmethod
    def get_system_arp_table() -> Dict[str, str]:
        arp_dict = {}

        # 1. Linux & Android (Termux) /proc/net/arp
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r", encoding="utf-8") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                            arp_dict[parts[0]] = parts[3].upper()
            except Exception as e:
                logger.debug("Linux /proc/net/arp error: %s", e)

        # 2. Standard arp -a (Windows / macOS / Linux)
        try:
            cmd = "arp -a"
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                m = re.search(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F\-:]{17})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("-", ":").upper()
                    if not ip.endswith(".255") and not ip.startswith("224.") and not ip.startswith("239.") and not ip.startswith("255."):
                        arp_dict[ip] = mac
        except Exception as e:
            logger.debug("ARP table parse exception: %s", e)

        # 3. Linux/Termux ip neigh fallback
        if shutil.which("ip") and not arp_dict:
            try:
                out = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and "lladdr" in parts:
                        idx = parts.index("lladdr")
                        ip = parts[0]
                        mac = parts[idx + 1].upper()
                        arp_dict[ip] = mac
            except Exception:
                pass

        return arp_dict

    @classmethod
    def _probe_host(cls, ip: str, arp_map: Dict[str, str], timeout: float = 0.2) -> Optional[Dict[str, Any]]:
        t0 = time.time()
        is_alive = False

        # Try connecting to fast diagnostic ports
        for port in [80, 443, 135, 445, 22, 53, 8080]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        is_alive = True
                        break
            except Exception:
                pass

        # If present in ARP map, it responded to network broadcast
        if not is_alive and ip in arp_map:
            is_alive = True

        if not is_alive:
            return None

        latency_ms = round((time.time() - t0) * 1000, 1)
        mac = arp_map.get(ip, "Unknown")
        vendor = cls._lookup_vendor(mac)

        hostname = "Host"
        try:
            h, _, _ = socket.gethostbyaddr(ip)
            hostname = h.split(".")[0]
        except Exception:
            pass

        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "latency_ms": latency_ms,
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    @classmethod
    def scan_subnet(cls, subnet_cidr: Optional[str] = None) -> List[Dict[str, Any]]:
        net_info = NetworkInterfaceManager.get_primary_interface()
        target_subnet = subnet_cidr or net_info["subnet_cidr"]
        logger.info("Scanning subnet: %s", target_subnet)

        try:
            network = ipaddress.ip_network(target_subnet, strict=False)
            hosts_to_scan = [str(ip) for ip in list(network.hosts())[:128]]
        except Exception as e:
            logger.error("Subnet parsing error: %s", e)
            hosts_to_scan = [net_info["local_ip"]]

        arp_map = cls.get_system_arp_table()
        discovered = []

        # Always include the local host
        local_dev = {
            "ip": net_info["local_ip"],
            "mac": net_info.get("mac_address") or "Local NIC",
            "hostname": socket.gethostname(),
            "vendor": "Local Host Interface",
            "latency_ms": 0.1,
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        discovered.append(local_dev)
        Database.upsert_device_sync(local_dev)

        # Multi-threaded fast probe
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            future_to_ip = {
                executor.submit(cls._probe_host, ip, arp_map): ip
                for ip in hosts_to_scan
                if ip != net_info["local_ip"]
            }
            for future in concurrent.futures.as_completed(future_to_ip):
                res = future.result()
                if res:
                    discovered.append(res)
                    Database.upsert_device_sync(res)

        logger.info("Subnet scan finished. Found %d active devices.", len(discovered))
        return discovered

import concurrent.futures
import logging
import re
import shutil
import socket
import subprocess
import time
from typing import List, Dict, Any, Optional
from core.interface import NetworkInterfaceManager
from core.db import Database

logger = logging.getLogger(__name__)

COMMON_PORTS = {
    21: ("FTP", "File Transfer Protocol (Plaintext)", "HIGH"),
    22: ("SSH", "Secure Shell", "LOW"),
    23: ("Telnet", "Telnet Terminal (Insecure)", "CRITICAL"),
    25: ("SMTP", "Simple Mail Transfer", "MEDIUM"),
    53: ("DNS", "Domain Name System", "LOW"),
    80: ("HTTP", "HyperText Transfer (Unencrypted)", "MEDIUM"),
    110: ("POP3", "Post Office Protocol", "MEDIUM"),
    135: ("RPC", "Microsoft RPC Endpoint Mapper", "HIGH"),
    139: ("NetBIOS", "NetBIOS Session Service", "HIGH"),
    443: ("HTTPS", "HTTP over TLS/SSL", "LOW"),
    445: ("SMB", "Microsoft SMB (High Risk Vector)", "HIGH"),
    1433: ("MSSQL", "Microsoft SQL Server", "HIGH"),
    1521: ("Oracle", "Oracle Database", "HIGH"),
    3306: ("MySQL", "MySQL Database", "HIGH"),
    3389: ("RDP", "Remote Desktop Protocol", "HIGH"),
    5432: ("PostgreSQL", "PostgreSQL Database", "MEDIUM"),
    5900: ("VNC", "Virtual Network Computing", "HIGH"),
    8000: ("HTTP-Alt", "Alternative Web Server", "LOW"),
    8080: ("HTTP-Proxy", "HTTP Proxy / App Server", "LOW"),
    8443: ("HTTPS-Alt", "Alternative HTTPS", "LOW"),
    27017: ("MongoDB", "MongoDB Database", "HIGH")
}

class PortScanner:
    @classmethod
    def scan_target(cls, target_ip: str, ports: Optional[List[int]] = None, timeout: float = 0.3) -> Dict[str, Any]:
        net_info = NetworkInterfaceManager.get_primary_interface()

        if not NetworkInterfaceManager.is_in_local_subnet(target_ip, net_info["subnet_cidr"]):
            warning_msg = f"BLOCKED: Target IP [{target_ip}] is outside your local subnet [{net_info['subnet_cidr']}]. Only local network scanning is permitted."
            logger.warning("Port scan blocked: %s", warning_msg)
            return {
                "target_ip": target_ip,
                "error": "OUT_OF_SCOPE",
                "message": warning_msg,
                "open_ports": [],
                "risk_score": 0
            }

        if not ports:
            ports = list(COMMON_PORTS.keys())

        nmap_bin = shutil.which("nmap")
        if nmap_bin:
            try:
                port_str = ",".join(str(p) for p in ports)
                out = subprocess.check_output([nmap_bin, "-sV", "-T4", "-p", port_str, target_ip], stderr=subprocess.DEVNULL, timeout=12).decode("utf-8", errors="ignore")
                open_ports = []
                for line in out.splitlines():
                    m = re.search(r"(\d+)/tcp\s+open\s+([^\s]+)\s*(.*)", line)
                    if m:
                        p_num = int(m.group(1))
                        svc = m.group(2)
                        ver = m.group(3)
                        p_info = COMMON_PORTS.get(p_num, (svc, "Service", "LOW"))
                        open_ports.append({
                            "port": p_num,
                            "service": svc,
                            "description": ver or p_info[1],
                            "risk": p_info[2],
                            "banner": ver
                        })
                scan_res = {
                    "target_ip": target_ip,
                    "scanner": "nmap -sV",
                    "open_ports_count": len(open_ports),
                    "open_ports": open_ports,
                    "risk_score": 50 if any(p["risk"] in ["HIGH", "CRITICAL"] for p in open_ports) else 90,
                    "security_assessment": "Assessed via Nmap service discovery."
                }
                Database.save_port_scan_sync(target_ip, scan_res)
                return scan_res
            except Exception as e:
                logger.debug("nmap port scan fallback: %s", e)

        open_ports = []
        high_risk_count = 0

        def check_port(p):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                res = s.connect_ex((target_ip, p))
                if res == 0:
                    banner = ""
                    try:
                        s.settimeout(0.2)
                        s.sendall(b"\r\n")
                        data = s.recv(128)
                        banner = data.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                    s.close()
                    p_info = COMMON_PORTS.get(p, ("Unknown", "Service", "LOW"))
                    return {
                        "port": p,
                        "service": p_info[0],
                        "description": p_info[1],
                        "risk": p_info[2],
                        "banner": banner
                    }
                s.close()
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(check_port, p) for p in ports]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    open_ports.append(res)
                    if res["risk"] in ["HIGH", "CRITICAL"]:
                        high_risk_count += 1

        open_ports.sort(key=lambda x: x["port"])
        risk_score = 50 if (high_risk_count >= 2 or any(p["risk"] == "CRITICAL" for p in open_ports)) else (75 if len(open_ports) > 3 else 95)
        assessment = "HIGH RISK — Sensitive administrative services exposed." if risk_score == 50 else ("MEDIUM RISK — Multiple listening ports active." if risk_score == 75 else "LOW RISK — Standard host profile.")

        scan_res = {
            "target_ip": target_ip,
            "scanner": "socket banner grabber",
            "open_ports_count": len(open_ports),
            "open_ports": open_ports,
            "risk_score": risk_score,
            "security_assessment": assessment,
            "timestamp": time.time()
        }
        Database.save_port_scan_sync(target_ip, scan_res)
        return scan_res

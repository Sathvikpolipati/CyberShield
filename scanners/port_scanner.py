import socket
import concurrent.futures
import time
from typing import List, Dict, Any

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

class PortScanner:
    @staticmethod
    def scan_target(ip: str, ports: List[int] = None, timeout: float = 0.5) -> Dict[str, Any]:
        if ports is None:
            ports = list(COMMON_PORTS.keys())

        open_ports = []
        def check_port(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                res = s.connect_ex((ip, port))
                if res == 0:
                    service = COMMON_PORTS.get(port, "Unknown")
                    return {"port": port, "service": service, "state": "OPEN"}
            except Exception:
                pass
            finally:
                s.close()
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(check_port, ports)
            for r in results:
                if r:
                    open_ports.append(r)

        risk_score = max(0, 100 - len(open_ports) * 15)
        return {
            "ip": ip,
            "open_ports_count": len(open_ports),
            "open_ports": open_ports,
            "risk_score": risk_score
        }

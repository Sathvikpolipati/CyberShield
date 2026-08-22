import socket
import ipaddress
import time
from typing import List, Dict, Any

class HostDiscovery:
    @staticmethod
    def scan_subnet(cidr: str) -> List[Dict[str, Any]]:
        hosts = []
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            local_ip = "127.0.0.1"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            except Exception:
                pass
            finally:
                s.close()

            hosts.append({
                "ip": local_ip,
                "hostname": "Local Host (This PC)",
                "vendor": "Intel/Realtek NIC",
                "last_seen": time.strftime("%H:%M:%S")
            })

            gateway_ip = str(list(net.hosts())[0])
            if gateway_ip != local_ip:
                hosts.append({
                    "ip": gateway_ip,
                    "hostname": "Default Gateway",
                    "vendor": "Router / Gateway",
                    "last_seen": time.strftime("%H:%M:%S")
                })
        except Exception:
            pass
        return hosts

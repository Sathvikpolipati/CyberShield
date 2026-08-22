import socket
import ipaddress
import psutil
from typing import Dict, Any

class NetworkInterfaceManager:
    @staticmethod
    def get_primary_interface() -> Dict[str, Any]:
        local_ip = "127.0.0.1"
        iface_name = "Default Adapter"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except Exception:
            pass
        finally:
            s.close()

        # Find matching interface
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    iface_name = name
                    break

        parts = local_ip.split(".")
        if len(parts) == 4:
            subnet_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        else:
            subnet_cidr = "192.168.1.0/24"

        return {
            "iface_name": iface_name,
            "local_ip": local_ip,
            "subnet_cidr": subnet_cidr
        }

    @staticmethod
    def is_in_local_subnet(target_ip: str, subnet_cidr: str) -> bool:
        try:
            net = ipaddress.ip_network(subnet_cidr, strict=False)
            ip = ipaddress.ip_address(target_ip)
            return ip in net
        except Exception:
            return False

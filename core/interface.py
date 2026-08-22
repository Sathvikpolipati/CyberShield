import ipaddress
import logging
import socket
import psutil
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class NetworkInterfaceManager:
    @staticmethod
    def get_primary_interface() -> Dict[str, Any]:
        local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception as e:
            logger.debug("Default route lookup exception: %s", e)

        netmask = "255.255.255.0"
        iface_name = "Default"
        mac_address = "Unknown"

        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    iface_name = name
                    netmask = addr.netmask or "255.255.255.0"
                elif getattr(addr, "family", None) == psutil.AF_LINK:
                    mac_address = addr.address

        try:
            network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            subnet_cidr = str(network)
            subnet_prefix = ".".join(local_ip.split(".")[:3]) + "."
        except Exception:
            subnet_cidr = "192.168.1.0/24"
            subnet_prefix = "192.168.1."
            network = ipaddress.IPv4Network("192.168.1.0/24")

        info = {
            "local_ip": local_ip,
            "iface_name": iface_name,
            "mac_address": mac_address,
            "netmask": netmask,
            "subnet_cidr": subnet_cidr,
            "subnet_prefix": subnet_prefix,
            "network_obj": network
        }
        logger.debug("Primary interface detected: %s", info)
        return info

    @staticmethod
    def is_in_local_subnet(target_ip: str, local_subnet_cidr: Optional[str] = None) -> bool:
        """Strict Subnet Boundary Enforcement: Returns True only if target_ip is in local CIDR."""
        try:
            if not local_subnet_cidr:
                info = NetworkInterfaceManager.get_primary_interface()
                local_subnet_cidr = info["subnet_cidr"]

            network = ipaddress.ip_network(local_subnet_cidr, strict=False)
            target = ipaddress.ip_address(target_ip)
            is_valid = target in network
            if not is_valid:
                logger.warning("Target IP %s is OUTSIDE local subnet %s", target_ip, local_subnet_cidr)
            return is_valid
        except Exception as e:
            logger.warning("Subnet validation error for %s: %s", target_ip, e)
            return False

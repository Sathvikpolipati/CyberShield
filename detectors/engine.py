from typing import List, Dict, Any
from core.models import PacketSummary
from core.firewall import FirewallManager
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector
from detectors.icmp_sweep import IcmpSweepDetector
from detectors.dns_tunnel import DNSTunnelDetector

class DetectionEngine:
    def __init__(self):
        self.detectors = [
            PortScanDetector(),
            SynFloodDetector(),
            IcmpSweepDetector(),
            DNSTunnelDetector()
        ]

    def analyze_packet(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        alerts = []
        for det in self.detectors:
            try:
                res = det.analyze(packet)
                if res:
                    alerts.extend(res)
            except Exception:
                pass

        if FirewallManager.autoblock_enabled:
            for a in alerts:
                if a.get("severity") in ["CRITICAL", "HIGH"]:
                    att = a.get("attacker_ip")
                    if att and not FirewallManager.is_ip_blocked(att):
                        FirewallManager.block_ip(att, reason=a.get("rule_name", "Auto Defense"))

        return alerts

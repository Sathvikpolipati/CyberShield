from typing import List, Dict, Any
from detectors.base import BaseDetector
from core.models import PacketSummary, ProtocolType

class DNSTunnelDetector(BaseDetector):
    def __init__(self):
        self.suspicious_queries = set()

    def analyze(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        alerts = []
        if packet.protocol == ProtocolType.DNS:
            if len(packet.summary) > 60:
                alerts.append({
                    "rule_name": "DNS Tunneling / Data Exfiltration",
                    "severity": "HIGH",
                    "attacker_ip": packet.src_ip,
                    "target_ip": packet.dst_ip,
                    "details": f"High-entropy anomalous DNS query: {packet.summary}"
                })
        return alerts

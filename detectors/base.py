import abc
from typing import List, Dict, Any, Optional
from core.parser import PacketSummary

class BaseDetector(abc.ABC):
    @abc.abstractmethod
    def process_packet(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        pass

    def create_alert(self, rule_name: str, severity: str, attacker_ip: str, target_ip: str, description: str) -> Dict[str, Any]:
        return {
            "rule": rule_name,
            "rule_name": rule_name,
            "severity": severity,
            "attacker_ip": attacker_ip,
            "target_ip": target_ip,
            "description": description,
            "details": description,
            "timestamp": None
        }

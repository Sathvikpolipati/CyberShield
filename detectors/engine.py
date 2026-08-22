import logging
from typing import List, Callable, Deque, Dict, Any
from collections import deque
from core.parser import PacketSummary
from core.db import Database
from core.firewall import FirewallManager
from detectors.base import BaseDetector
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SYNFloodDetector
from detectors.icmp_sweep import ICMPSweepDetector
from detectors.dns_tunnel import DNSTunnelingDetector
from config import Config

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self):
        self.detectors: List[BaseDetector] = [
            PortScanDetector(),
            SYNFloodDetector(),
            ICMPSweepDetector(),
            DNSTunnelingDetector()
        ]
        self.alert_history: Deque[Dict[str, Any]] = deque(maxlen=Config.ALERT_HISTORY_LIMIT)
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_callback(self, cb: Callable[[Dict[str, Any]], None]):
        self.callbacks.append(cb)

    def analyze_packet(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        # If attacker IP is already blocked, ignore
        if FirewallManager.is_ip_blocked(packet.src_ip):
            return []

        new_alerts = []
        for detector in self.detectors:
            try:
                triggered = detector.process_packet(packet)
                for alert in triggered:
                    self.alert_history.append(alert)
                    new_alerts.append(alert)
                    Database.save_alert_sync(alert)
                    
                    attacker = alert.get("attacker_ip")
                    rule = alert.get("rule_name")
                    severity = alert.get("severity")
                    logger.info("Threat Alert [%s]: %s -> %s (%s)", severity, attacker, alert.get("target_ip"), rule)

                    # Auto-block if enabled and high severity
                    if FirewallManager.autoblock_enabled and attacker and severity in ["CRITICAL", "HIGH"]:
                        FirewallManager.block_ip(attacker, reason=f"Auto-Blocked: {rule}")

                    for cb in self.callbacks:
                        try:
                            cb(alert)
                        except Exception as e:
                            logger.debug("Callback exception: %s", e)
            except Exception as e:
                logger.debug("Detector exception: %s", e)
        return new_alerts

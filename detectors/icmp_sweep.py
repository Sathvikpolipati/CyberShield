import time
from collections import defaultdict, deque
from typing import List, Dict, Any
from detectors.base import BaseDetector
from core.models import PacketSummary, ProtocolType

class IcmpSweepDetector(BaseDetector):
    def __init__(self, threshold: int = 5, window_seconds: float = 3.0):
        self.threshold = threshold
        self.window = window_seconds
        self.history = defaultdict(deque)

    def analyze(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        alerts = []
        if packet.protocol == ProtocolType.ICMP:
            now = packet.timestamp
            src = packet.src_ip
            dst = packet.dst_ip
            q = self.history[src]
            q.append((now, dst))
            while q and now - q[0][0] > self.window:
                q.popleft()
            unique_targets = {t for _, t in q}
            if len(unique_targets) >= self.threshold:
                alerts.append({
                    "rule_name": "ICMP Subnet Sweep",
                    "severity": "MEDIUM",
                    "attacker_ip": src,
                    "target_ip": dst,
                    "details": f"{src} pinged {len(unique_targets)} unique hosts in {self.window}s"
                })
                q.clear()
        return alerts

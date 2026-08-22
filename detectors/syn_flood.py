import time
from collections import defaultdict, deque
from typing import List, Dict, Any
from detectors.base import BaseDetector
from core.models import PacketSummary, ProtocolType

class SynFloodDetector(BaseDetector):
    def __init__(self, threshold: int = 30, window_seconds: float = 2.0):
        self.threshold = threshold
        self.window = window_seconds
        self.history = defaultdict(deque)

    def analyze(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        alerts = []
        if packet.protocol == ProtocolType.TCP and "S" in packet.summary:
            now = packet.timestamp
            src = packet.src_ip
            dst = packet.dst_ip
            q = self.history[src]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.threshold:
                alerts.append({
                    "rule_name": "SYN Flood DoS Attack",
                    "severity": "CRITICAL",
                    "attacker_ip": src,
                    "target_ip": dst,
                    "details": f"{src} generated {len(q)} SYN packets in {self.window}s"
                })
                q.clear()
        return alerts

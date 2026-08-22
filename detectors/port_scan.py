import time
from collections import defaultdict, deque
from typing import List, Dict, Any
from detectors.base import BaseDetector
from core.models import PacketSummary

class PortScanDetector(BaseDetector):
    def __init__(self, threshold: int = 15, window_seconds: float = 3.0):
        self.threshold = threshold
        self.window = window_seconds
        self.history = defaultdict(deque)

    def analyze(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        alerts = []
        if packet.dst_port:
            now = packet.timestamp
            src = packet.src_ip
            dst = packet.dst_ip
            q = self.history[src]
            q.append((now, packet.dst_port))
            while q and now - q[0][0] > self.window:
                q.popleft()
            unique_ports = {p for _, p in q}
            if len(unique_ports) >= self.threshold:
                alerts.append({
                    "rule_name": "Port Scan Detected",
                    "severity": "HIGH",
                    "attacker_ip": src,
                    "target_ip": dst,
                    "details": f"{src} scanned {len(unique_ports)} unique ports in {self.window}s"
                })
                q.clear()
        return alerts

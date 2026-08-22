import time
from collections import defaultdict, deque
from typing import List, Dict, Any
from core.parser import PacketSummary, ProtocolType
from detectors.base import BaseDetector
from config import Config

class PortScanDetector(BaseDetector):
    def __init__(self, window_seconds: float = Config.PORT_SCAN_WINDOW, threshold: int = Config.PORT_SCAN_THRESHOLD):
        self.window = window_seconds
        self.threshold = threshold
        # src_ip -> deque of (timestamp, dst_ip, dst_port) bounded maxlen=200
        self.history = defaultdict(lambda: deque(maxlen=200))
        self.last_alert_time = {}

    def process_packet(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        if packet.protocol not in [ProtocolType.TCP, ProtocolType.UDP] or not packet.dst_port:
            return []

        src = packet.src_ip
        dst = packet.dst_ip
        port = packet.dst_port
        now = packet.timestamp or time.time()

        q = self.history[src]
        q.append((now, dst, port))

        # O(1) amortized sliding window pruning
        while q and (now - q[0][0] > self.window):
            q.popleft()

        # Group unique ports per target host
        target_ports = defaultdict(set)
        for _, t_dst, t_port in q:
            target_ports[t_dst].add(t_port)

        alerts = []
        for target, ports in target_ports.items():
            if len(ports) >= self.threshold:
                last_alert = self.last_alert_time.get((src, target), 0)
                if now - last_alert > 5.0:
                    self.last_alert_time[(src, target)] = now
                    alerts.append(self.create_alert(
                        rule_name="Port Scan Detected",
                        severity="HIGH",
                        attacker_ip=src,
                        target_ip=target,
                        description=f"Host {src} probed {len(ports)} unique ports on target {target} within {self.window}s window."
                    ))
        return alerts

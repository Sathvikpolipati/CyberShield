import time
from collections import defaultdict, deque
from typing import List, Dict, Any
from core.parser import PacketSummary, ProtocolType
from detectors.base import BaseDetector
from config import Config

class ICMPSweepDetector(BaseDetector):
    def __init__(self, window: float = Config.ICMP_SWEEP_WINDOW, threshold: int = Config.ICMP_SWEEP_THRESHOLD):
        self.window = window
        self.threshold = threshold
        self.history = defaultdict(lambda: deque(maxlen=200))
        self.last_alert = {}

    def process_packet(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        if packet.protocol != ProtocolType.ICMP:
            return []

        src = packet.src_ip
        dst = packet.dst_ip
        now = packet.timestamp or time.time()

        q = self.history[src]
        q.append((now, dst))

        while q and (now - q[0][0] > self.window):
            q.popleft()

        unique_targets = set(t_dst for _, t_dst in q)
        if len(unique_targets) >= self.threshold:
            last_t = self.last_alert.get(src, 0)
            if now - last_t > 5.0:
                self.last_alert[src] = now
                return [self.create_alert(
                    rule_name="ICMP Ping Sweep",
                    severity="MEDIUM",
                    attacker_ip=src,
                    target_ip=dst,
                    description=f"ICMP sweep detected from {src}: {len(unique_targets)} unique hosts pinged in {self.window}s."
                )]
        return []

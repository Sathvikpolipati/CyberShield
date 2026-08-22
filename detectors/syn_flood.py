import time
from collections import defaultdict, deque
from typing import List, Dict, Any
from core.parser import PacketSummary, ProtocolType
from detectors.base import BaseDetector
from config import Config

class SYNFloodDetector(BaseDetector):
    def __init__(self, rate_threshold: int = Config.SYN_FLOOD_RATE_THRESHOLD, ack_ratio_max: float = Config.SYN_ACK_RATIO_MAX, window: float = Config.SYN_FLOOD_WINDOW):
        self.rate_threshold = rate_threshold
        self.ack_ratio_max = ack_ratio_max
        self.window = window
        self.syn_history = defaultdict(lambda: deque(maxlen=500))
        self.syn_ack_history = defaultdict(lambda: deque(maxlen=500))
        self.last_alert = {}

    def process_packet(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        if packet.protocol not in [ProtocolType.TCP, ProtocolType.HTTP, ProtocolType.HTTPS] or not packet.flags:
            return []

        now = packet.timestamp or time.time()
        dst = packet.dst_ip
        src = packet.src_ip

        if packet.flags == "S":
            q = self.syn_history[dst]
            q.append(now)
            while q and (now - q[0] > self.window):
                q.popleft()

            syn_count = len(q)
            if syn_count >= self.rate_threshold:
                ack_q = self.syn_ack_history[dst]
                while ack_q and (now - ack_q[0] > self.window):
                    ack_q.popleft()
                ack_count = len(ack_q)
                ratio = ack_count / syn_count if syn_count > 0 else 1.0

                if ratio <= self.ack_ratio_max:
                    last_t = self.last_alert.get(dst, 0)
                    if now - last_t > 3.0:
                        self.last_alert[dst] = now
                        return [self.create_alert(
                            rule_name="SYN Flood Attack",
                            severity="HIGH",
                            attacker_ip=src,
                            target_ip=dst,
                            description=f"SYN Flood targeting {dst}: {syn_count} SYN/sec (SYN-ACK ratio: {ratio:.2f} <= {self.ack_ratio_max})."
                        )]
        elif "A" in packet.flags:
            self.syn_ack_history[src].append(now)

        return []

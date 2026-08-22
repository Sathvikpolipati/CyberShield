import math
import time
from collections import defaultdict, deque
from typing import List, Dict, Any
from core.parser import PacketSummary, ProtocolType
from detectors.base import BaseDetector
from config import Config

class DNSTunnelingDetector(BaseDetector):
    def __init__(self, entropy_threshold: float = Config.DNS_ENTROPY_THRESHOLD, burst_threshold: int = Config.DNS_BURST_THRESHOLD, burst_window: float = Config.DNS_BURST_WINDOW):
        self.entropy_threshold = entropy_threshold
        self.burst_threshold = burst_threshold
        self.burst_window = burst_window
        self.query_history = defaultdict(lambda: deque(maxlen=200))
        self.last_alert = {}

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        length = len(text)
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def process_packet(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        if packet.protocol != ProtocolType.DNS:
            return []

        src = packet.src_ip
        dst = packet.dst_ip
        now = packet.timestamp or time.time()
        domain = packet.info.get("domain") or packet.info.get("qname") or (packet.summary.split()[1] if len(packet.summary.split()) > 1 else "")

        alerts = []
        if domain:
            entropy = self.calculate_entropy(domain)
            if entropy >= self.entropy_threshold and len(domain) > 15:
                last_t = self.last_alert.get((src, "entropy"), 0)
                if now - last_t > 5.0:
                    self.last_alert[(src, "entropy")] = now
                    alerts.append(self.create_alert(
                        rule_name="DNS Tunneling / Data Exfiltration",
                        severity="HIGH",
                        attacker_ip=src,
                        target_ip=dst,
                        description=f"High-entropy DNS query detected from {src}: '{domain}' (Entropy: {entropy} >= {self.entropy_threshold})."
                    ))

        # Query burst detection
        q = self.query_history[src]
        q.append(now)
        while q and (now - q[0] > self.burst_window):
            q.popleft()

        if len(q) >= self.burst_threshold:
            last_t = self.last_alert.get((src, "burst"), 0)
            if now - last_t > 10.0:
                self.last_alert[(src, "burst")] = now
                alerts.append(self.create_alert(
                    rule_name="DNS Query Flood",
                    severity="HIGH",
                    attacker_ip=src,
                    target_ip=dst,
                    description=f"Abnormal DNS query burst: {len(q)} queries within {self.burst_window}s from {src}."
                ))

        return alerts

# Alias for test compatibility
DNSAnomalyDetector = DNSTunnelingDetector

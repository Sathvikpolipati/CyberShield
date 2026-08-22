import pytest
import time
from core.parser import PacketSummary, ProtocolType
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SYNFloodDetector
from detectors.icmp_sweep import ICMPSweepDetector
from detectors.dns_tunnel import DNSAnomalyDetector

def test_port_scan_detector_triggers():
    detector = PortScanDetector()
    attacker = "192.168.1.105"
    target = "192.168.1.15"
    alerts = []
    now = time.time()

    for port in range(20, 36):
        pkt = PacketSummary(
            id=port,
            timestamp=now,
            src_ip=attacker,
            dst_ip=target,
            src_port=40000 + port,
            dst_port=port,
            protocol=ProtocolType.TCP,
            length=64,
            flags="S",
            summary="SYN probe"
        )
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) >= 1
    assert alerts[0]["attacker_ip"] == attacker
    assert alerts[0]["severity"] == "HIGH"
    assert "Port Scan" in alerts[0]["rule_name"]

def test_syn_flood_detector_triggers():
    detector = SYNFloodDetector()
    attacker = "192.168.1.200"
    target = "192.168.1.10"
    alerts = []
    now = time.time()

    for i in range(120):
        pkt = PacketSummary(
            id=i,
            timestamp=now,
            src_ip=attacker,
            dst_ip=target,
            src_port=30000 + i,
            dst_port=80,
            protocol=ProtocolType.TCP,
            length=64,
            flags="S",
            summary="SYN flood burst"
        )
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) >= 1
    assert alerts[0]["severity"] == "HIGH"
    assert "SYN Flood" in alerts[0]["rule_name"]

def test_icmp_sweep_detector_triggers():
    detector = ICMPSweepDetector()
    attacker = "192.168.1.105"
    alerts = []
    now = time.time()

    for i in range(8):
        pkt = PacketSummary(
            id=i,
            timestamp=now,
            src_ip=attacker,
            dst_ip=f"192.168.1.{10 + i}",
            protocol=ProtocolType.ICMP,
            length=64,
            summary="ICMP Echo probe",
            info={"type": 8}
        )
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) >= 1
    assert alerts[0]["severity"] == "MEDIUM"
    assert "Ping Sweep" in alerts[0]["rule_name"]

def test_dns_tunneling_detector_triggers():
    detector = DNSAnomalyDetector()
    attacker = "192.168.1.77"
    now = time.time()
    
    long_hex = "4f8a9c2b7e1d3f0a5c8e2b9a7d1f3e0c4b8a2e7d"
    pkt = PacketSummary(
        id=1,
        timestamp=now,
        src_ip=attacker,
        dst_ip="8.8.8.8",
        src_port=53123,
        dst_port=53,
        protocol=ProtocolType.DNS,
        length=120,
        summary="DNS Query",
        info={"qname": f"{long_hex}.c2exfil.darkops.io"}
    )
    alerts = detector.process_packet(pkt)
    assert len(alerts) >= 1
    assert alerts[0]["severity"] == "HIGH"
    assert "DNS Tunneling" in alerts[0]["rule_name"]

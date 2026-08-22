from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector
from detectors.icmp_sweep import IcmpSweepDetector
from detectors.dns_tunnel import DNSTunnelDetector
from core.models import PacketSummary, ProtocolType

def test_port_scan_detector_triggers():
    det = PortScanDetector(threshold=3, window_seconds=5.0)
    for p in range(1, 5):
        pkt = PacketSummary(
            id=p, timestamp=100.0, formatted_time="00:00:00",
            src_ip="192.168.1.100", dst_ip="192.168.1.1",
            src_port=5000, dst_port=p, protocol=ProtocolType.TCP, length=64, summary="TCP SYN"
        )
        alerts = det.analyze(pkt)
    assert len(alerts) > 0
    assert alerts[0]["rule_name"] == "Port Scan Detected"

def test_syn_flood_detector_triggers():
    det = SynFloodDetector(threshold=5, window_seconds=2.0)
    alerts = []
    for i in range(10):
        pkt = PacketSummary(
            id=i, timestamp=100.0, formatted_time="00:00:00",
            src_ip="192.168.1.50", dst_ip="192.168.1.1",
            src_port=1000+i, dst_port=80, protocol=ProtocolType.TCP, length=64, summary="TCP [S]"
        )
        alerts.extend(det.analyze(pkt))
    assert len(alerts) > 0
    assert alerts[0]["rule_name"] == "SYN Flood DoS Attack"

def test_icmp_sweep_detector_triggers():
    det = IcmpSweepDetector(threshold=3, window_seconds=5.0)
    alerts = []
    for i in range(1, 5):
        pkt = PacketSummary(
            id=i, timestamp=100.0, formatted_time="00:00:00",
            src_ip="192.168.1.99", dst_ip=f"192.168.1.{i}",
            src_port=None, dst_port=None, protocol=ProtocolType.ICMP, length=64, summary="ICMP"
        )
        alerts.extend(det.analyze(pkt))
    assert len(alerts) > 0
    assert alerts[0]["rule_name"] == "ICMP Subnet Sweep"

def test_dns_tunneling_detector_triggers():
    det = DNSTunnelDetector()
    pkt = PacketSummary(
        id=1, timestamp=100.0, formatted_time="00:00:00",
        src_ip="192.168.1.10", dst_ip="8.8.8.8",
        src_port=50000, dst_port=53, protocol=ProtocolType.DNS, length=120,
        summary="DNS Query: " + "a" * 80 + ".evil-tunnel.com"
    )
    alerts = det.analyze(pkt)
    assert len(alerts) > 0
    assert "DNS Tunneling" in alerts[0]["rule_name"]

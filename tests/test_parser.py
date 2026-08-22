from core.parser import PacketParser, ProtocolType
from core.models import PacketSummary

def test_parse_tcp_packet():
    pkt = PacketSummary(
        id=1, timestamp=100.0, formatted_time="00:00:01",
        src_ip="192.168.1.2", dst_ip="192.168.1.1",
        src_port=443, dst_port=50000, protocol=ProtocolType.HTTPS, length=1200, summary="HTTPS TLS"
    )
    assert pkt.protocol == ProtocolType.HTTPS
    assert pkt.src_port == 443

def test_parse_dns_query():
    pkt = PacketSummary(
        id=2, timestamp=100.0, formatted_time="00:00:02",
        src_ip="192.168.1.2", dst_ip="8.8.8.8",
        src_port=53000, dst_port=53, protocol=ProtocolType.DNS, length=100, summary="DNS Query"
    )
    assert pkt.protocol == ProtocolType.DNS
    assert pkt.dst_port == 53

def test_parse_icmp_echo():
    pkt = PacketSummary(
        id=3, timestamp=100.0, formatted_time="00:00:03",
        src_ip="192.168.1.2", dst_ip="192.168.1.1",
        src_port=None, dst_port=None, protocol=ProtocolType.ICMP, length=64, summary="ICMP"
    )
    assert pkt.protocol == ProtocolType.ICMP

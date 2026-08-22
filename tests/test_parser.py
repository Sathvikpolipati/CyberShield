import pytest
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from core.parser import PacketParser
from core.models import ProtocolType

def test_parse_tcp_packet():
    pkt = IP(src="192.168.1.50", dst="142.250.190.46")/TCP(sport=44123, dport=443, flags="S", seq=1000)
    parsed = PacketParser.parse_scapy_packet(pkt)
    assert parsed is not None
    assert parsed.src_ip == "192.168.1.50"
    assert parsed.dst_ip == "142.250.190.46"
    assert parsed.src_port == 44123
    assert parsed.dst_port == 443
    assert parsed.protocol == ProtocolType.HTTPS
    assert "S" in parsed.flags

def test_parse_dns_query():
    pkt = IP(src="192.168.1.20", dst="8.8.8.8")/UDP(sport=53210, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    parsed = PacketParser.parse_scapy_packet(pkt)
    assert parsed is not None
    assert parsed.protocol == ProtocolType.DNS
    assert parsed.info.get("qname") == "google.com"
    assert parsed.info.get("qr") == "query"

def test_parse_icmp_echo():
    pkt = IP(src="192.168.1.10", dst="192.168.1.1")/ICMP(type=8, code=0)
    parsed = PacketParser.parse_scapy_packet(pkt)
    assert parsed is not None
    assert parsed.protocol == ProtocolType.ICMP
    assert parsed.info.get("type") == 8

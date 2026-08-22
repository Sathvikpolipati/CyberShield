import datetime
import logging
import time
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class ProtocolType(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    ARP = "ARP"
    OTHER = "OTHER"

class PacketSummary(BaseModel):
    id: int
    timestamp: float = Field(default_factory=time.time)
    formatted_time: str = ""
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: ProtocolType
    length: int
    flags: Optional[str] = None
    summary: str
    info: Dict[str, Any] = Field(default_factory=dict)
    raw_hex_preview: Optional[str] = None

class PacketParser:
    _counter: int = 0

    @classmethod
    def parse_scapy_packet(cls, scapy_pkt) -> Optional[PacketSummary]:
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw
            cls._counter += 1
            pkt_id = cls._counter
            pkt_len = len(scapy_pkt)
            ts = float(getattr(scapy_pkt, "time", time.time()))
            formatted_time = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_port = None
            dst_port = None
            proto = ProtocolType.OTHER
            flags = None
            info: Dict[str, Any] = {}
            summary_desc = ""

            if scapy_pkt.haslayer(IP):
                src_ip = scapy_pkt[IP].src
                dst_ip = scapy_pkt[IP].dst
                info["ttl"] = scapy_pkt[IP].ttl
            elif scapy_pkt.haslayer(IPv6):
                src_ip = scapy_pkt[IPv6].src
                dst_ip = scapy_pkt[IPv6].dst
            elif scapy_pkt.haslayer(ARP):
                src_ip = scapy_pkt[ARP].psrc
                dst_ip = scapy_pkt[ARP].pdst
                return PacketSummary(
                    id=pkt_id, timestamp=ts, formatted_time=formatted_time,
                    src_ip=src_ip, dst_ip=dst_ip, protocol=ProtocolType.ARP,
                    length=pkt_len, summary=f"ARP Who has {dst_ip}? Tell {src_ip}"
                )

            if scapy_pkt.haslayer(TCP):
                proto = ProtocolType.TCP
                src_port = int(scapy_pkt[TCP].sport)
                dst_port = int(scapy_pkt[TCP].dport)
                flags = str(scapy_pkt[TCP].flags)
                info["flags"] = flags

                if dst_port == 80 or src_port == 80:
                    proto = ProtocolType.HTTP
                elif dst_port == 443 or src_port == 443:
                    proto = ProtocolType.HTTPS
                elif dst_port == 22 or src_port == 22:
                    proto = ProtocolType.SSH
                summary_desc = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags}]"

            elif scapy_pkt.haslayer(UDP):
                proto = ProtocolType.UDP
                src_port = int(scapy_pkt[UDP].sport)
                dst_port = int(scapy_pkt[UDP].dport)
                summary_desc = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

                if scapy_pkt.haslayer(DNS):
                    proto = ProtocolType.DNS
                    if scapy_pkt.haslayer(DNSQR):
                        raw_qname = scapy_pkt[DNSQR].qname
                        qname = (raw_qname.decode("utf-8", errors="ignore") if isinstance(raw_qname, bytes) else str(raw_qname)).rstrip(".")
                        info["qname"] = qname
                        qr_val = getattr(scapy_pkt[DNS], "qr", 0)
                        info["qr"] = "response" if qr_val == 1 else "query"
                        summary_desc = f"DNS Query: {qname}"

            elif scapy_pkt.haslayer(ICMP):
                proto = ProtocolType.ICMP
                info["type"] = scapy_pkt[ICMP].type
                summary_desc = f"ICMP Type {scapy_pkt[ICMP].type} ({src_ip} -> {dst_ip})"

            raw_preview = None
            if scapy_pkt.haslayer(Raw):
                raw_preview = bytes(scapy_pkt[Raw].load)[:64].hex()

            return PacketSummary(
                id=pkt_id, timestamp=ts, formatted_time=formatted_time,
                src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                protocol=proto, length=pkt_len, flags=flags, summary=summary_desc,
                info=info, raw_hex_preview=raw_preview
            )
        except Exception as e:
            logger.debug("Packet dissection error: %s", e)
            return None

    @classmethod
    def parse_tshark_line(cls, line: str) -> Optional[PacketSummary]:
        try:
            parts = line.strip().split("\t")
            if len(parts) >= 7:
                cls._counter += 1
                ts_str, src_ip, dst_ip, proto_str, sport, dport, length, *rest = parts
                sport_int = int(sport) if sport and sport.isdigit() else None
                dport_int = int(dport) if dport and dport.isdigit() else None
                
                proto = ProtocolType.OTHER
                p_upper = proto_str.upper()
                if "TCP" in p_upper: proto = ProtocolType.TCP
                elif "UDP" in p_upper: proto = ProtocolType.UDP
                elif "ICMP" in p_upper: proto = ProtocolType.ICMP
                elif "DNS" in p_upper: proto = ProtocolType.DNS
                elif "HTTP" in p_upper: proto = ProtocolType.HTTP

                summary = f"{proto.value} {src_ip}:{sport or ''} -> {dst_ip}:{dport or ''}"
                return PacketSummary(
                    id=cls._counter,
                    timestamp=time.time(),
                    formatted_time=datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport_int,
                    dst_port=dport_int,
                    protocol=proto,
                    length=int(length) if length.isdigit() else 60,
                    summary=summary
                )
        except Exception as e:
            logger.debug("Tshark parse error: %s", e)
        return None

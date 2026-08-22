import time
from core.models import PacketSummary, ProtocolType

class PacketParser:
    _packet_counter = 0

    @classmethod
    def parse(cls, pkt) -> PacketSummary:
        cls._packet_counter += 1
        now = time.time()
        formatted_time = time.strftime("%H:%M:%S", time.localtime(now))
        
        src_ip = "127.0.0.1"
        dst_ip = "127.0.0.1"
        src_port = None
        dst_port = None
        proto = ProtocolType.OTHER
        length = len(pkt) if hasattr(pkt, "__len__") else 64
        summary = "Raw Packet"

        try:
            if hasattr(pkt, "haslayer"):
                if pkt.haslayer("IP"):
                    src_ip = pkt["IP"].src
                    dst_ip = pkt["IP"].dst
                elif pkt.haslayer("IPv6"):
                    src_ip = pkt["IPv6"].src
                    dst_ip = pkt["IPv6"].dst

                if pkt.haslayer("TCP"):
                    proto = ProtocolType.TCP
                    src_port = pkt["TCP"].sport
                    dst_port = pkt["TCP"].dport
                    if src_port == 443 or dst_port == 443:
                        proto = ProtocolType.HTTPS
                        summary = f"HTTPS TLS ({src_port}->{dst_port})"
                    elif src_port == 80 or dst_port == 80:
                        proto = ProtocolType.HTTP
                        summary = f"HTTP Web ({src_port}->{dst_port})"
                    else:
                        summary = f"TCP Flags [{pkt['TCP'].flags}] ({src_port}->{dst_port})"
                elif pkt.haslayer("UDP"):
                    proto = ProtocolType.UDP
                    src_port = pkt["UDP"].sport
                    dst_port = pkt["UDP"].dport
                    if src_port == 53 or dst_port == 53:
                        proto = ProtocolType.DNS
                        summary = f"DNS Query/Response ({src_port}->{dst_port})"
                    elif src_port == 443 or dst_port == 443:
                        proto = ProtocolType.HTTPS
                        summary = f"QUIC / HTTPS UDP ({src_port}->{dst_port})"
                    else:
                        summary = f"UDP Datagram ({src_port}->{dst_port})"
                elif pkt.haslayer("ICMP"):
                    proto = ProtocolType.ICMP
                    summary = "ICMP Ping / Control Message"
        except Exception:
            pass

        return PacketSummary(
            id=cls._packet_counter,
            timestamp=now,
            formatted_time=formatted_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=length,
            summary=summary
        )

from enum import Enum
from pydantic import BaseModel
from typing import Optional

class ProtocolType(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    OTHER = "OTHER"

class PacketSummary(BaseModel):
    id: int
    timestamp: float
    formatted_time: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: ProtocolType
    length: int
    summary: str

from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import time

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

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

class SecurityAlert(BaseModel):
    id: str
    timestamp: float = Field(default_factory=time.time)
    formatted_time: str = ""
    rule_name: str
    severity: Severity
    attacker_ip: str
    target_ip: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)

class TrafficStats(BaseModel):
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    protocols: Dict[str, int] = Field(default_factory=dict)
    top_talkers: List[Dict[str, Any]] = Field(default_factory=list)
    alert_counts: Dict[str, int] = Field(default_factory=lambda: {
        "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0
    })
    active_threats: int = 0
    uptime_seconds: float = 0.0

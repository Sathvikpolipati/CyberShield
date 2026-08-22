import os
import sys
from pydantic import BaseModel

class SystemConfig(BaseModel):
    DATABASE_URL: str = "sqlite:///data/network_monitor.db"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "logs/network_monitor.log"
    SECURITY_LOG_FILE: str = "logs/security_alerts.jsonl"
    PID_FILE: str = ".network_monitor.pid"
    WEB_HOST: str = "0.0.0.0"
    WEB_PORT: int = 8000
    PACKET_QUEUE_MAX: int = 2000
    PROMISCUOUS_MODE: bool = True
    AUTO_SCAN_ON_STARTUP: bool = True
    MAX_HISTORICAL_PACKETS: int = 1000
    MAX_HISTORICAL_ALERTS: int = 500

Config = SystemConfig()

def setup_logging(verbose: bool = False):
    import logging
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(Config.LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout) if verbose else logging.NullHandler()
        ]
    )

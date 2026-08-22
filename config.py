import os
import logging

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

class Config:
    # Base Directories
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    DB_PATH = os.path.join(DATA_DIR, "network_monitor.db")
    LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
    PID_FILE = os.path.join(BASE_DIR, ".network_monitor.pid")

    # Server Defaults
    WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
    WEB_PORT = int(os.getenv("WEB_PORT", 8000))

    # Queue & History Limits
    PACKET_QUEUE_MAX = 5000
    PACKET_HISTORY_LIMIT = 100
    ALERT_HISTORY_LIMIT = 50
    THROUGHPUT_HISTORY_SECS = 60

    # Threat Detection Thresholds
    PORT_SCAN_WINDOW = 5.0
    PORT_SCAN_THRESHOLD = 10

    SYN_FLOOD_RATE_THRESHOLD = 100
    SYN_ACK_RATIO_MAX = 0.1
    SYN_FLOOD_WINDOW = 1.0

    ICMP_SWEEP_WINDOW = 3.0
    ICMP_SWEEP_THRESHOLD = 5

    DNS_ENTROPY_THRESHOLD = 4.0
    DNS_BURST_THRESHOLD = 50
    DNS_BURST_WINDOW = 60.0

    # Polling & Broadcast Timers (Seconds)
    SOCKET_POLL_INTERVAL = 2.0
    WS_BROADCAST_INTERVAL = 0.5

def setup_logging(verbose: bool = False):
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers = []
    
    file_handler = logging.FileHandler(Config.LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root_logger.addHandler(file_handler)
    
    if verbose:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root_logger.addHandler(stream_handler)
    else:
        root_logger.addHandler(logging.NullHandler())

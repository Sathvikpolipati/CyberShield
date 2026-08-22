import json
import os
import time
from core.models import SecurityAlert, PacketSummary

class SecurityLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.alert_log_file = os.path.join(self.log_dir, "security_alerts.jsonl")

    def log_alert(self, alert: SecurityAlert):
        with open(self.alert_log_file, "a", encoding="utf-8") as f:
            f.write(alert.model_dump_json() + "\n")

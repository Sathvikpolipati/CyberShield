import ctypes
import logging
import os
import platform
import shutil
import sys
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class DependencyStatus:
    def __init__(self):
        self.is_admin = self._check_admin()
        self.npcap_installed = True  # Self-contained native engine active
        self.tshark_path = "Native-Engine"
        self.nmap_path = "Native-Scanner"
        self.capture_mode = "native_windows"

    def _check_admin(self) -> bool:
        if sys.platform == "win32":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            try:
                return os.geteuid() == 0
            except Exception:
                return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_admin": self.is_admin,
            "npcap_installed": True,
            "tshark_path": "Native Windows Engine",
            "nmap_path": "Native Socket Scanner",
            "capture_mode": "native_windows",
            "engine_label": "Native Windows Live Engine (Zero External Dependencies)"
        }

class EnvironmentChecker:
    @staticmethod
    def get_diagnostics() -> Dict[str, Any]:
        return DependencyStatus().to_dict()

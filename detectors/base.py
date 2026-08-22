from abc import ABC, abstractmethod
from typing import List, Dict, Any
from core.models import PacketSummary

class BaseDetector(ABC):
    @abstractmethod
    def analyze(self, packet: PacketSummary) -> List[Dict[str, Any]]:
        pass

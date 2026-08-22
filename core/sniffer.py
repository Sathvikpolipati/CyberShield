import queue
import socket
import threading
import time
import psutil
from typing import Optional, List, Dict, Any
from core.parser import PacketParser
from core.firewall import FirewallManager

class LiveSniffer:
    def __init__(self, packet_queue: queue.Queue, interface: Optional[str] = None):
        self.packet_queue = packet_queue
        self.interface = interface
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.cached_sockets: List[Dict[str, Any]] = []

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True, name="SnifferThread")
        self.thread.start()

    def stop(self):
        self.running = False

    def _sniff_loop(self):
        try:
            from scapy.all import sniff
            def prn(pkt):
                if not self.running:
                    return
                parsed = PacketParser.parse(pkt)
                if FirewallManager.is_ip_blocked(parsed.src_ip):
                    return
                try:
                    self.packet_queue.put_nowait(parsed)
                except queue.Full:
                    pass

            sniff(prn=prn, store=0, stop_filter=lambda _: not self.running)
        except Exception:
            while self.running:
                time.sleep(0.5)

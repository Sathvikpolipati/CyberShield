import datetime
import math
import os
import shutil
import sys
import threading
import time
from collections import deque, Counter
from typing import List, Dict, Any, Optional
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box

from core.parser import PacketSummary, ProtocolType
from core.interface import NetworkInterfaceManager
from core.host_discovery import HostDiscovery
from core.firewall import FirewallManager
from scanners.port_scanner import PortScanner
from reporting.report_generator import SecurityReportGenerator
from config import Config

class TerminalDashboard:
    """
    Military-Grade CyberShield SOC Dashboard.
    Features:
    - 5 Side-by-Side Top Metrics Cards (Packets, Bandwidth, Threats, Active Defense, Protocols).
    - 4-Panel Main Body (Live Packet Stream, Protocol Flow & Top Talkers, Threat Alerts, Process Sockets / LAN Assets).
    - Native Mouse Wheel Scrolling on Windows & Linux across all views.
    - Responsive Auto-Scaling: Dynamically adjusts to window resizing, minimize, and maximize operations.
    - Dedicated Threat Center ('threats'): Full-screen interactive threat intelligence with one-click IP blocking.
    - Top Talkers & Process Sockets Inspectors with live scrolling.
    - Scrollable categorized Help & Operational User Manual.
    """
    def __init__(self, mode: str = "Real-Time Network Traffic Analyzer"):
        self.console = Console(force_terminal=True, legacy_windows=False)
        self.mode = mode
        self.start_time = time.time()
        self.net_info = NetworkInterfaceManager.get_primary_interface()

        # Ring buffers (500 packets history)
        self.recent_packets: deque = deque(maxlen=500)
        self.recent_alerts: deque = deque(maxlen=200)
        self.active_hosts: List[Dict[str, Any]] = []
        self.current_sockets: List[Dict[str, Any]] = []
        self.top_talkers: Counter = Counter()
        self.talker_bytes: Counter = Counter()

        # View mode: 'dash' (Main HUD), 'threats' (Threat Center), 'talkers' (Top Talkers), 'sockets' (Process Sockets)
        self.view_mode: str = "dash"

        # Scroll offsets
        self.scroll_offsets = {
            "dash": 0,
            "threats": 0,
            "talkers": 0,
            "sockets": 0,
            "help": 0
        }

        # Interactive command bar
        self.command_buffer: str = ""
        self.command_history: List[str] = []
        self.history_idx: int = -1
        self.status_message: str = "CyberShield SOC Active. Scroll with [bold yellow]Mouse Wheel[/bold yellow] or type [bold cyan]help[/bold cyan], [bold red]threats[/bold red], [bold yellow]talkers[/bold yellow], [bold green]scan[/bold green], or [bold red]kill[/bold red]."
        self.status_msg_time = time.time()

        # States
        self.is_scanning: bool = False
        self.show_help: bool = False
        self.radar_frame: int = 0
        self.should_exit: bool = False

        # Telemetry counters
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "OTHER": 0}
        self.threat_count = 0
        self.active_threats = 0
        self.protocol_filter: Optional[str] = None
        self.lock = threading.Lock()

    def update_packet(self, pkt: PacketSummary):
        with self.lock:
            if self.protocol_filter and pkt.protocol.value != self.protocol_filter:
                return
            self.recent_packets.appendleft(pkt)
            self.total_packets += 1
            self.total_bytes += pkt.length
            pname = pkt.protocol.value
            self.protocols[pname] = self.protocols.get(pname, 0) + 1
            if pkt.src_ip:
                self.top_talkers[pkt.src_ip] += 1
                self.talker_bytes[pkt.src_ip] += pkt.length
            if pkt.dst_ip:
                self.top_talkers[pkt.dst_ip] += 1
                self.talker_bytes[pkt.dst_ip] += pkt.length

    def update_alert(self, alert: dict):
        with self.lock:
            self.recent_alerts.appendleft(alert)
            self.threat_count += 1
            self.active_threats += 1
            att = alert.get('attacker_ip', 'unknown')
            rule = alert.get('rule_name') or alert.get('rule', 'Threat')
            self.set_status(f"[bold red]🚨 THREAT DETECTED:[/bold red] {rule} from [bold yellow]{att}[/bold yellow] (Type [bold white on red] block {att} [/bold white on red] to ban)")

    def update_sockets_from_sniffer(self, sockets_list: List[Dict[str, Any]]):
        with self.lock:
            self.current_sockets = sockets_list

    def scroll_up(self, delta: int = 3):
        """Scrolls up the active view."""
        with self.lock:
            mode = "help" if self.show_help else self.view_mode
            cur = self.scroll_offsets.get(mode, 0)
            if mode == "help":
                total = 26
            elif mode == "threats":
                total = len(self.recent_alerts)
            elif mode == "talkers":
                total = len(self.top_talkers)
            elif mode == "sockets":
                total = len(self.current_sockets)
            else:
                total = len(self.recent_packets)

            max_offset = max(0, total - 6)
            new_offset = min(cur + delta, max_offset)
            self.scroll_offsets[mode] = new_offset
            if new_offset > 0:
                self.set_status(f"[bold yellow]▲ Scrolled {mode.upper()}: viewing offset -{new_offset} (Showing {new_offset+1}-{min(new_offset+10, max(total,1))} of {total}). Scroll down or type 'live' to return.[/bold yellow]")

    def scroll_down(self, delta: int = 3):
        """Scrolls down the active view."""
        with self.lock:
            mode = "help" if self.show_help else self.view_mode
            cur = self.scroll_offsets.get(mode, 0)
            new_offset = max(0, cur - delta)
            self.scroll_offsets[mode] = new_offset
            if new_offset == 0:
                self.set_status(f"[bold green]● LIVE / TOP {mode.upper()} VIEW ACTIVE.[/bold green]")
            else:
                self.set_status(f"[bold yellow]▼ Scrolled {mode.upper()}: offset -{new_offset}[/bold yellow]")

    def scroll_live(self):
        """Snaps back to top/live stream."""
        with self.lock:
            mode = "help" if self.show_help else self.view_mode
            self.scroll_offsets[mode] = 0
            self.set_status(f"[bold green]● Resumed TOP / LIVE view of {mode.upper()}.[/bold green]")

    def toggle_view(self):
        """Cycles through views (Tab key)."""
        with self.lock:
            if self.view_mode == "dash":
                self.view_mode = "threats"
            elif self.view_mode == "threats":
                self.view_mode = "talkers"
            elif self.view_mode == "talkers":
                self.view_mode = "sockets"
            else:
                self.view_mode = "dash"
            self.show_help = False
            self.scroll_offsets[self.view_mode] = 0
            self.set_status(f"[bold cyan]Switched view to [{self.view_mode.upper()}].[/bold cyan]")

    def set_status(self, msg: str):
        self.status_message = msg
        self.status_msg_time = time.time()

    def handle_char(self, ch: str):
        """Processes typed characters into the command buffer."""
        with self.lock:
            if ch in ["\x03", "\x04"]:  # Ctrl+C / Ctrl+D
                self.should_exit = True
                return

            if ch in ["\r", "\n", "\r\n"]:
                cmd_to_run = self.command_buffer.strip()
                if cmd_to_run:
                    self.command_history.append(cmd_to_run)
                    self.history_idx = len(self.command_history)
                self.command_buffer = ""
                if cmd_to_run:
                    self.execute_command(cmd_to_run)
            elif ch in ["\x08", "\x7f", "\b"]:  # Backspace
                self.command_buffer = self.command_buffer[:-1]
            elif ch == "\t":  # Tab key
                self.toggle_view()
            elif len(ch) == 1 and (ch.isprintable() or ch == " "):
                if ch not in ["\x1b", "\x00", "\xe0"]:
                    self.command_buffer += ch

    def history_up(self):
        with self.lock:
            if self.command_history and self.history_idx > 0:
                self.history_idx -= 1
                self.command_buffer = self.command_history[self.history_idx]

    def history_down(self):
        with self.lock:
            if self.command_history and self.history_idx < len(self.command_history) - 1:
                self.history_idx += 1
                self.command_buffer = self.command_history[self.history_idx]
            else:
                self.history_idx = len(self.command_history)
                self.command_buffer = ""

    def execute_command(self, cmd_text: str):
        cmd = cmd_text.strip().lower()
        if not cmd:
            return

        parts = cmd.split()
        action = parts[0]

        # Linux Exit
        if action in ["kill", "pkill", "killall", "exit", "quit", "q", "stop", "x"]:
            self.should_exit = True
            return

        # Dedicated Threat Management & Defense View
        elif action in ["threats", "threat", "alerts", "alert", "defense", "nids"]:
            self.view_mode = "threats"
            self.show_help = False
            self.scroll_offsets["threats"] = 0
            self.set_status(f"[bold red]THREAT CENTER ACTIVE ({len(self.recent_alerts)} incidents). Type 'block <ip>' to ban attacker, or 'dash' to return.[/bold red]")

        # Active Firewall IP Blocking
        elif action in ["block", "ban", "isolate", "drop"] and len(parts) > 1:
            target_ip = parts[1]
            res = FirewallManager.block_ip(target_ip, reason="Admin Command in SOC")
            if res.get("success"):
                self.set_status(f"[bold white on red] 🛑 BLOCKED: [/bold white on red] Attacker [bold yellow]{target_ip}[/bold yellow] is now banned from the network!")
            else:
                self.set_status(f"[bold red]Block failed: {res.get('message')}[/bold red]")

        # Active Firewall IP Unblocking
        elif action in ["unblock", "unban", "allow"] and len(parts) > 1:
            target_ip = parts[1]
            res = FirewallManager.unblock_ip(target_ip)
            self.set_status(f"[bold green]✓ UNBLOCKED: Host {target_ip} access restored.[/bold green]")

        # Auto-Block Toggle
        elif action in ["autoblock", "auto-block", "mitigate"]:
            if len(parts) > 1:
                FirewallManager.autoblock_enabled = (parts[1] in ["on", "true", "1", "enable"])
            else:
                FirewallManager.autoblock_enabled = not FirewallManager.autoblock_enabled
            state_str = "[bold green]ENABLED (Auto-blocking HIGH/CRIT threats)[/bold green]" if FirewallManager.autoblock_enabled else "[bold yellow]DISABLED[/bold yellow]"
            self.set_status(f"Active Defense Auto-Block is now {state_str}.")

        # Deep Threat Inspection / Nmap Audit on Attacker Host
        elif action in ["inspect", "nmap", "ports", "port", "p"] and len(parts) > 1:
            target_ip = parts[1]
            self.trigger_port_scan(target_ip)

        # Linux Process Inspector
        elif action in ["ps", "top", "htop", "sockets", "sock", "process"]:
            self.view_mode = "sockets"
            self.show_help = False
            self.scroll_offsets["sockets"] = 0
            self.set_status(f"[bold cyan]PROCESS SOCKETS INSPECTOR active ({len(self.current_sockets)} sockets). Scroll with mouse wheel or type 'dash' to return.[/bold cyan]")

        # Linux Top Talkers & Bandwidth
        elif action in ["talkers", "talk", "top-talkers", "t", "who", "w", "endpoints"]:
            self.view_mode = "talkers"
            self.show_help = False
            self.scroll_offsets["talkers"] = 0
            self.set_status(f"[bold cyan]TOP TALKER ENDPOINTS INSPECTOR active ({len(self.top_talkers)} active hosts). Scroll with mouse wheel or type 'dash' to return.[/bold cyan]")

        # Main Packet Dashboard HUD
        elif action in ["dash", "main", "hud", "home", "tcpdump", "wireshark", "tshark"]:
            self.view_mode = "dash"
            self.show_help = False
            self.scroll_offsets["dash"] = 0
            self.set_status("[bold green]Switched to Main SOC Packet Monitor HUD.[/bold green]")

        # Linux ARP / Subnet Discovery
        elif action in ["scan", "s", "arp", "arp-scan", "netdiscover", "nmap-scan"]:
            self.show_help = False
            self.trigger_subnet_scan()

        # Linux Interface & Network Config
        elif action in ["ifconfig", "ip", "ip-addr", "route"]:
            self.set_status(f"[bold cyan]NIC: {self.net_info['iface_name']} | IP: {self.net_info['local_ip']} | Subnet CIDR: {self.net_info['subnet_cidr']}[/bold cyan]")

        # Help / Manual
        elif action in ["help", "man", "h", "?", "info"]:
            self.show_help = not self.show_help
            self.scroll_offsets["help"] = 0
            status_txt = "[bold cyan]Opened Scrollable Command Manual. Scroll with mouse wheel or type 'help' to exit.[/bold cyan]" if self.show_help else "[bold green]Closed Help Manual. Back to live monitor.[/bold green]"
            self.set_status(status_txt)

        # Linux Tail / Live Feed
        elif action in ["live", "tail", "now", "l", "top"]:
            self.scroll_live()

        # Navigation & Scrolling
        elif action in ["up", "pgup", "u", "less"]:
            delta = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3
            self.scroll_up(delta)
        elif action in ["down", "pgdn", "d", "more"]:
            delta = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3
            self.scroll_down(delta)

        # Export PDF Report
        elif action in ["pdf", "export", "e", "report"]:
            self.trigger_pdf_export()

        # Protocol Filtering
        elif action in ["filter", "f", "grep", "proto"] and len(parts) > 1:
            self.protocol_filter = parts[1].upper()
            self.set_status(f"[bold cyan]Protocol filter active: {self.protocol_filter} (Type 'clear' to reset)[/bold cyan]")

        # Clear Buffer
        elif action in ["clear", "c", "cls", "reset"]:
            self.protocol_filter = None
            self.show_help = False
            self.scroll_offsets[self.view_mode] = 0
            self.recent_packets.clear()
            self.set_status("[bold green]Packet buffer cleared. Filter reset to ALL protocols.[/bold green]")

        else:
            self.set_status(f"[bold red]Unknown command '{action}'. Type 'help' to view all operations.[/bold red]")

    def trigger_subnet_scan(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.radar_frame = 0
        self.set_status(f"[bold green]RADAR ACTIVE: Scanning local subnet {self.net_info['subnet_cidr']} (ARP sweep)...[/bold green]")

        def scan_worker():
            try:
                hosts = HostDiscovery.scan_subnet(self.net_info["subnet_cidr"])
                with self.lock:
                    self.active_hosts = hosts
                self.set_status(f"[bold green]✓ ARP Discovery Finished! Found {len(hosts)} active devices on {self.net_info['subnet_cidr']}.[/bold green]")
            except Exception as e:
                self.set_status(f"[bold red]Scan error: {e}[/bold red]")
            finally:
                time.sleep(3.0)
                self.is_scanning = False

        threading.Thread(target=scan_worker, daemon=True).start()

    def trigger_port_scan(self, target_ip: str):
        if not NetworkInterfaceManager.is_in_local_subnet(target_ip, self.net_info["subnet_cidr"]):
            self.set_status(f"[bold red]BLOCKED: Target {target_ip} is outside local subnet {self.net_info['subnet_cidr']}.[/bold red]")
            return

        self.set_status(f"[bold yellow]Auditing open ports & service fingerprint on {target_ip}...[/bold yellow]")
        def port_worker():
            try:
                res = PortScanner.scan_target(target_ip)
                cnt = res.get("open_ports_count", 0)
                score = res.get("risk_score", 100)
                ports_list = ", ".join(f"{p['port']}/{p['service']}" for p in res.get("open_ports", [])[:5])
                self.set_status(f"[bold green]Audit for {target_ip}: {cnt} open ports [{ports_list}] (Security Score: {score}/100)[/bold green]")
            except Exception as e:
                self.set_status(f"[bold red]Port scan failed: {e}[/bold red]")
        threading.Thread(target=port_worker, daemon=True).start()

    def trigger_pdf_export(self):
        self.set_status("[bold cyan]Exporting Executive Security PDF directly to your Downloads folder...[/bold cyan]")
        def pdf_worker():
            try:
                saved_path = SecurityReportGenerator.generate_pdf_report()
                self.set_status(f"[bold green]✓ PDF Exported directly to Downloads: {saved_path}[/bold green]")
            except Exception as e:
                self.set_status(f"[bold red]PDF export failed: {e}[/bold red]")
        threading.Thread(target=pdf_worker, daemon=True).start()

    def render_header(self) -> Panel:
        uptime = int(time.time() - self.start_time)
        hrs, rem = divmod(uptime, 3600)
        mins, secs = divmod(rem, 60)
        time_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"

        title = Text()
        title.append(" 🛡️  CYBERSHIELD SOC ", style="bold cyan")
        title.append("• NETWORK TRAFFIC ANALYZER & DEFENSE ", style="bold green")
        title.append(f"| NIC: {self.net_info['iface_name']} ({self.net_info['local_ip']}) ", style="bold yellow")
        title.append(f"| Subnet: {self.net_info['subnet_cidr']} ", style="bold magenta")
        title.append(f"| View: [{self.view_mode.upper()}] ", style="bold white on blue")
        title.append(f"| {time_str} ", style="dim white")

        return Panel(
            Align.center(title),
            box=box.HORIZONTALS,
            style="cyan",
            padding=(0, 1)
        )

    def render_metrics_bar(self) -> Columns:
        uptime = max(time.time() - self.start_time, 1.0)
        pps = self.total_packets / uptime
        kbps = (self.total_bytes / 1024) / uptime

        kb_total = self.total_bytes / 1024
        mb_total = kb_total / 1024
        bw_str = f"{mb_total:.2f} MB" if mb_total >= 1.0 else f"{kb_total:.1f} KB"

        # Threat Posture
        if self.active_threats > 3:
            threat_color = "bold red"
            posture = "CRITICAL"
        elif self.active_threats > 0:
            threat_color = "bold yellow"
            posture = "ELEVATED"
        else:
            threat_color = "bold green"
            posture = "NORMAL"

        # Active Defense Status
        blocked_count = len(FirewallManager._blocked_ips)
        if blocked_count > 0:
            def_color = "bold green"
            def_text = f"{blocked_count} BANNED 🛑"
            def_sub = "Active Defense"
        elif FirewallManager.autoblock_enabled:
            def_color = "bold cyan"
            def_text = "AUTO-SHIELD"
            def_sub = "Active Defense"
        else:
            def_color = "yellow"
            def_text = "STANDBY"
            def_sub = "'threats' / 'block'"

        # Protocol Breakdown
        total_p = max(sum(self.protocols.values()), 1)
        tcp_pct = int((self.protocols["TCP"] / total_p) * 100)
        udp_pct = int((self.protocols["UDP"] / total_p) * 100)
        https_pct = int((self.protocols["HTTPS"] / total_p) * 100)

        # 5 Balanced Cards Placed Side-by-Side
        p1 = Panel(f"[bold white]{self.total_packets:,}[/bold white]\n[cyan]{pps:.1f} pkt/s[/cyan]", title="[bold cyan]PACKETS[/bold cyan]", border_style="cyan", box=box.ROUNDED, padding=(0, 1))
        p2 = Panel(f"[bold white]{bw_str}[/bold white]\n[blue]{kbps:.1f} KB/s[/blue]", title="[bold blue]BANDWIDTH[/bold blue]", border_style="blue", box=box.ROUNDED, padding=(0, 1))
        p3 = Panel(f"[{threat_color}]{posture}[/{threat_color}]\n[{threat_color}]{self.threat_count} Alerts[/{threat_color}]", title="[bold red]THREATS[/bold red]", border_style="red" if self.active_threats > 0 else "green", box=box.ROUNDED, padding=(0, 1))
        p4 = Panel(f"[{def_color}]{def_text}[/{def_color}]\n[dim white]{def_sub}[/dim white]", title="[bold green]DEFENSE[/bold green]", border_style="green" if blocked_count > 0 else "blue", box=box.ROUNDED, padding=(0, 1))
        p5 = Panel(f"[cyan]TCP:{tcp_pct}%[/cyan] [blue]UDP:{udp_pct}%[/blue]\n[yellow]HTTPS:{https_pct}%[/yellow] [green]DNS:{self.protocols['DNS']}[/green]", title="[bold magenta]PROTOCOLS[/bold magenta]", border_style="magenta", box=box.ROUNDED, padding=(0, 1))
        return Columns([p1, p2, p3, p4, p5], expand=True)

    def render_dedicated_threats_view(self) -> Panel:
        """Renders full-screen interactive threat defense & mitigation center."""
        table = Table(expand=True, box=box.ROUNDED, show_lines=True)
        table.add_column("Incident #", style="bold yellow", width=12, justify="center")
        table.add_column("Severity", style="bold", width=10, justify="center")
        table.add_column("Attack Signature / Rule", style="bold white", width=28)
        table.add_column("Attacker IP Endpoint", style="bold red", width=22)
        table.add_column("Target Host", style="cyan", width=20)
        table.add_column("Defense Status & Action", style="bold", ratio=1)

        with self.lock:
            all_alerts = list(self.recent_alerts)
            offset = self.scroll_offsets.get("threats", 0)
            view_alerts = all_alerts[offset : offset + 14]

        for i, a in enumerate(view_alerts, start=offset + 1):
            sev = a.get("severity", "HIGH")
            if sev == "CRITICAL":
                s_tag = "[bold white on red] CRITICAL [/bold white on red]"
            elif sev == "HIGH":
                s_tag = "[bold red] HIGH [/bold red]"
            else:
                s_tag = "[bold yellow] MEDIUM [/bold yellow]"

            rule = a.get("rule_name") or a.get("rule", "Unknown Threat")
            att = a.get("attacker_ip", "0.0.0.0")
            tgt = a.get("target_ip", "0.0.0.0")

            if FirewallManager.is_ip_blocked(att):
                status_act = "[bold white on red] BLOCKED 🛑 [/bold white on red] [dim](Type 'unblock " + att + "' to allow)[/dim]"
            else:
                status_act = f"[bold yellow]ACTIVE THREAT[/bold yellow] [bold green](Type 'block {att}' to ban)[/bold green]"

            table.add_row(f"INC-{i:03d}", s_tag, rule, att, tgt, status_act)

        if not view_alerts:
            table.add_row("SAFE", "[bold green]NORMAL[/bold green]", "Zero active threat incidents detected.", "--", "--", "[bold green]All Network Endpoints Secure[/bold green]")

        blocked = FirewallManager.get_all_blocked()
        blocked_txt = ", ".join(b["ip"] for b in blocked[:4]) if blocked else "None"

        total = max(len(all_alerts), 1)
        title_tag = f"[bold red] 🚨 CYBERSHIELD ACTIVE THREAT CENTER & DEFENSE [bold yellow](Incidents: {len(all_alerts)} | Blocked IPs: {len(blocked)} [{blocked_txt}] | Type 'block <ip>' | 'dash' for HUD)[/bold yellow] [/bold red]"
        return Panel(table, title=title_tag, border_style="red", box=box.HEAVY)

    def render_radar_modal(self) -> Panel:
        self.radar_frame += 1
        radar_chars = ["◜", "◝", "◞", "◟", "◐", "◓", "◑", "◒"]
        spin = radar_chars[self.radar_frame % len(radar_chars)]

        radar_art = [
            f"       [bold green]╔═════════════════════════════════════════════════════════════╗[/bold green]",
            f"       [bold green]║[/bold green]             [bold cyan]📡 ACTIVE NETWORK RADAR SWEEP {spin}[/bold cyan]               [bold green]║[/bold green]",
            f"       [bold green]╠═════════════════════════════════════════════════════════════╣[/bold green]",
            f"       [bold green]║[/bold green]                    [dim cyan]  .   :   .  [/dim cyan]                         [bold green]║[/bold green]",
            f"       [bold green]║[/bold green]                  [cyan]. '  [bold green]●[/bold green]  .   ' .[/cyan]                       [bold green]║[/bold green]",
            f"       [bold green]║[/bold green]                [cyan]:    .   |   .    :[/cyan]                     [bold green]║[/bold green]",
            f"       [bold green]║[/bold green]               [cyan]:  .-----[bold yellow]+[/bold yellow]-----.  :[/cyan]                    [bold green]║[/bold green]",
            f"       [bold green]║[/bold green]                [cyan]:    .   |   .    :[/cyan]                     [bold green]║[/bold green]",
            f"       [bold green]║[/bold green]                  [cyan]. '  .   ' [bold green]●[/bold green] .[/cyan]                       [bold green]║[/bold green]",
            f"       [bold green]║[/bold green]                    [dim cyan]  '   :   '  [/dim cyan]                         [bold green]║[/bold green]",
            f"       [bold green]╠═════════════════════════════════════════════════════════════╣[/bold green]",
            f"       [bold green]║[/bold green] Target Subnet: [yellow]{self.net_info['subnet_cidr']:<18}[/yellow] | Discovered: [green]{len(self.active_hosts):<2} Hosts[/green]       [bold green]║[/bold green]",
            f"       [bold green]╚═════════════════════════════════════════════════════════════╝[/bold green]"
        ]
        text = "\n".join(radar_art)
        return Panel(Align.center(text), title="[bold green on black] 📡 RADAR SCAN POPUP MODAL (ACTIVE) [/bold green on black]", border_style="green", box=box.HEAVY)

    def render_help_modal(self) -> Panel:
        """Renders comprehensive, fully-scrollable user manual categorized by operational command."""
        all_commands = [
            # 1. Host Discovery & Scanning Operations
            ("[bold green]1. RECON & SCAN OPERATIONS[/bold green]", "", ""),
            ("scan, arp, netdiscover", "scan", "Triggers live animated subnet ARP radar sweep to discover LAN hosts"),
            ("nmap, inspect, ports", "nmap <target_ip>", "Performs deep TCP/UDP port audit & service fingerprinting (e.g. `nmap 192.168.149.1`)"),
            ("ifconfig, ip, route", "ifconfig", "Displays active network adapter name, local IP, MAC address, and subnet CIDR boundary"),
            
            # 2. Threat Defense & Active Mitigation Operations
            ("[bold red]2. THREAT DEFENSE & MITIGATION[/bold red]", "", ""),
            ("threats, alerts, nids", "threats", "Opens full-screen Threat Intelligence & Defense Center with incident triage"),
            ("block, ban, isolate", "block <target_ip>", "Actively blocks attacker IP via Firewall (netsh / iptables) + drops packets in-engine"),
            ("unblock, allow, unban", "unblock <target_ip>", "Removes firewall block rule and restores network access for specified IP"),
            ("autoblock on / off", "autoblock on", "Enables real-time automatic banning of CRITICAL & HIGH severity threats"),

            # 3. Protocol Flow & Traffic Filter Operations
            ("[bold magenta]3. PROTOCOL FLOW & FILTERING[/bold magenta]", "", ""),
            ("filter, grep, proto", "filter <proto>", "Filters packet stream and flow matrix by protocol (e.g. `filter HTTPS`, `filter DNS`, `filter TCP`, `filter UDP`)"),
            ("clear, reset, cls", "clear", "Clears packet stream buffer and resets all active protocol filters"),
            ("dash, home, tcpdump", "dash", "Switches back to main 4-panel SOC Dashboard HUD"),

            # 4. Process Sockets & OS Telemetry
            ("[bold cyan]4. PROCESS SOCKETS & OS INSPECTION[/bold cyan]", "", ""),
            ("ps, top, sockets, sock", "ps", "Opens full-screen Process Sockets Inspector (PID, Process Name, Local/Remote Endpoints, State)"),

            # 5. Top Talkers & Bandwidth Matrix
            ("[bold yellow]5. TOP TALKERS & BANDWIDTH[/bold yellow]", "", ""),
            ("talkers, who, endpoints", "talkers", "Opens dedicated full-screen Top Talkers matrix (Host scopes, packet volume, flow share bars)"),

            # 6. Reporting, Scrolling & System Controls
            ("[bold white]6. REPORTING & SYSTEM CONTROLS[/bold white]", "", ""),
            ("pdf, export, report", "pdf", "Generates executive Cyber Security PDF Audit Report directly into `Downloads/`"),
            ("up, pgup [N]", "up 10", "Scrolls active view (help, packets, threats, talkers, sockets) upward through history"),
            ("down, pgdn [N]", "down 10", "Scrolls active view downward toward latest data"),
            ("live, tail", "live", "Snaps directly back to real-time incoming packet stream (● LIVE) or top of manual"),
            ("kill, pkill, Ctrl+C", "kill", "Terminates sniffer process and stops all background threads cleanly")
        ]

        total_cmds = len(all_commands)
        offset = self.scroll_offsets.get("help", 0)
        view_cmds = all_commands[offset : offset + 14]

        table = Table(expand=True, box=box.ROUNDED, show_lines=True)
        table.add_column("Command / Shorthand", style="bold green", width=26)
        table.add_column("Syntax Example", style="yellow", width=22)
        table.add_column("Operational Function & Security Description", style="white", ratio=1)

        for col1, col2, col3 in view_cmds:
            table.add_row(col1, col2, col3)

        title_tag = f"[bold cyan] 📖 CYBERSHIELD COMPLETE OPERATIONAL USER MANUAL [bold yellow](Viewing {offset+1}-{min(offset+14, total_cmds)} of {total_cmds} operations | Scroll with mouse | 'help' to exit)[/bold yellow] [/bold cyan]"
        return Panel(table, title=title_tag, border_style="cyan", box=box.HEAVY)

    def render_packet_table(self, max_rows: int = 10) -> Table:
        table = Table(expand=True, box=box.SIMPLE_HEAD, show_lines=False)
        table.add_column("Time", style="dim cyan", width=9, no_wrap=True)
        table.add_column("Proto", style="bold", width=6)
        table.add_column("Source", style="cyan", width=22)
        table.add_column("Target", style="yellow", width=22)
        table.add_column("Bytes", style="dim", justify="right", width=6)
        table.add_column("Summary Info", style="white", ratio=1)

        proto_colors = {
            ProtocolType.TCP: "[bold cyan]TCP[/bold cyan]",
            ProtocolType.UDP: "[bold blue]UDP[/bold blue]",
            ProtocolType.ICMP: "[bold magenta]ICMP[/bold magenta]",
            ProtocolType.DNS: "[bold green]DNS[/bold green]",
            ProtocolType.HTTP: "[bold yellow]HTTP[/bold yellow]",
            ProtocolType.HTTPS: "[bold yellow]HTTPS[/bold yellow]",
            ProtocolType.OTHER: "[dim white]OTHER[/dim white]"
        }

        with self.lock:
            all_pkts = list(self.recent_packets)
            start = self.scroll_offsets.get("dash", 0)
            pkts = all_pkts[start : start + max_rows]

        for p in pkts:
            t_str = p.formatted_time.split(".")[0] if p.formatted_time else "--:--:--"
            pr_label = proto_colors.get(p.protocol, str(p.protocol.value))
            src_str = f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip
            dst_str = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip
            table.add_row(t_str, pr_label, src_str, dst_str, str(p.length), p.summary[:45])

        if not pkts:
            table.add_row("--:--:--", "--", "Listening...", "Waiting for packets...", "0", "Native Sniffer Active")

        return table

    def render_dedicated_talkers_view(self) -> Panel:
        """Renders full-screen interactive scrollable top talkers inspector."""
        table = Table(expand=True, box=box.ROUNDED, show_lines=True)
        table.add_column("Rank", style="bold yellow", width=6, justify="center")
        table.add_column("IP Address / Endpoint", style="bold cyan", width=24)
        table.add_column("Host Scope / Type", style="white", width=22)
        table.add_column("Packets Sent/Recv", style="bold white", width=18, justify="right")
        table.add_column("Bandwidth Vol", style="bold green", width=16, justify="right")
        table.add_column("Flow Activity Bar", style="bold magenta", ratio=1)

        def make_bar(pct: int) -> str:
            filled = int(pct / 10)
            return f"[green]{'█' * filled}{'░' * (10 - filled)}[/green] {pct}%"

        with self.lock:
            all_talkers = self.top_talkers.most_common()
            offset = self.scroll_offsets.get("talkers", 0)
            view_talkers = all_talkers[offset : offset + 14]
            total_vol = max(sum(self.talker_bytes.values()), 1)

        for i, (ip, count) in enumerate(view_talkers, start=offset + 1):
            b_cnt = self.talker_bytes.get(ip, count * 128)
            mb = b_cnt / (1024 * 1024)
            kb = b_cnt / 1024
            bw_str = f"{mb:.2f} MB" if mb >= 1.0 else f"{kb:.1f} KB"
            pct = int((b_cnt / total_vol) * 100)
            
            if ip == self.net_info["local_ip"]:
                htype = "[bold green]Local Host (This PC)[/bold green]"
            elif ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
                htype = "[cyan]LAN Device (Local Subnet)[/cyan]"
            elif ":" in ip:
                htype = "[magenta]IPv6 Remote Endpoint[/magenta]"
            else:
                htype = "[yellow]WAN / Remote Internet[/yellow]"

            table.add_row(f"#{i}", ip, htype, f"{count:,} pkts", bw_str, make_bar(min(pct * 2, 100)))

        if not view_talkers:
            table.add_row("#1", self.net_info["local_ip"], "Local Host", f"{self.total_packets:,} pkts", "1.0 KB", make_bar(100))

        total = max(len(all_talkers), 1)
        title_tag = f"[bold cyan] 📡 TOP TALKER ENDPOINTS INSPECTOR [bold yellow](Viewing {offset+1}-{min(offset+14, total)} of {total} endpoints | Scroll with mouse | 'dash' to return)[/bold yellow] [/bold cyan]"
        return Panel(table, title=title_tag, border_style="yellow", box=box.HEAVY)

    def render_traffic_flow_matrix(self) -> Panel:
        """Side-by-side Protocol Distribution & Top Talkers."""
        total_p = max(sum(self.protocols.values()), 1)

        def make_bar(pct: int, color: str = "cyan") -> str:
            filled = int(pct / 10)
            return f"[{color}]{'█' * filled}{'░' * (10 - filled)}[/{color}] {pct}%"

        p_table = Table(box=box.SIMPLE, show_header=False, expand=True, padding=(0, 1))
        p_table.add_column("Proto", style="bold white", width=7)
        p_table.add_column("Activity", width=16)
        p_table.add_column("Count", style="dim cyan", justify="right")

        for proto, color in [("TCP", "cyan"), ("HTTPS", "yellow"), ("DNS", "green"), ("UDP", "blue"), ("ICMP", "magenta")]:
            cnt = self.protocols.get(proto, 0)
            pct = int((cnt / total_p) * 100)
            p_table.add_row(proto, make_bar(pct, color), f"{cnt:,} pkts")

        t_table = Table(box=box.SIMPLE, show_header=True, expand=True, padding=(0, 1))
        t_table.add_column("Top Active Host", style="bold yellow", width=18)
        t_table.add_column("Flow Activity", style="green")

        with self.lock:
            top_talkers_list = self.top_talkers.most_common(10)

        for ip, count in top_talkers_list[:4]:
            pct_flow = int((count / max(self.total_packets * 2, 1)) * 100)
            t_table.add_row(ip[:17], make_bar(min(pct_flow * 2, 100), "green"))

        if not top_talkers_list:
            t_table.add_row(self.net_info["local_ip"], make_bar(100, "green"))

        matrix_cols = Columns([
            Panel(p_table, title="[bold magenta]📊 Protocol Flow Share (Type 'filter <proto>')[/bold magenta]", border_style="magenta", box=box.ROUNDED),
            Panel(t_table, title="[bold yellow]📡 Top Talkers (Type 'talkers')[/bold yellow]", border_style="yellow", box=box.ROUNDED)
        ], expand=True)

        return Panel(
            matrix_cols,
            title="[bold cyan]⚡ Live Network Traffic Flow & Protocol Activity Matrix[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED
        )

    def render_dedicated_sockets_view(self) -> Panel:
        """Renders full-screen interactive process sockets inspector."""
        table = Table(expand=True, box=box.ROUNDED, show_lines=True)
        table.add_column("Proto", style="bold cyan", width=8)
        table.add_column("PID", style="bold yellow", width=10)
        table.add_column("Process Name / Application", style="bold white", width=28)
        table.add_column("Local IP & Port", style="green", width=26)
        table.add_column("Remote IP & Port", style="magenta", width=26)
        table.add_column("State", style="bold", width=14)

        with self.lock:
            all_socks = list(self.current_sockets)
            offset = self.scroll_offsets.get("sockets", 0)
            view_socks = all_socks[offset : offset + 16]

        for s in view_socks:
            st = s["state"]
            st_styled = f"[bold green]{st}[/bold green]" if st == "LISTEN" else (f"[bold cyan]{st}[/bold cyan]" if st == "ESTABLISHED" else f"[dim]{st}[/dim]")
            p_display = s["pname"] if s["pname"] != "System" else "System / Service"
            table.add_row(s["proto"], str(s["pid"]), p_display, s["local"], s["remote"], st_styled)

        if not view_socks:
            table.add_row("TCP", "--", "Active Socket Monitor", "0.0.0.0:0", "0.0.0.0:0", "LISTEN")

        total = max(len(all_socks), 1)
        title_tag = f"[bold cyan] 💻 PROCESS SOCKETS INSPECTOR [bold yellow](Viewing {offset+1}-{min(offset+16, total)} of {total} sockets | Scroll with mouse | 'dash' to return)[/bold yellow] [/bold cyan]"
        return Panel(table, title=title_tag, border_style="cyan", box=box.HEAVY)

    def render_alerts_table(self, max_rows: int = 8) -> Table:
        table = Table(expand=True, box=box.SIMPLE_HEAD, show_lines=False)
        table.add_column("Sev", style="bold", width=8)
        table.add_column("Rule / Threat Signature", style="white", ratio=1)
        table.add_column("Attacker -> Target", style="yellow", width=30)

        with self.lock:
            alts = list(self.recent_alerts)[:max_rows]

        for a in alts:
            sev = a.get("severity", "HIGH")
            s_tag = "[bold red on white] CRIT [/bold red on white]" if sev == "CRITICAL" else ("[bold red] HIGH [/bold red]" if sev == "HIGH" else "[bold yellow] MED [/bold yellow]")
            rule = a.get("rule_name") or a.get("rule", "Anomaly")
            att = a.get("attacker_ip", "0.0.0.0")
            tgt = a.get("target_ip", "0.0.0.0")
            
            if FirewallManager.is_ip_blocked(att):
                rule = f"{rule} [bold red](BLOCKED 🛑)[/bold red]"

            table.add_row(s_tag, rule, f"{att} -> {tgt}")

        if not alts:
            table.add_row("[bold green]SAFE[/bold green]", "Zero active threat incidents detected.", "Traffic Nominal")

        return table

    def render_hosts_table(self, max_rows: int = 8) -> Table:
        table = Table(expand=True, box=box.SIMPLE_HEAD, show_lines=False)
        table.add_column("IP Address", style="bold cyan", width=16)
        table.add_column("Hostname", style="white", width=18)
        table.add_column("Hardware Vendor", style="green", ratio=1)
        table.add_column("Last Seen", style="dim white", width=10)

        with self.lock:
            hosts = list(self.active_hosts)[:max_rows]

        for h in hosts:
            last = h.get("last_seen", "Just now")
            if len(str(last)) > 8:
                last = str(last)[11:19]
            table.add_row(h.get("ip", "--"), h.get("hostname", "Host")[:16], h.get("vendor", "OEM Device")[:20], last)

        if not hosts:
            table.add_row("--", "Type 'scan' & press Enter", "No LAN devices scanned yet", "--")

        return table

    def render_sockets_table(self, max_rows: int = 8) -> Table:
        table = Table(expand=True, box=box.SIMPLE_HEAD, show_lines=False)
        table.add_column("Proto", style="bold cyan", width=6)
        table.add_column("PID", style="yellow", width=8)
        table.add_column("Process Name", style="white", width=18)
        table.add_column("Local Endpoint", style="yellow", width=22)
        table.add_column("Remote Endpoint", style="magenta", width=22)
        table.add_column("State", style="green", width=10)

        with self.lock:
            all_socks = list(self.current_sockets)
            socks = all_socks[:max_rows]

        for s in socks:
            st = s["state"]
            st_styled = f"[bold green]{st}[/bold green]" if st == "LISTEN" else (f"[cyan]{st}[/cyan]" if st == "ESTABLISHED" else f"[dim]{st}[/dim]")
            table.add_row(s["proto"], str(s["pid"]), s["pname"][:16], s["local"][:21], s["remote"][:21], st_styled)

        if not socks:
            table.add_row("TCP", "--", "System", "0.0.0.0:0", "0.0.0.0:0", "LISTEN")

        return table

    def render_command_bar(self) -> Panel:
        bar = Text()
        bar.append("CyberShield> ", style="bold green")
        bar.append(f"{self.command_buffer}", style="bold white on black")
        bar.append(" █\n", style="bold green")

        try:
            status_text = Text.from_markup(f"Status: {self.status_message}")
        except Exception:
            status_text = Text(f"Status: {self.status_message}", style="cyan")

        quick_chips = Text()
        quick_chips.append(" [help] ", style="bold black on blue")
        quick_chips.append(" [threats] ", style="bold white on red")
        quick_chips.append(" [block <ip>] ", style="bold black on red")
        quick_chips.append(" [unblock <ip>] ", style="bold black on green")
        quick_chips.append(" [nmap <ip>] ", style="bold black on blue")
        quick_chips.append(" [filter <proto>] ", style="bold black on magenta")
        quick_chips.append(" [scan] ", style="bold black on green")
        quick_chips.append(" [talkers] ", style="bold black on yellow")
        quick_chips.append(" [ps] ", style="bold black on white")
        quick_chips.append(" [dash] ", style="bold black on white")
        quick_chips.append(" [pdf] ", style="bold black on magenta")
        quick_chips.append(" [kill/Ctrl+C] ", style="bold black on red")

        content = Group(bar, status_text, Text(""), quick_chips)

        return Panel(
            content,
            title="[bold cyan]⌨️ Linux Interactive Shell & Threat Defense Bar (Fixed & Scroll-Proof)[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            padding=(0, 1)
        )

    def render(self) -> Any:
        cols, rows = shutil.get_terminal_size(fallback=(120, 30))
        offset = self.scroll_offsets.get(self.view_mode, 0)
        stream_title = "[bold green]🔬 Live Packet Inspection Stream [bold white on green] ● LIVE [/bold white on green][/bold green]" if offset == 0 else f"[bold yellow]🔬 Packet Stream History [bold black on yellow] ▲ VIEWING -{offset} pkts [/bold black on yellow][/bold yellow]"

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="metrics", size=4),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=5)
        )

        layout["header"].update(self.render_header())
        layout["metrics"].update(self.render_metrics_bar())
        layout["footer"].update(self.render_command_bar())

        if self.show_help:
            layout["body"].update(self.render_help_modal())
        elif self.view_mode == "threats":
            layout["body"].update(self.render_dedicated_threats_view())
        elif self.view_mode == "talkers":
            layout["body"].update(self.render_dedicated_talkers_view())
        elif self.view_mode == "sockets":
            layout["body"].update(self.render_dedicated_sockets_view())
        elif self.is_scanning:
            layout["body"].split_row(
                Layout(name="left", ratio=6),
                Layout(name="right", ratio=5)
            )
            layout["body"]["left"].update(self.render_radar_modal())
            layout["body"]["right"].update(Panel(
                self.render_hosts_table(),
                title="[bold cyan]📡 Discovered Local Devices[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED
            ))
        else:
            layout["body"].split_row(
                Layout(name="left", ratio=6),
                Layout(name="right", ratio=5)
            )

            # Left side: Live Packet Stream on Top + Traffic Flow Matrix on Bottom
            layout["body"]["left"].split_column(
                Layout(name="packet_stream", ratio=6),
                Layout(name="traffic_matrix", ratio=4)
            )

            pkt_rows = max(4, min(14, int((rows - 16) / 2)))

            layout["body"]["left"]["packet_stream"].update(Panel(
                self.render_packet_table(max_rows=pkt_rows),
                title=stream_title,
                border_style="green" if offset == 0 else "yellow",
                box=box.ROUNDED
            ))

            layout["body"]["left"]["traffic_matrix"].update(self.render_traffic_flow_matrix())

            # Right side: Security Threat Alerts on Top + Local Asset Inventory / Sockets on Bottom
            layout["body"]["right"].split_column(
                Layout(name="alerts", ratio=5),
                Layout(name="hosts_or_sockets", ratio=5)
            )

            layout["body"]["right"]["alerts"].update(Panel(
                self.render_alerts_table(max_rows=pkt_rows),
                title="[bold red]🚨 Security Threat Alerts (Type 'threats' for Full View)[/bold red]",
                border_style="red",
                box=box.ROUNDED
            ))

            layout["body"]["right"]["hosts_or_sockets"].update(Panel(
                self.render_hosts_table() if self.active_hosts else self.render_sockets_table(max_rows=pkt_rows),
                title="[bold cyan]📡 Local Network Asset Inventory (LAN Devices)[/bold cyan]" if self.active_hosts else "[bold cyan]💻 Live System Process Sockets[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED
            ))

        return layout

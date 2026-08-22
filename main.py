import argparse
import asyncio
import ctypes
import logging
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from ctypes import wintypes

# Ensure UTF-8 output across all consoles (Windows PowerShell, CMD, Termux, Linux, macOS)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from config import Config, setup_logging
from core.env_checker import EnvironmentChecker, DependencyStatus
from core.interface import NetworkInterfaceManager
from core.firewall import FirewallManager
from core.sniffer import LiveSniffer
from core.db import Database
from core.host_discovery import HostDiscovery
from scanners.port_scanner import PortScanner
from reporting.report_generator import SecurityReportGenerator
from detectors.engine import DetectionEngine
from ui.tui import TerminalDashboard
from ui.web import app as web_module

logger = logging.getLogger("main")

# Windows Native Console Mouse & Event Structures
if sys.platform == "win32":
    class COORD(ctypes.Structure):
        _fields_ = [('X', wintypes.SHORT), ('Y', wintypes.SHORT)]

    class KEY_EVENT_RECORD(ctypes.Structure):
        _fields_ = [
            ('bKeyDown', wintypes.BOOL),
            ('wRepeatCount', wintypes.WORD),
            ('wVirtualKeyCode', wintypes.WORD),
            ('wVirtualScanCode', wintypes.WORD),
            ('UnicodeChar', wintypes.WCHAR),
            ('dwControlKeyState', wintypes.DWORD)
        ]

    class MOUSE_EVENT_RECORD(ctypes.Structure):
        _fields_ = [
            ('dwMousePosition', COORD),
            ('dwButtonState', wintypes.DWORD),
            ('dwControlKeyState', wintypes.DWORD),
            ('dwEventFlags', wintypes.DWORD)
        ]

    class WINDOW_BUFFER_SIZE_RECORD(ctypes.Structure):
        _fields_ = [('dwSize', COORD)]

    class EVENT_UNION(ctypes.Union):
        _fields_ = [
            ('KeyEvent', KEY_EVENT_RECORD),
            ('MouseEvent', MOUSE_EVENT_RECORD),
            ('WindowBufferSizeEvent', WINDOW_BUFFER_SIZE_RECORD)
        ]

    class INPUT_RECORD(ctypes.Structure):
        _fields_ = [
            ('EventType', wintypes.WORD),
            ('Event', EVENT_UNION)
        ]

def stop_daemon(verbose: bool = False):
    if not os.path.exists(Config.PID_FILE):
        if verbose:
            print("[-] No active background daemon found (.network_monitor.pid does not exist).")
        return
    try:
        with open(Config.PID_FILE, "r") as f:
            pid = int(f.read().strip())
        if verbose:
            print(f"[*] Stopping background daemon process (PID {pid})...")
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.kill(pid, signal.SIGTERM)
        if os.path.exists(Config.PID_FILE):
            os.remove(Config.PID_FILE)
        if verbose:
            print("[+] CyberShield background monitor stopped successfully.")
    except Exception as e:
        logger.error("Error stopping daemon: %s", e)
        if os.path.exists(Config.PID_FILE):
            os.remove(Config.PID_FILE)

def check_status(verbose: bool = True):
    if not os.path.exists(Config.PID_FILE):
        if verbose:
            print("[-] CyberShield Monitor is NOT running.")
        return False
    try:
        with open(Config.PID_FILE, "r") as f:
            pid = int(f.read().strip())
        import psutil
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            if verbose:
                print(f"[+] CyberShield Monitor is ACTIVE (PID {pid}, CPU: {p.cpu_percent()}%, Mem: {p.memory_info().rss / (1024*1024):.1f} MB)")
                print(f"[*] Web Dashboard: http://localhost:{Config.WEB_PORT}")
                print(f"[*] Log File: {Config.LOG_FILE}")
            return True
        else:
            if verbose:
                print("[-] Daemon PID file exists but process is dead.")
            os.remove(Config.PID_FILE)
            return False
    except Exception as e:
        logger.error("Status check error: %s", e)
        return False

def run_service(args):
    setup_logging(verbose=args.verbose)
    deps = DependencyStatus()
    net_info = NetworkInterfaceManager.get_primary_interface()

    if args.verbose:
        print("=" * 70)
        print(" [CyberShield Threat Defense System]")
        print(f" [✓] Engine Mode:    NATIVE (Zero External Drivers Required)")
        print(f" [*] Active NIC:     {net_info['iface_name']} (IP: {net_info['local_ip']})")
        print(f" [*] Scope Subnet:   {net_info['subnet_cidr']}")
        print("=" * 70)

    logger.info("Initializing CyberShield Monitor (Mode: %s, NIC: %s, IP: %s, Subnet: %s)", deps.capture_mode, net_info['iface_name'], net_info['local_ip'], net_info['subnet_cidr'])

    Database.init_db()
    FirewallManager.init()

    packet_queue = queue.Queue(maxsize=Config.PACKET_QUEUE_MAX)
    detection_engine = DetectionEngine()

    sniffer = LiveSniffer(packet_queue, interface=args.interface)
    sniffer.start()

    web_module.detection_engine = detection_engine
    web_module.live_sniffer = sniffer

    tui_dashboard = TerminalDashboard(mode="Multi-Platform Real-Time") if args.ui in ["terminal", "both"] else None

    loop = asyncio.new_event_loop()
    def run_async_loop(al):
        asyncio.set_event_loop(al)
        al.run_forever()

    async_thread = threading.Thread(target=run_async_loop, args=(loop,), daemon=True)
    async_thread.start()

    running = True

    # Immortal, crash-proof packet consumer thread
    def packet_consumer():
        nonlocal running
        last_sock_sync = 0.0
        while running:
            try:
                try:
                    pkt = packet_queue.get(timeout=0.1)
                except queue.Empty:
                    now = time.time()
                    if now - last_sock_sync >= 1.0 and tui_dashboard:
                        last_sock_sync = now
                        tui_dashboard.update_sockets_from_sniffer(sniffer.cached_sockets)
                    continue

                alerts = detection_engine.analyze_packet(pkt)
                pkt_dict = pkt.model_dump()
                web_module.recent_packets.append(pkt_dict)
                web_module.stats["total_packets"] += 1
                web_module.stats["total_bytes"] += pkt.length
                p_name = pkt.protocol.value
                web_module.stats["protocols"][p_name] = web_module.stats["protocols"].get(p_name, 0) + 1

                if tui_dashboard:
                    tui_dashboard.update_packet(pkt)
                    now = time.time()
                    if now - last_sock_sync >= 1.0:
                        last_sock_sync = now
                        tui_dashboard.update_sockets_from_sniffer(sniffer.cached_sockets)

                web_module.broadcast_sync({"type": "packet", "packet": pkt_dict})

                for alert in alerts:
                    web_module.recent_alerts.append(alert)
                    web_module.stats["alert_count"] += 1
                    web_module.stats["active_threats"] += 1

                    if tui_dashboard:
                        tui_dashboard.update_alert(alert)

                    web_module.broadcast_sync({"type": "alert", "alert": alert})

                packet_queue.task_done()

            except Exception as e:
                logger.debug("Packet consumer loop protected exception: %s", e)

    proc_thread = threading.Thread(target=packet_consumer, daemon=True, name="PacketConsumerThread")
    proc_thread.start()

    with open(Config.PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    try:
        if args.ui == "terminal":
            from rich.live import Live

            # Live screen instance
            live = Live(tui_dashboard.render(), screen=True, auto_refresh=False, console=tui_dashboard.console)
            live.start()

            # Dedicated responsive keyboard & native mouse wheel listener
            def keyboard_thread():
                nonlocal running
                if sys.platform == "win32":
                    import msvcrt
                    kernel32 = ctypes.windll.kernel32
                    STD_INPUT_HANDLE = -10
                    h_in = kernel32.GetStdHandle(STD_INPUT_HANDLE)
                    orig_mode = wintypes.DWORD()
                    kernel32.GetConsoleMode(h_in, ctypes.byref(orig_mode))
                    
                    # Enable Windows Console QuickEdit mode (native text selection, mouse highlight & copy)
                    ENABLE_QUICK_EDIT_MODE = 0x0040
                    ENABLE_EXTENDED_FLAGS = 0x0080
                    ENABLE_WINDOW_INPUT = 0x0008
                    ENABLE_PROCESSED_INPUT = 0x0001
                    kernel32.SetConsoleMode(h_in, (orig_mode.value & ~0x0010) | ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT | ENABLE_PROCESSED_INPUT)

                    ir = (INPUT_RECORD * 16)()
                    read_count = wintypes.DWORD()

                    try:
                        while running:
                            try:
                                if tui_dashboard.should_exit:
                                    running = False
                                    break
                                
                                # Read Windows Console Input Records (captures Mouse Wheel + Keys + Resize)
                                num_events = wintypes.DWORD(0)
                                kernel32.GetNumberOfConsoleInputEvents(h_in, ctypes.byref(num_events))
                                if num_events.value > 0:
                                    kernel32.ReadConsoleInputW(h_in, ir, 16, ctypes.byref(read_count))
                                    for i in range(read_count.value):
                                        rec = ir[i]
                                        
                                        # 1. MOUSE EVENT (Native Wheel Detection)
                                        if rec.EventType == 0x0002:
                                            me = rec.Event.MouseEvent
                                            # MOUSE_WHEELED = 0x0004
                                            if me.dwEventFlags == 0x0004:
                                                # Check high word of button state (signed)
                                                btn = ctypes.c_int32(me.dwButtonState).value
                                                if btn > 0:
                                                    tui_dashboard.scroll_up(2)  # Wheel Up
                                                else:
                                                    tui_dashboard.scroll_down(2)  # Wheel Down
                                                live.update(tui_dashboard.render(), refresh=True)

                                        # 2. KEY EVENT
                                        elif rec.EventType == 0x0001:
                                            ke = rec.Event.KeyEvent
                                            if ke.bKeyDown:
                                                vk = ke.wVirtualKeyCode
                                                uch = ke.UnicodeChar

                                                # Ctrl+C (vk 0x43 with Ctrl) or Ctrl+D
                                                if uch in ['\x03', '\x04'] or (vk == 0x43 and (ke.dwControlKeyState & 0x0008 or ke.dwControlKeyState & 0x0004)):
                                                    running = False
                                                    break

                                                # Arrows & Navigation Keys
                                                if vk == 0x26:  # Up Arrow
                                                    if tui_dashboard.command_buffer:
                                                        tui_dashboard.history_up()
                                                    else:
                                                        tui_dashboard.scroll_up(2)
                                                elif vk == 0x28:  # Down Arrow
                                                    if tui_dashboard.command_buffer:
                                                        tui_dashboard.history_down()
                                                    else:
                                                        tui_dashboard.scroll_down(2)
                                                elif vk == 0x21:  # Page Up
                                                    tui_dashboard.scroll_up(5)
                                                elif vk == 0x22:  # Page Down
                                                    tui_dashboard.scroll_down(5)
                                                elif vk == 0x23:  # End Key
                                                    tui_dashboard.scroll_live()
                                                elif uch:
                                                    tui_dashboard.handle_char(uch)

                                                live.update(tui_dashboard.render(), refresh=True)

                                        # 3. WINDOW BUFFER SIZE EVENT (Minimize / Maximize)
                                        elif rec.EventType == 0x0004:
                                            live.update(tui_dashboard.render(), refresh=True)

                                time.sleep(0.015)
                            except Exception as e:
                                logger.debug("Windows Input loop exception: %s", e)
                    finally:
                        kernel32.SetConsoleMode(h_in, orig_mode.value)
                else:
                    import select, tty, termios
                    fd = sys.stdin.fileno()
                    old_settings = termios.tcgetattr(fd)
                    try:
                        tty.setcbreak(fd)
                        while running:
                            try:
                                if tui_dashboard.should_exit:
                                    running = False
                                    break
                                r, _, _ = select.select([sys.stdin], [], [], 0.02)
                                if r:
                                    ch = sys.stdin.read(1)
                                    if ch in ['\x03', '\x04']:
                                        running = False
                                        break
                                    if ch == '\x1b':
                                        time.sleep(0.015)
                                        seq = ""
                                        while select.select([sys.stdin], [], [], 0)[0]:
                                            seq += sys.stdin.read(1)
                                        if "<64;" in seq or "64;" in seq or "[5~" in seq:
                                            tui_dashboard.scroll_up(2)
                                        elif "<65;" in seq or "65;" in seq or "[6~" in seq:
                                            tui_dashboard.scroll_down(2)
                                        elif "[A" in seq:
                                            if tui_dashboard.command_buffer:
                                                tui_dashboard.history_up()
                                            else:
                                                tui_dashboard.scroll_up(2)
                                        elif "[B" in seq:
                                            if tui_dashboard.command_buffer:
                                                tui_dashboard.history_down()
                                            else:
                                                tui_dashboard.scroll_down(2)
                                        elif "[4~" in seq or "[F" in seq:
                                            tui_dashboard.scroll_live()
                                        live.update(tui_dashboard.render(), refresh=True)
                                        continue
                                    tui_dashboard.handle_char(ch)
                                    if tui_dashboard.should_exit:
                                        running = False
                                        break
                                    live.update(tui_dashboard.render(), refresh=True)
                                except Exception as e:
                                    logger.debug("Linux stdin exception: %s", e)
                    finally:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

            kb = threading.Thread(target=keyboard_thread, daemon=True)
            kb.start()

            # Immortal Display Refresh Loop
            while running:
                try:
                    if tui_dashboard.should_exit:
                        running = False
                        break
                    time.sleep(0.25)
                    live.update(tui_dashboard.render(), refresh=True)
                except Exception as e:
                    logger.debug("Live render refresh exception: %s", e)

            live.stop()
        else:
            import uvicorn
            if args.verbose:
                print(f"[*] Web server listening on http://{args.host}:{args.port}")
            
            uvicorn.run(
                web_module.app,
                host=args.host,
                port=args.port,
                log_level="warning" if not args.verbose else "info",
                access_log=args.verbose
            )
    except KeyboardInterrupt:
        pass
    finally:
        running = False
        sniffer.stop()
        if os.path.exists(Config.PID_FILE):
            try:
                os.remove(Config.PID_FILE)
            except Exception:
                pass
        print("[+] CyberShield monitor stopped cleanly.")
        logger.info("CyberShield monitor terminated.")

def main():
    parser = argparse.ArgumentParser(description="CyberShield Multi-Platform Real-Time Network Traffic Analyzer")
    parser.add_argument("--web", action="store_true", help="Start web dashboard (silent by default)")
    parser.add_argument("--ui", choices=["web", "terminal", "both"], default="terminal", help="UI mode: terminal (default) or web")
    parser.add_argument("--daemon", action="store_true", help="Run as background daemon service via pythonw.exe")
    parser.add_argument("--stop", action="store_true", help="Stop running background daemon service")
    parser.add_argument("--status", action="store_true", help="Check status of background daemon")
    parser.add_argument("--interface", default=None, help="Network interface to capture")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose terminal logging")
    parser.add_argument("--host", default=Config.WEB_HOST, help="Web server host")
    parser.add_argument("--port", type=int, default=Config.WEB_PORT, help="Web server port")

    args = parser.parse_args()

    if args.web:
        args.ui = "web"

    if args.stop:
        stop_daemon(verbose=True)
        return

    if args.status:
        check_status(verbose=True)
        return

    if args.daemon:
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        print(f"[*] Spawning CyberShield background monitor (pythonw.exe)...")
        print(f"[*] Logs: {Config.LOG_FILE}")
        
        python_exe = sys.executable
        if sys.platform == "win32":
            pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            if os.path.exists(pythonw):
                python_exe = pythonw

        cmd = [python_exe, __file__, "--host", args.host, "--port", str(args.port), "--web"]
        if args.interface:
            cmd.extend(["--interface", args.interface])

        with open(Config.LOG_FILE, "a", encoding="utf-8") as log_out:
            subprocess.Popen(
                cmd,
                stdout=log_out,
                stderr=log_out,
                creationflags=subprocess.DETACHED_PROCESS if sys.platform == "win32" else 0
            )

        time.sleep(1.5)
        check_status(verbose=True)
        return

    run_service(args)

if __name__ == "__main__":
    main()

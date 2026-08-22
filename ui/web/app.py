import asyncio
import logging
import os
import queue
import sys
import threading
import time
from collections import deque
from typing import List, Dict, Any, Optional
import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from config import Config
from core.env_checker import EnvironmentChecker, DependencyStatus
from core.interface import NetworkInterfaceManager
from core.db import Database
from core.firewall import FirewallManager
from core.host_discovery import HostDiscovery
from scanners.port_scanner import PortScanner
from reporting.report_generator import SecurityReportGenerator

logger = logging.getLogger(__name__)

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
logging.getLogger("fastapi").setLevel(logging.WARNING)

app = FastAPI(title="CyberShield Live SOC Dashboard", version="2.5.0")

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(templates_dir, exist_ok=True)
os.makedirs(static_dir, exist_ok=True)

templates = Jinja2Templates(directory=templates_dir)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

recent_packets: deque = deque(maxlen=Config.PACKET_HISTORY_LIMIT)
recent_alerts: deque = deque(maxlen=Config.ALERT_HISTORY_LIMIT)
throughput_history: deque = deque([0.0]*60, maxlen=Config.THROUGHPUT_HISTORY_SECS)
current_sockets: List[Dict[str, Any]] = []
_pname_cache: Dict[int, str] = {}

detection_engine: Optional[Any] = None
live_sniffer: Optional[Any] = None
active_websockets: List[WebSocket] = []
main_event_loop: Optional[asyncio.AbstractEventLoop] = None

stats = {
    "total_packets": 0,
    "total_bytes": 0,
    "packets_per_sec": 0.0,
    "bytes_per_sec": 0.0,
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "OTHER": 0},
    "alert_count": 0,
    "active_threats": 0,
    "start_time": time.time()
}

_last_pkt_count = 0
_last_byte_count = 0
_last_tick_time = time.time()

class PortScanReq(BaseModel):
    target_ip: str

class SubnetScanReq(BaseModel):
    subnet_cidr: Optional[str] = None

# Pure Python In-Memory Socket Poller
async def socket_poller_task():
    global current_sockets, _pname_cache
    while True:
        try:
            parsed = []
            connections = psutil.net_connections(kind="inet")
            for c in connections[:60]:
                proto = "TCP" if c.type == 1 else "UDP"
                local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "--"
                remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "--"
                state = c.status if proto == "TCP" else "NONE"
                pid = c.pid or "--"

                pname = "System"
                if c.pid:
                    if c.pid not in _pname_cache:
                        try:
                            _pname_cache[c.pid] = psutil.Process(c.pid).name()
                        except Exception:
                            _pname_cache[c.pid] = f"PID {c.pid}"
                    pname = _pname_cache[c.pid]

                parsed.append({
                    "proto": proto,
                    "local": local,
                    "remote": remote,
                    "state": state,
                    "pid": str(pid),
                    "pname": pname
                })
            current_sockets = parsed
        except Exception as e:
            logger.debug("psutil socket poller exception: %s", e)
        await asyncio.sleep(Config.SOCKET_POLL_INTERVAL)

# WebSocket & Metrics Broadcast (500ms interval)
async def ws_broadcast_task():
    global _last_pkt_count, _last_byte_count, _last_tick_time
    while True:
        await asyncio.sleep(Config.WS_BROADCAST_INTERVAL)
        now = time.time()
        dt = max(now - _last_tick_time, 0.2)
        
        # Calculate instant live rate
        instant_pkts = (stats["total_packets"] - _last_pkt_count) / dt
        instant_bytes = (stats["total_bytes"] - _last_byte_count) / dt
        
        _last_pkt_count = stats["total_packets"]
        _last_byte_count = stats["total_bytes"]
        _last_tick_time = now
        
        stats["packets_per_sec"] = round(instant_pkts, 1)
        stats["bytes_per_sec"] = round(instant_bytes, 1)
        throughput_history.append(stats["packets_per_sec"])

        payload = {
            "type": "tick",
            "stats": stats,
            "threat_level": "CRITICAL" if stats["active_threats"] > 3 else ("ELEVATED" if stats["active_threats"] > 0 else "NOMINAL"),
            "throughput": list(throughput_history),
            "protocols": stats["protocols"],
            "sockets": current_sockets[:25]
        }
        await broadcast(payload)

def broadcast_sync(payload: Dict[str, Any]):
    global main_event_loop
    if not active_websockets or not main_event_loop or not main_event_loop.is_running():
        return
    try:
        asyncio.run_coroutine_threadsafe(broadcast(payload), main_event_loop)
    except Exception:
        pass

async def broadcast(payload: Dict[str, Any]):
    disconnected = []
    for ws in list(active_websockets):
        try:
            await ws.send_json(payload)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in active_websockets:
            active_websockets.remove(ws)

# Auto-start internal sniffer worker if web app is started independently
def ensure_sniffer_running():
    global live_sniffer, detection_engine
    if live_sniffer is not None:
        return
    
    Database.init_db()
    FirewallManager.init()

    from detectors.engine import DetectionEngine
    from core.sniffer import LiveSniffer

    packet_queue = queue.Queue(maxsize=Config.PACKET_QUEUE_MAX)
    detection_engine = DetectionEngine()
    live_sniffer = LiveSniffer(packet_queue)
    live_sniffer.start()

    def background_consumer():
        while True:
            try:
                try:
                    pkt = packet_queue.get(timeout=0.1)
                except queue.Empty:
                    continue

                alerts = detection_engine.analyze_packet(pkt)
                pkt_dict = pkt.model_dump()
                recent_packets.append(pkt_dict)
                stats["total_packets"] += 1
                stats["total_bytes"] += pkt.length
                p_name = pkt.protocol.value
                stats["protocols"][p_name] = stats["protocols"].get(p_name, 0) + 1

                broadcast_sync({"type": "packet", "packet": pkt_dict})

                for alert in alerts:
                    recent_alerts.append(alert)
                    stats["alert_count"] += 1
                    stats["active_threats"] += 1
                    broadcast_sync({"type": "alert", "alert": alert})

                packet_queue.task_done()
            except Exception as e:
                logger.debug("Web sniffer consumer exception: %s", e)

    t = threading.Thread(target=background_consumer, daemon=True, name="WebBackgroundConsumer")
    t.start()

@app.on_event("startup")
async def startup_event():
    global main_event_loop
    main_event_loop = asyncio.get_running_loop()
    ensure_sniffer_running()
    asyncio.create_task(socket_poller_task())
    asyncio.create_task(ws_broadcast_task())

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    net_info = NetworkInterfaceManager.get_primary_interface()
    diag = EnvironmentChecker.get_diagnostics()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"net_info": net_info, "diagnostics": diag}
    )

@app.get("/api/deps")
async def get_deps():
    deps = DependencyStatus()
    return deps.to_dict()

@app.get("/api/status")
async def get_status():
    return {
        "diagnostics": EnvironmentChecker.get_diagnostics(),
        "network": NetworkInterfaceManager.get_primary_interface(),
        "sniffer_engine": getattr(live_sniffer, "active_engine", "NATIVE_RAW_SOCKET") if live_sniffer else "ACTIVE"
    }

@app.get("/api/stats")
async def get_stats():
    threat_level = "CRITICAL" if stats["active_threats"] > 3 else ("ELEVATED" if stats["active_threats"] > 0 else "NOMINAL")
    return {
        "total_packets": stats["total_packets"],
        "total_bytes": stats["total_bytes"],
        "packets_per_sec": stats["packets_per_sec"],
        "bytes_per_sec": stats["bytes_per_sec"],
        "threat_count": stats["alert_count"],
        "active_threats": stats["active_threats"],
        "threat_level": threat_level,
        "protocols": stats["protocols"],
        "throughput": list(throughput_history)
    }

@app.get("/api/alerts")
async def get_alerts():
    return await Database.get_recent_alerts(limit=Config.ALERT_HISTORY_LIMIT)

@app.get("/api/packets")
async def get_packets():
    return list(recent_packets)[-50:]

@app.get("/api/hosts")
async def get_hosts():
    return await Database.get_all_devices()

@app.get("/api/sockets")
async def get_sockets():
    return current_sockets

@app.get("/api/protocol-breakdown")
async def get_protocols():
    return stats["protocols"]

@app.get("/api/throughput-history")
async def get_throughput_history():
    return list(throughput_history)

@app.post("/api/real/scan-subnet")
async def trigger_subnet_scan(req: SubnetScanReq):
    net_info = NetworkInterfaceManager.get_primary_interface()
    target = req.subnet_cidr or net_info["subnet_cidr"]

    if not NetworkInterfaceManager.is_in_local_subnet(target.split("/")[0], net_info["subnet_cidr"]):
        raise HTTPException(
            status_code=403,
            detail=f"BLOCKED: Target IP [{target}] is outside your local subnet [{net_info['subnet_cidr']}]. Only local network scanning is permitted."
        )

    devices = HostDiscovery.scan_subnet(subnet_cidr=target)
    await broadcast({"type": "hosts_update", "devices": devices})
    return {"status": "success", "count": len(devices), "devices": devices}

@app.post("/api/real/scan-ports")
async def trigger_port_scan(req: PortScanReq):
    net_info = NetworkInterfaceManager.get_primary_interface()
    if not NetworkInterfaceManager.is_in_local_subnet(req.target_ip, net_info["subnet_cidr"]):
        err_msg = f"BLOCKED: Target IP [{req.target_ip}] is outside your local subnet [{net_info['subnet_cidr']}]. Only local network scanning is permitted."
        logger.warning(err_msg)
        raise HTTPException(status_code=403, detail=err_msg)

    results = PortScanner.scan_target(req.target_ip)
    await broadcast({"type": "port_scan_result", "target_ip": req.target_ip, "results": results})
    return results

@app.get("/api/export-pdf")
async def export_pdf():
    reports_dir = os.path.join(Config.BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, "Executive_Network_Security_Report.pdf")
    SecurityReportGenerator.generate_pdf_report(pdf_path)
    return FileResponse(pdf_path, media_type="application/pdf", filename="Executive_Network_Security_Report.pdf")

@app.websocket("/ws")
async def websocket_handler(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        deps_info = DependencyStatus().to_dict()
        init_payload = {
            "type": "init",
            "deps": deps_info,
            "packets": list(recent_packets)[-40:],
            "alerts": await Database.get_recent_alerts(limit=15),
            "hosts": await Database.get_all_devices(),
            "sockets": current_sockets[:25],
            "stats": stats,
            "throughput": list(throughput_history)
        }
        await websocket.send_json(init_payload)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_websockets:
            active_websockets.remove(websocket)
    except Exception:
        if websocket in active_websockets:
            active_websockets.remove(websocket)

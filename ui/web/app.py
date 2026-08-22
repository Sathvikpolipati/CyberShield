import asyncio
import logging
import os
import sys
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
from core.host_discovery import HostDiscovery
from scanners.port_scanner import PortScanner
from reporting.report_generator import SecurityReportGenerator

logger = logging.getLogger(__name__)

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
logging.getLogger("fastapi").setLevel(logging.WARNING)

app = FastAPI(title="CyberShield Live Network Traffic Analyser", version="2.5.0")

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(templates_dir, exist_ok=True)
os.makedirs(static_dir, exist_ok=True)

templates = Jinja2Templates(directory=templates_dir)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

recent_packets: deque = deque(maxlen=Config.PACKET_HISTORY_LIMIT)
recent_alerts: deque = deque(maxlen=Config.ALERT_HISTORY_LIMIT)
throughput_history: deque = deque(maxlen=Config.THROUGHPUT_HISTORY_SECS)
current_sockets: List[Dict[str, Any]] = []
_pname_cache: Dict[int, str] = {}

detection_engine: Optional[Any] = None
live_sniffer: Optional[Any] = None
active_websockets: List[WebSocket] = []

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

class PortScanReq(BaseModel):
    target_ip: str

class SubnetScanReq(BaseModel):
    subnet_cidr: Optional[str] = None

# Pure Python In-Memory Socket Poller (ZERO SUBPROCESSES)
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

# WebSocket Periodic Broadcast (500ms)
async def ws_broadcast_task():
    while True:
        await asyncio.sleep(Config.WS_BROADCAST_INTERVAL)
        if active_websockets:
            now = time.time()
            uptime = max(now - stats["start_time"], 1.0)
            stats["packets_per_sec"] = round(stats["total_packets"] / uptime, 1)
            stats["bytes_per_sec"] = round(stats["total_bytes"] / uptime, 1)
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

@app.on_event("startup")
async def startup_event():
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
        "sniffer_engine": getattr(live_sniffer, "active_engine", "SCAPY") if live_sniffer else "STANDBY"
    }

@app.get("/api/stats")
async def get_stats():
    now = time.time()
    uptime = max(now - stats["start_time"], 1.0)
    threat_level = "CRITICAL" if stats["active_threats"] > 3 else ("ELEVATED" if stats["active_threats"] > 0 else "NOMINAL")
    return {
        "total_packets": stats["total_packets"],
        "total_bytes": stats["total_bytes"],
        "packets_per_sec": stats["packets_per_sec"],
        "bytes_per_sec": stats["bytes_per_sec"],
        "threat_count": stats["alert_count"],
        "threat_level": threat_level,
        "uptime_seconds": round(uptime, 1)
    }

@app.get("/api/alerts")
async def get_alerts():
    return await Database.get_recent_alerts(limit=Config.ALERT_HISTORY_LIMIT)

@app.get("/api/packets")
async def get_packets():
    return list(recent_packets)

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
            "packets": list(recent_packets)[-30:],
            "alerts": await Database.get_recent_alerts(limit=15),
            "hosts": await Database.get_all_devices(),
            "sockets": current_sockets[:25],
            "stats": stats
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

async def broadcast(payload: Dict[str, Any]):
    disconnected = []
    for ws in active_websockets:
        try:
            await ws.send_json(payload)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in active_websockets:
            active_websockets.remove(ws)

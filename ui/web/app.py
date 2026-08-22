import os
import time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from typing import List, Dict, Any
from pydantic import BaseModel

app = FastAPI(title="CyberShield Web Dashboard")

# Serve static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

recent_packets: List[Dict[str, Any]] = []
recent_alerts: List[Dict[str, Any]] = []
active_websockets: List[WebSocket] = []

stats = {
    "total_packets": 0,
    "total_bytes": 0,
    "alert_count": 0,
    "active_threats": 0,
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "OTHER": 0}
}

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    idx = os.path.join(static_dir, "index.html")
    if os.path.exists(idx):
        with open(idx, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>CyberShield SOC Web Dashboard Active</h1>"

@app.get("/api/stats")
async def get_stats():
    return stats

@app.get("/api/packets")
async def get_packets():
    return recent_packets[-50:]

@app.get("/api/alerts")
async def get_alerts():
    return recent_alerts[-50:]

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_websockets.remove(websocket)

async def broadcast(message: dict):
    for ws in list(active_websockets):
        try:
            await ws.send_json(message)
        except Exception:
            if ws in active_websockets:
                active_websockets.remove(ws)

app.recent_packets = recent_packets
app.recent_alerts = recent_alerts
app.active_websockets = active_websockets
app.stats = stats
app.broadcast = broadcast

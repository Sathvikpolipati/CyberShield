let packetsCache = [];
let alertsCache = [];
let hostsCache = [];
let throughputData = new Array(60).fill(0);
let reconnectDelay = 1000;
let ws = null;

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        document.getElementById('ws-status').className = 'status-badge online';
        document.getElementById('ws-status').innerText = 'CONNECTED';
        reconnectDelay = 1000;
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'packet') {
            addPacket(data.packet);
        } else if (data.type === 'alert') {
            addAlert(data.alert);
        }
    };

    ws.onclose = () => {
        document.getElementById('ws-status').className = 'status-badge offline';
        document.getElementById('ws-status').innerText = 'RECONNECTING...';
        setTimeout(initWebSocket, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 1.5, 10000);
    };
}

function addPacket(pkt) {
    packetsCache.unshift(pkt);
    if (packetsCache.length > 50) packetsCache.pop();
    renderPackets();
}

function addAlert(alert) {
    alertsCache.unshift(alert);
    if (alertsCache.length > 20) alertsCache.pop();
    renderAlerts();
}

function renderPackets() {
    const tbody = document.getElementById('packet-tbody');
    if (!tbody) return;
    tbody.innerHTML = packetsCache.map(p => `
        <tr>
            <td>${p.formatted_time}</td>
            <td><span class="proto-badge ${p.protocol.toLowerCase()}">${p.protocol}</span></td>
            <td>${p.src_ip}:${p.src_port || ''}</td>
            <td>${p.dst_ip}:${p.dst_port || ''}</td>
            <td>${p.length} B</td>
            <td>${p.summary}</td>
        </tr>
    `).join('');
}

function renderAlerts() {
    const container = document.getElementById('alerts-container');
    if (!container) return;
    container.innerHTML = alertsCache.map(a => `
        <div class="alert-card ${a.severity.toLowerCase()}">
            <div class="alert-title">[${a.severity}] ${a.rule_name}</div>
            <div class="alert-desc">${a.details || ''}</div>
            <div class="alert-endpoints">${a.attacker_ip} -> ${a.target_ip}</div>
        </div>
    `).join('');
}

window.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
});

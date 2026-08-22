let packetsCache = [];
let alertsCache = [];
let hostsCache = [];
let throughputData = new Array(60).fill(0);
let reconnectDelay = 1000;
let ws = null;
let pollingFallbackActive = false;

// Initialize Chart.js Throughput Line Chart with Transparent Background
const ctxThroughput = document.getElementById('throughputChart').getContext('2d');
const throughputChart = new Chart(ctxThroughput, {
    type: 'line',
    data: {
        labels: new Array(60).fill(''),
        datasets: [{
            label: 'Packets/sec',
            data: throughputData,
            borderColor: '#00dcff',
            backgroundColor: 'rgba(0, 220, 255, 0.12)',
            borderWidth: 2,
            fill: true,
            tension: 0.35,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: { display: false },
            y: {
                grid: { color: 'rgba(0, 220, 255, 0.08)' },
                ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } },
                beginAtZero: true
            }
        },
        plugins: { legend: { display: false } }
    }
});

// Initialize Protocol Donut Chart
const ctxProtocol = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(ctxProtocol, {
    type: 'doughnut',
    data: {
        labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'Other'],
        datasets: [{
            data: [1, 1, 1, 1, 1, 1, 1],
            backgroundColor: ['#00dcff', '#3b82f6', '#ec4899', '#10b981', '#f59e0b', '#eab308', '#64748b'],
            borderWidth: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        cutout: '72%'
    }
});

// Connect WebSocket with Exponential Backoff + Live Packet Sync
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        const dot = document.getElementById('wsDot');
        const txt = document.getElementById('wsText');
        if (dot) dot.className = 'inline-block w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping';
        if (txt) {
            txt.textContent = '● LIVE CONNECTED';
            txt.className = 'text-emerald-400 font-bold';
        }
        reconnectDelay = 1000;
        pollingFallbackActive = false;
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'init') {
                packetsCache = data.packets || [];
                alertsCache = data.alerts || [];
                hostsCache = data.hosts || [];
                renderPackets();
                renderAlerts();
                renderHosts();
                if (data.sockets) renderSockets(data.sockets);
                if (data.stats) updateMetrics(data.stats, data.threat_level || 'NOMINAL');
                if (data.throughput) {
                    throughputChart.data.datasets[0].data = data.throughput;
                    throughputChart.update();
                }
            } else if (data.type === 'tick') {
                updateMetrics(data.stats, data.threat_level);
                if (data.throughput) {
                    throughputChart.data.datasets[0].data = data.throughput;
                    throughputChart.update();
                }
                if (data.protocols) updateProtocols(data.protocols);
                if (data.sockets) renderSockets(data.sockets);
            } else if (data.type === 'packet') {
                packetsCache.unshift(data.packet);
                if (packetsCache.length > 80) packetsCache.pop();
                renderPackets();
            } else if (data.type === 'alert') {
                alertsCache.unshift(data.alert);
                renderAlerts();
            } else if (data.type === 'hosts_update') {
                hostsCache = data.devices || [];
                renderHosts();
            }
        } catch (e) {
            console.debug('WS parse error:', e);
        }
    };

    ws.onclose = () => {
        const dot = document.getElementById('wsDot');
        const txt = document.getElementById('wsText');
        if (dot) dot.className = 'inline-block w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse';
        if (txt) {
            txt.textContent = '● RECONNECTING';
            txt.className = 'text-amber-400 font-bold';
        }
        startFallbackPolling();
        setTimeout(connectWebSocket, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 1.5, 10000);
    };
}

// Fallback Polling guarantees live data even if WebSockets are blocked
function startFallbackPolling() {
    if (pollingFallbackActive) return;
    pollingFallbackActive = true;
    
    const poll = async () => {
        if (!pollingFallbackActive) return;
        try {
            const [statsRes, pktsRes, alertsRes] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/packets'),
                fetch('/api/alerts')
            ]);
            const s = await statsRes.json();
            const p = await pktsRes.json();
            const a = await alertsRes.json();

            updateMetrics(s, s.threat_level);
            if (s.throughput) {
                throughputChart.data.datasets[0].data = s.throughput;
                throughputChart.update();
            }
            if (s.protocols) updateProtocols(s.protocols);
            if (Array.isArray(p)) {
                packetsCache = p;
                renderPackets();
            }
            if (Array.isArray(a)) {
                alertsCache = a;
                renderAlerts();
            }
        } catch (err) {
            console.debug('Poll error:', err);
        }
        if (pollingFallbackActive) {
            setTimeout(poll, 1500);
        }
    };
    poll();
}

function updateMetrics(s, threatLevel) {
    if (!s) return;
    document.getElementById('statPackets').textContent = (s.total_packets || 0).toLocaleString();
    document.getElementById('statBytes').textContent = `${((s.total_bytes || 0) / 1024).toFixed(1)} KB`;
    document.getElementById('statRate').textContent = s.packets_per_sec || 0;
    document.getElementById('statBps').textContent = ((s.bytes_per_sec || 0) / 1024).toFixed(1);
    document.getElementById('statThreats').textContent = s.active_threats || s.threat_count || 0;
    document.getElementById('statThreatCount').textContent = s.alert_count || s.threat_count || 0;

    const tElem = document.getElementById('statThreatLevel');
    if (tElem) {
        tElem.textContent = threatLevel || 'NOMINAL';
        if (threatLevel === 'CRITICAL') {
            tElem.className = 'text-3xl font-bold font-mono text-red-500 animate-pulse';
        } else if (threatLevel === 'ELEVATED') {
            tElem.className = 'text-3xl font-bold font-mono text-amber-400';
        } else {
            tElem.className = 'text-3xl font-bold font-mono text-emerald-400';
        }
    }
}

function updateProtocols(p) {
    const tcp = p.TCP || 0;
    const udp = p.UDP || 0;
    const icmp = p.ICMP || 0;
    const dns = p.DNS || 0;
    const http = p.HTTP || 0;
    const https = p.HTTPS || 0;
    const other = p.OTHER || 0;

    const legT = document.getElementById('legTCP');
    const legU = document.getElementById('legUDP');
    const legI = document.getElementById('legICMP');
    if (legT) legT.textContent = tcp;
    if (legU) legU.textContent = udp;
    if (legI) legI.textContent = icmp;

    const total = tcp + udp + icmp + dns + http + https + other;
    if (total > 0) {
        protocolChart.data.datasets[0].data = [tcp, udp, icmp, dns, http, https, other];
        protocolChart.update();
    }
}

function renderPackets() {
    const tbody = document.getElementById('packetTableBody');
    if (!tbody) return;
    if (packetsCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500">Listening on interface... Intercepting live traffic.</td></tr>`;
        return;
    }

    tbody.innerHTML = packetsCache.slice(0, 30).map((pkt, idx) => {
        let protoClass = 'bg-cyan-950/80 text-cyan-400 border border-cyan-500/40';
        if (pkt.protocol === 'UDP') protoClass = 'bg-blue-950/80 text-blue-400 border border-blue-500/40';
        else if (pkt.protocol === 'ICMP') protoClass = 'bg-pink-950/80 text-pink-400 border border-pink-500/40';
        else if (pkt.protocol === 'DNS') protoClass = 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40';
        else if (pkt.protocol === 'HTTP' || pkt.protocol === 'HTTPS') protoClass = 'bg-amber-950/80 text-amber-400 border border-amber-500/40';

        const timeStr = pkt.formatted_time ? pkt.formatted_time.split(' ')[1] || pkt.formatted_time : '00:00:00';
        const src = `${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}`;
        const dst = `${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}`;

        return `
            <tr onclick="openPacketModal(${idx})" class="hover:bg-cyan-950/40 cursor-pointer transition border-b border-slate-800/40">
                <td class="py-2 px-3 text-slate-400 text-[11px]">${timeStr}</td>
                <td class="py-2 px-2"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${protoClass}">${pkt.protocol}</span></td>
                <td class="py-2 px-3 text-slate-200">${src} &rarr; ${dst}</td>
                <td class="py-2 px-2 text-right text-slate-400 font-mono">${pkt.length}</td>
                <td class="py-2 px-3 text-slate-400 truncate max-w-[200px]" title="${pkt.summary || ''}">${pkt.summary || '--'}</td>
            </tr>
        `;
    }).join('');
}

function renderAlerts() {
    const container = document.getElementById('alertContainer');
    const noMsg = document.getElementById('noAlertsMsg');
    const badge = document.getElementById('alertBadge');
    if (badge) badge.textContent = `${alertsCache.length} EVENTS`;

    if (!container) return;
    if (alertsCache.length === 0) {
        if (noMsg) noMsg.classList.remove('hidden');
        return;
    }
    if (noMsg) noMsg.classList.add('hidden');

    container.innerHTML = alertsCache.slice(0, 15).map(alt => {
        const sev = alt.severity || 'HIGH';
        const isCrit = sev === 'CRITICAL' || sev === 'HIGH';
        return `
            <div class="p-3.5 rounded-xl border ${isCrit ? 'border-red-500/40 bg-red-950/30' : 'border-amber-500/40 bg-amber-950/30'} space-y-1.5 backdrop-blur-sm shadow-md">
                <div class="flex items-center justify-between">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isCrit ? 'bg-red-900 text-white' : 'bg-amber-900 text-amber-200'}">${sev}</span>
                    <span class="text-[10px] font-mono text-slate-400">${(alt.timestamp || '').toString().slice(0,19)}</span>
                </div>
                <h4 class="text-xs font-bold text-white">${alt.rule || alt.rule_name || 'Threat Detected'}</h4>
                <p class="text-xs text-slate-300 leading-relaxed">${alt.details || alt.description || 'Heuristic anomaly trigger.'}</p>
                <div class="text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-700/50">
                    ${alt.attacker_ip} &rarr; ${alt.target_ip}
                </div>
            </div>
        `;
    }).join('');
}

function renderHosts() {
    const tbody = document.getElementById('hostsTableBody');
    if (!tbody) return;
    if (hostsCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-500">No LAN devices found yet. Click "SCAN LOCAL SUBNET NOW".</td></tr>`;
        return;
    }

    tbody.innerHTML = hostsCache.map(h => `
        <tr class="hover:bg-cyan-950/40 transition border-b border-slate-800/40">
            <td class="py-2.5 px-3 font-bold text-cyan-400">${h.ip}</td>
            <td class="py-2.5 px-3 text-white">${h.hostname || 'Host'}</td>
            <td class="py-2.5 px-3 text-slate-400 font-mono">${h.mac || 'Unknown'}</td>
            <td class="py-2.5 px-3 text-slate-300">${h.vendor || 'OEM / Network Device'}</td>
            <td class="py-2.5 px-2 text-slate-400">${(h.last_seen || '').toString().slice(11,19) || 'Just now'}</td>
            <td class="py-2.5 px-3 text-right">
                <button onclick="scanHostPorts('${h.ip}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-600 text-cyan-200 text-xs font-mono transition">
                    Scan Ports
                </button>
            </td>
        </tr>
    `).join('');
}

function renderSockets(sockets) {
    const tbody = document.getElementById('socketTableBody');
    if (!tbody) return;
    tbody.innerHTML = (sockets || []).map(s => `
        <tr class="hover:bg-cyan-950/40 transition border-b border-slate-800/40">
            <td class="py-2 px-3"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${s.proto === 'TCP' ? 'bg-cyan-950 text-cyan-400 border border-cyan-500/40' : 'bg-blue-950 text-blue-400 border border-blue-500/40'}">${s.proto}</span></td>
            <td class="py-2 px-3 font-semibold text-white">${s.pname}</td>
            <td class="py-2 px-3 text-cyan-300 font-mono">${s.local}</td>
            <td class="py-2 px-3 text-yellow-300 font-mono">${s.remote}</td>
            <td class="py-2 px-2 text-center"><span class="px-1.5 py-0.5 rounded text-[10px] font-mono ${s.state === 'LISTEN' ? 'bg-purple-950 text-purple-400 border border-purple-800 font-bold' : (s.state === 'ESTABLISHED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400')}">${s.state}</span></td>
        </tr>
    `).join('');
}

async function scanLocalSubnet() {
    const btn = document.getElementById('btnSubnetScan');
    const spin = document.getElementById('scanSpin');
    btn.disabled = true;
    spin.classList.remove('hidden');

    try {
        const res = await fetch('/api/real/scan-subnet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        hostsCache = data.devices || [];
        renderHosts();
    } catch (e) {
        console.error(e);
    } finally {
        btn.disabled = false;
        spin.classList.add('hidden');
    }
}

async function scanHostPorts(ip) {
    document.getElementById('portModalIp').textContent = ip;
    document.getElementById('portModalBody').innerHTML = `<p class="text-center py-6 text-slate-400">Scanning ports on ${ip}...</p>`;
    document.getElementById('portModal').classList.remove('hidden');

    try {
        const res = await fetch('/api/real/scan-ports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_ip: ip })
        });
        const data = await res.json();
        if (data.error) {
            document.getElementById('portModalBody').innerHTML = `<div class="p-3 bg-red-950 border border-red-800 text-red-300 rounded">${data.message}</div>`;
            return;
        }

        const portList = (data.open_ports || []).map(p => `
            <div class="p-2.5 rounded bg-black/50 border border-cyan-500/30 flex items-center justify-between">
                <div>
                    <span class="text-cyan-400 font-bold">Port ${p.port}</span> (${p.service})
                    <div class="text-[10px] text-slate-400">${p.description}</div>
                </div>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${p.risk === 'HIGH' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">${p.risk}</span>
            </div>
        `).join('');

        document.getElementById('portModalBody').innerHTML = `
            <div class="p-3 rounded bg-black/60 border border-cyan-500/40 mb-3">
                <p class="font-bold text-white">Security Score: <span class="text-cyan-400">${data.risk_score}/100</span></p>
                <p class="text-xs text-slate-300 mt-1">${data.security_assessment}</p>
            </div>
            <div class="space-y-2">
                <p class="text-xs text-slate-400 font-bold">Open Ports (${data.open_ports_count}):</p>
                ${portList || '<div class="p-4 text-center text-slate-400">No open ports detected.</div>'}
            </div>
        `;
    } catch (e) {
        document.getElementById('portModalBody').innerHTML = `<p class="text-center py-6 text-red-400">Scan failed: ${e.message}</p>`;
    }
}

function openPacketModal(idx) {
    const pkt = packetsCache[idx];
    if (!pkt) return;
    document.getElementById('modalBody').innerHTML = `
        <div class="p-3 bg-black/60 rounded-lg border border-cyan-500/30 space-y-1">
            <p><strong class="text-cyan-400">Timestamp:</strong> ${pkt.formatted_time}</p>
            <p><strong class="text-cyan-400">Protocol:</strong> ${pkt.protocol}</p>
            <p><strong class="text-cyan-400">Length:</strong> ${pkt.length} bytes</p>
            <p><strong class="text-cyan-400">Source:</strong> ${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</p>
            <p><strong class="text-cyan-400">Destination:</strong> ${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</p>
            ${pkt.flags ? `<p><strong class="text-cyan-400">Flags:</strong> ${pkt.flags}</p>` : ''}
            <p><strong class="text-cyan-400">Summary:</strong> ${pkt.summary}</p>
        </div>
        ${pkt.raw_hex_preview ? `
        <div class="p-3 bg-black/60 rounded-lg border border-cyan-500/30 space-y-1">
            <p class="text-slate-400 font-bold mb-1">Raw Hex & ASCII Payload Preview:</p>
            <div class="p-2 bg-black rounded font-mono text-[10px] text-emerald-400 break-all select-all">${pkt.raw_hex_preview}</div>
        </div>` : ''}
    `;
    document.getElementById('packetModal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('packetModal').classList.add('hidden');
}

// Start WebSocket connection on load
connectWebSocket();

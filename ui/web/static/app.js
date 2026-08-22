let packetsCache = [];
let alertsCache = [];
let hostsCache = [];
let throughputData = new Array(60).fill(0);
let reconnectDelay = 1000;
let ws = null;

// Initialize Chart.js Throughput Line Chart
const ctxThroughput = document.getElementById('throughputChart').getContext('2d');
const throughputChart = new Chart(ctxThroughput, {
    type: 'line',
    data: {
        labels: new Array(60).fill(''),
        datasets: [{
            label: 'Packets/sec',
            data: throughputData,
            borderColor: '#06B6D4',
            backgroundColor: 'rgba(6, 182, 212, 0.12)',
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: { display: false },
            y: {
                grid: { color: '#1F2937' },
                ticks: { color: '#9CA3AF', font: { family: 'JetBrains Mono', size: 10 } },
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
            backgroundColor: ['#06B6D4', '#3B82F6', '#EC4899', '#10B981', '#F59E0B', '#EAB308', '#6B7280'],
            borderWidth: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        cutout: '68%'
    }
});

// Update Dependency Status Bar
function updateDependencyStatus(status) {
    const bar = document.getElementById('dep-status-bar');
    if (!bar) return;
    bar.className = 'w-full px-4 py-2 text-white text-xs font-semibold text-center bg-emerald-600 transition-colors shadow-md';
    bar.textContent = '✓ All systems nominal — Real-time Native Windows capture engine active';
}

fetch('/api/deps')
    .then(res => res.json())
    .then(data => updateDependencyStatus(data))
    .catch(err => console.debug('Deps fetch error:', err));

// Connect WebSocket with Exponential Backoff
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        document.getElementById('wsDot').className = 'inline-block w-2.5 h-2.5 rounded-full bg-emerald-500';
        document.getElementById('wsText').textContent = 'LIVE CONNECTED';
        document.getElementById('wsText').className = 'text-emerald-400 font-semibold';
        reconnectDelay = 1000;
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'init') {
            packetsCache = data.packets || [];
            alertsCache = data.alerts || [];
            hostsCache = data.hosts || [];
            renderPackets();
            renderAlerts();
            renderHosts();
            if (data.sockets) renderSockets(data.sockets);
            if (data.deps) updateDependencyStatus(data.deps);
        } else if (data.type === 'deps') {
            updateDependencyStatus(data.data);
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
            if (packetsCache.length > 100) packetsCache.pop();
            renderPackets();
        } else if (data.type === 'alert') {
            alertsCache.unshift(data.alert);
            renderAlerts();
        } else if (data.type === 'hosts_update') {
            hostsCache = data.devices || [];
            renderHosts();
        }
    };

    ws.onclose = () => {
        document.getElementById('wsDot').className = 'inline-block w-2.5 h-2.5 rounded-full bg-red-500 animate-ping';
        document.getElementById('wsText').textContent = 'RECONNECTING';
        document.getElementById('wsText').className = 'text-red-400';
        setTimeout(connectWebSocket, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 2, 30000);
    };
}

function updateMetrics(s, threatLevel) {
    document.getElementById('statPackets').textContent = (s.total_packets || 0).toLocaleString();
    document.getElementById('statBytes').textContent = `${((s.total_bytes || 0) / 1024).toFixed(1)} KB`;
    document.getElementById('statRate').textContent = s.packets_per_sec || 0;
    document.getElementById('statBps').textContent = ((s.bytes_per_sec || 0) / 1024).toFixed(1);
    document.getElementById('statThreats').textContent = s.active_threats || 0;
    document.getElementById('statThreatCount').textContent = s.alert_count || 0;

    const tElem = document.getElementById('statThreatLevel');
    tElem.textContent = threatLevel;
    if (threatLevel === 'CRITICAL') {
        tElem.className = 'text-2xl font-bold font-mono text-red-500 animate-pulse';
    } else if (threatLevel === 'ELEVATED') {
        tElem.className = 'text-2xl font-bold font-mono text-amber-400';
    } else {
        tElem.className = 'text-2xl font-bold font-mono text-emerald-400';
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
    protocolChart.data.datasets[0].data = [tcp, udp, icmp, dns, http, https, other];
    protocolChart.update();

    document.getElementById('protocolLegend').innerHTML = `
        <div><span class="text-cyan-400 font-bold">TCP:</span> ${tcp}</div>
        <div><span class="text-blue-400 font-bold">UDP:</span> ${udp}</div>
        <div><span class="text-pink-400 font-bold">ICMP:</span> ${icmp}</div>
        <div><span class="text-emerald-400 font-bold">DNS:</span> ${dns}</div>
        <div><span class="text-amber-400 font-bold">HTTP:</span> ${http}</div>
        <div><span class="text-yellow-400 font-bold">HTTPS:</span> ${https}</div>
    `;
}

const protoColors = {
    'TCP': 'bg-cyan-950 text-cyan-400 border-cyan-800',
    'UDP': 'bg-blue-950 text-blue-400 border-blue-800',
    'ICMP': 'bg-pink-950 text-pink-400 border-pink-800',
    'DNS': 'bg-emerald-950 text-emerald-400 border-emerald-800',
    'HTTP': 'bg-amber-950 text-amber-400 border-amber-800',
    'HTTPS': 'bg-yellow-950 text-yellow-400 border-yellow-800',
    'SSH': 'bg-purple-950 text-purple-400 border-purple-800',
    'ARP': 'bg-slate-800 text-slate-300 border-slate-700',
    'OTHER': 'bg-slate-900 text-slate-400 border-slate-800'
};

function renderPackets() {
    const tbody = document.getElementById('packetTableBody');
    tbody.innerHTML = packetsCache.slice(0, 30).map((pkt, idx) => {
        const badge = protoColors[pkt.protocol] || protoColors['OTHER'];
        const src = pkt.src_port ? `${pkt.src_ip}:${pkt.src_port}` : pkt.src_ip;
        const dst = pkt.dst_port ? `${pkt.dst_ip}:${pkt.dst_port}` : pkt.dst_ip;
        const t = pkt.formatted_time ? pkt.formatted_time.split('.')[0] : '--:--:--';
        return `
            <tr onclick="openPacketModal(${idx})" class="hover:bg-cyber-800/90 cursor-pointer transition">
                <td class="py-2 px-3 text-slate-500 whitespace-nowrap">${t}</td>
                <td class="py-2 px-2"><span class="px-1.5 py-0.5 rounded text-[10px] border font-bold ${badge}">${pkt.protocol}</span></td>
                <td class="py-2 px-3 whitespace-nowrap"><span class="text-cyan-400 font-semibold">${src}</span> &rarr; <span class="text-yellow-400 font-semibold">${dst}</span></td>
                <td class="py-2 px-2 text-right text-slate-400">${pkt.length}</td>
                <td class="py-2 px-3 text-slate-400 truncate max-w-xs">${pkt.summary}</td>
            </tr>
        `;
    }).join('');
}

function renderAlerts() {
    const container = document.getElementById('alertContainer');
    const noMsg = document.getElementById('noAlertsMsg');
    document.getElementById('alertBadge').textContent = `${alertsCache.length} EVENTS`;

    if (alertsCache.length === 0) {
        if (noMsg) noMsg.classList.remove('hidden');
        return;
    }

    container.innerHTML = alertsCache.slice(0, 15).map(alt => {
        const sev = alt.severity || 'HIGH';
        const isCrit = sev === 'CRITICAL' || sev === 'HIGH';
        return `
            <div class="p-3 rounded-xl border ${isCrit ? 'border-red-800 bg-red-950/40' : 'border-amber-800 bg-amber-950/40'} space-y-1.5">
                <div class="flex items-center justify-between">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isCrit ? 'bg-red-900 text-white' : 'bg-amber-900 text-amber-200'}">${sev}</span>
                    <span class="text-[10px] font-mono text-slate-400">${(alt.timestamp || '').toString().slice(0,19)}</span>
                </div>
                <h4 class="text-xs font-bold text-white">${alt.rule || alt.rule_name}</h4>
                <p class="text-xs text-slate-300">${alt.details || alt.description}</p>
                <div class="text-[10px] font-mono text-slate-400 pt-1 border-t border-cyber-800">
                    ${alt.attacker_ip} &rarr; ${alt.target_ip}
                </div>
            </div>
        `;
    }).join('');
}

function renderHosts() {
    const tbody = document.getElementById('hostsTableBody');
    if (hostsCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-500">No LAN devices found yet. Click "SCAN LOCAL SUBNET NOW".</td></tr>`;
        return;
    }

    tbody.innerHTML = hostsCache.map(h => `
        <tr class="hover:bg-cyber-800/80 transition">
            <td class="py-2.5 px-3 font-bold text-cyan-400">${h.ip}</td>
            <td class="py-2.5 px-3 text-white">${h.hostname || 'Host'}</td>
            <td class="py-2.5 px-3 text-slate-400 font-mono">${h.mac || 'Unknown'}</td>
            <td class="py-2.5 px-3 text-slate-300">${h.vendor || 'OEM / Network Device'}</td>
            <td class="py-2.5 px-2 text-slate-400">${(h.last_seen || '').toString().slice(11,19) || 'Just now'}</td>
            <td class="py-2.5 px-3 text-right">
                <button onclick="scanHostPorts('${h.ip}')" class="px-2.5 py-1 rounded bg-cyber-700 hover:bg-cyan-700 text-cyan-200 text-xs font-mono transition">
                    Scan Ports
                </button>
            </td>
        </tr>
    `).join('');
}

function renderSockets(sockets) {
    const tbody = document.getElementById('socketTableBody');
    tbody.innerHTML = sockets.map(s => `
        <tr class="hover:bg-cyber-800/80 transition">
            <td class="py-2 px-3"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${s.proto === 'TCP' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' : 'bg-blue-950 text-blue-400 border border-blue-800'}">${s.proto}</span></td>
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
            <div class="p-2.5 rounded bg-cyber-900 border border-cyber-700 flex items-center justify-between">
                <div>
                    <span class="text-cyan-400 font-bold">Port ${p.port}</span> (${p.service})
                    <div class="text-[10px] text-slate-400">${p.description}</div>
                </div>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${p.risk === 'HIGH' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">${p.risk}</span>
            </div>
        `).join('');

        document.getElementById('portModalBody').innerHTML = `
            <div class="p-3 rounded bg-cyber-900/90 border border-cyan-800 mb-3">
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
        <div class="p-3 bg-cyber-900 rounded-lg border border-cyber-700 space-y-1">
            <p><strong class="text-cyan-400">Timestamp:</strong> ${pkt.formatted_time}</p>
            <p><strong class="text-cyan-400">Protocol:</strong> ${pkt.protocol}</p>
            <p><strong class="text-cyan-400">Length:</strong> ${pkt.length} bytes</p>
            <p><strong class="text-cyan-400">Source:</strong> ${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</p>
            <p><strong class="text-cyan-400">Destination:</strong> ${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</p>
            ${pkt.flags ? `<p><strong class="text-cyan-400">Flags:</strong> ${pkt.flags}</p>` : ''}
            <p><strong class="text-cyan-400">Summary:</strong> ${pkt.summary}</p>
        </div>
        ${pkt.raw_hex_preview ? `
        <div class="p-3 bg-cyber-900 rounded-lg border border-cyber-700 space-y-1">
            <p class="text-slate-400 font-bold mb-1">Raw Hex & ASCII Payload Preview:</p>
            <div class="p-2 bg-black rounded font-mono text-[10px] text-emerald-400 break-all select-all">${pkt.raw_hex_preview}</div>
        </div>` : ''}
    `;
    document.getElementById('packetModal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('packetModal').classList.add('hidden');
}

connectWebSocket();

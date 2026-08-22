// CyberShield Live SOC Dashboard v2.5
let packetsCache = [];
let alertsCache = [];
let hostsCache = [];
let socketsCache = [];
let talkersCache = [];
let blockedIpsCache = [];
let throughputData = new Array(60).fill(0);
let reconnectDelay = 1000;
let ws = null;
let currentFilter = 'ALL';
let currentTab = 'hud';

// Initialize Chart.js Throughput Line Chart
const ctxThroughput = document.getElementById('throughputChart')?.getContext('2d');
let throughputChart = null;
if (ctxThroughput) {
    throughputChart = new Chart(ctxThroughput, {
        type: 'line',
        data: {
            labels: new Array(60).fill(''),
            datasets: [{
                label: 'Packets/sec',
                data: throughputData,
                borderColor: '#1d6dff',
                backgroundColor: 'rgba(29, 109, 255, 0.12)',
                borderWidth: 2,
                fill: true,
                tension: 0.35,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            scales: {
                x: { display: false },
                y: {
                    grid: { color: 'rgba(29, 109, 255, 0.08)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } },
                    beginAtZero: true
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// Initialize Protocol Donut Chart
const ctxProtocol = document.getElementById('protocolChart')?.getContext('2d');
let protocolChart = null;
if (ctxProtocol) {
    protocolChart = new Chart(ctxProtocol, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'Other'],
            datasets: [{
                data: [1, 1, 1, 1, 1, 1, 1],
                backgroundColor: ['#1d6dff', '#3b82f6', '#ec4899', '#10b981', '#f59e0b', '#eab308', '#64748b'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 0 },
            plugins: { legend: { display: false } },
            cutout: '72%'
        }
    });
}

// Switch Tabs (HUD, Threats, Talkers, Sockets, Hosts/Scan, Manual)
async function switchTab(tabName) {
    if (tabName === 'scan') tabName = 'hosts';
    if (tabName === 'ps') tabName = 'sockets';
    currentTab = tabName;

    // Update URL hash without jumping page
    history.replaceState(null, null, `#${tabName}`);

    const tabs = ['hud', 'threats', 'talkers', 'sockets', 'hosts', 'manual'];
    tabs.forEach(t => {
        const viewEl = document.getElementById(`view-${t}`);
        const tabEl = document.getElementById(`tab-${t}`);
        if (viewEl) {
            if (t === tabName) viewEl.classList.remove('hidden');
            else viewEl.classList.add('hidden');
        }
        if (tabEl) {
            if (t === tabName) {
                tabEl.className = 'px-3 py-1.5 rounded-lg font-bold bg-blue-600 text-white shadow-md transition';
            } else {
                tabEl.className = 'px-3 py-1.5 rounded-lg font-bold text-slate-400 hover:text-white hover:bg-slate-800/80 transition';
            }
        }
    });

    // Immediate Data Fetch and Render for Sub-Modules
    if (tabName === 'threats') {
        if (alertsCache.length === 0) {
            try {
                const r = await fetch('/api/alerts');
                alertsCache = await r.json();
            } catch(e) {}
        }
        renderFullThreats();
    } else if (tabName === 'talkers') {
        if (talkersCache.length === 0) {
            try {
                const r = await fetch('/api/talkers');
                talkersCache = await r.json();
            } catch(e) {}
        }
        renderTalkers();
    } else if (tabName === 'sockets') {
        if (socketsCache.length === 0) {
            try {
                const r = await fetch('/api/sockets');
                socketsCache = await r.json();
            } catch(e) {}
        }
        renderFullSockets();
    } else if (tabName === 'hosts') {
        if (hostsCache.length === 0) {
            try {
                const r = await fetch('/api/hosts');
                hostsCache = await r.json();
            } catch(e) {}
        }
        renderHosts();
    } else if (tabName === 'hud') {
        renderPackets();
        renderAlerts();
    }
}

// Connect WebSocket with Automatic Recovery
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        const dot = document.getElementById('wsDot');
        const txt = document.getElementById('wsText');
        if (dot) dot.className = 'inline-block w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping';
        if (txt) {
            txt.textContent = '● LIVE';
            txt.className = 'text-emerald-400 font-bold';
        }
        reconnectDelay = 1000;
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'init') {
                packetsCache = data.packets || [];
                alertsCache = data.alerts || [];
                hostsCache = data.hosts || [];
                socketsCache = data.sockets || [];
                talkersCache = data.talkers || [];
                blockedIpsCache = data.blocked_ips || [];
                renderPackets();
                renderAlerts();
                if (currentTab === 'threats') renderFullThreats();
                if (currentTab === 'talkers') renderTalkers();
                if (currentTab === 'hosts') renderHosts();
                if (currentTab === 'sockets') renderFullSockets();
                if (data.stats) updateMetrics(data.stats, data.threat_level || 'NOMINAL');
                if (data.throughput && throughputChart) {
                    throughputChart.data.datasets[0].data = data.throughput;
                    throughputChart.update();
                }
            } else if (data.type === 'tick') {
                if (data.stats) updateMetrics(data.stats, data.threat_level);
                if (data.throughput && throughputChart) {
                    throughputChart.data.datasets[0].data = data.throughput;
                    throughputChart.update();
                }
                if (data.protocols) updateProtocols(data.protocols);
                if (data.new_packets && data.new_packets.length > 0) {
                    for (let i = data.new_packets.length - 1; i >= 0; i--) {
                        packetsCache.unshift(data.new_packets[i]);
                    }
                    if (packetsCache.length > 100) packetsCache.length = 100;
                    if (currentTab === 'hud') renderPackets();
                }
                if (data.sockets) {
                    socketsCache = data.sockets;
                    if (currentTab === 'sockets') renderFullSockets();
                }
                if (data.talkers) {
                    talkersCache = data.talkers;
                    if (currentTab === 'talkers') renderTalkers();
                }
                if (data.blocked_ips) blockedIpsCache = data.blocked_ips;
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
        setTimeout(connectWebSocket, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 1.5, 5000);
    };
}

// Fallback background polling every 2.5s
setInterval(async () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        try {
            const [statsRes, pktsRes, altsRes] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/packets'),
                fetch('/api/alerts')
            ]);
            const s = await statsRes.json();
            const p = await pktsRes.json();
            const a = await altsRes.json();

            updateMetrics(s, s.threat_level);
            if (s.throughput && throughputChart) {
                throughputChart.data.datasets[0].data = s.throughput;
                throughputChart.update();
            }
            if (s.protocols) updateProtocols(s.protocols);
            if (Array.isArray(p)) {
                packetsCache = p;
                if (currentTab === 'hud') renderPackets();
            }
            if (Array.isArray(a)) {
                alertsCache = a;
                renderAlerts();
                if (currentTab === 'threats') renderFullThreats();
            }
        } catch (e) {}
    }
}, 2500);

function updateMetrics(s, threatLevel) {
    if (!s) return;
    const pElem = document.getElementById('statPackets');
    if (pElem) pElem.textContent = (s.total_packets || 0).toLocaleString();
    const bElem = document.getElementById('statBytes');
    if (bElem) bElem.textContent = `${((s.total_bytes || 0) / 1024).toFixed(1)} KB`;
    const rElem = document.getElementById('statRate');
    if (rElem) rElem.textContent = s.packets_per_sec || 0;
    const bpsElem = document.getElementById('statBps');
    if (bpsElem) bpsElem.textContent = ((s.bytes_per_sec || 0) / 1024).toFixed(1);
    const thElem = document.getElementById('statThreats');
    if (thElem) thElem.textContent = s.active_threats || s.threat_count || 0;
    const tcElem = document.getElementById('statThreatCount');
    if (tcElem) tcElem.textContent = s.alert_count || s.threat_count || 0;

    const navBadge = document.getElementById('navThreatBadge');
    if (navBadge) navBadge.textContent = s.active_threats || s.threat_count || 0;

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
    if (total > 0 && protocolChart) {
        protocolChart.data.datasets[0].data = [tcp, udp, icmp, dns, http, https, other];
        protocolChart.update();
    }
}

function setProtoFilter(proto) {
    currentFilter = proto;
    ['ALL', 'TCP', 'UDP', 'DNS', 'HTTP'].forEach(p => {
        const btn = document.getElementById(`btnFilter${p}`);
        if (btn) {
            if (p === proto) btn.className = 'px-2.5 py-1 rounded bg-blue-600 text-white font-bold';
            else btn.className = 'px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white';
        }
    });
    renderPackets();
}

function filterPackets() {
    renderPackets();
}

function renderPackets() {
    const tbody = document.getElementById('packetTableBody');
    if (!tbody) return;
    const searchVal = (document.getElementById('packetSearch')?.value || '').toLowerCase();

    let filtered = packetsCache;
    if (currentFilter !== 'ALL') {
        if (currentFilter === 'HTTP') {
            filtered = filtered.filter(p => p.protocol === 'HTTP' || p.protocol === 'HTTPS');
        } else {
            filtered = filtered.filter(p => p.protocol === currentFilter);
        }
    }
    if (searchVal) {
        filtered = filtered.filter(p => 
            (p.src_ip && p.src_ip.includes(searchVal)) || 
            (p.dst_ip && p.dst_ip.includes(searchVal)) ||
            (p.summary && p.summary.toLowerCase().includes(searchVal))
        );
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500">Listening on interface... Intercepting live traffic.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.slice(0, 35).map((pkt, idx) => {
        let protoClass = 'bg-blue-950/80 text-blue-400 border border-blue-500/40';
        if (pkt.protocol === 'UDP') protoClass = 'bg-indigo-950/80 text-indigo-400 border border-indigo-500/40';
        else if (pkt.protocol === 'ICMP') protoClass = 'bg-pink-950/80 text-pink-400 border border-pink-500/40';
        else if (pkt.protocol === 'DNS') protoClass = 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40';
        else if (pkt.protocol === 'HTTP' || pkt.protocol === 'HTTPS') protoClass = 'bg-amber-950/80 text-amber-400 border border-amber-500/40';

        const timeStr = pkt.formatted_time ? pkt.formatted_time.split(' ')[1] || pkt.formatted_time : '00:00:00';
        const src = `${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}`;
        const dst = `${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}`;

        return `
            <tr onclick="openPacketModal(${idx})" class="hover:bg-blue-950/40 cursor-pointer transition border-b border-slate-800/40">
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
    if (!container) return;

    if (alertsCache.length === 0) {
        if (noMsg) noMsg.classList.remove('hidden');
        return;
    }
    if (noMsg) noMsg.classList.add('hidden');

    container.innerHTML = alertsCache.slice(0, 15).map(alt => {
        const sev = alt.severity || 'HIGH';
        const isCrit = sev === 'CRITICAL' || sev === 'HIGH';
        const isBlocked = blockedIpsCache.includes(alt.attacker_ip);

        return `
            <div class="p-3.5 rounded-xl border ${isCrit ? 'border-red-500/40 bg-red-950/30' : 'border-amber-500/40 bg-amber-950/30'} space-y-1.5 backdrop-blur-sm shadow-md">
                <div class="flex items-center justify-between">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isCrit ? 'bg-red-900 text-white' : 'bg-amber-900 text-amber-200'}">${sev}</span>
                    <span class="text-[10px] font-mono text-slate-400">${(alt.timestamp || '').toString().slice(0,19)}</span>
                </div>
                <h4 class="text-xs font-bold text-white">${alt.rule || alt.rule_name || 'Threat Detected'}</h4>
                <p class="text-xs text-slate-300 leading-relaxed">${alt.details || alt.description || 'Heuristic anomaly trigger.'}</p>
                <div class="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-700/50">
                    <span>${alt.attacker_ip} &rarr; ${alt.target_ip}</span>
                    ${isBlocked 
                        ? `<span class="text-emerald-400 font-bold">🛑 ISOLATED</span>`
                        : `<button onclick="blockIP('${alt.attacker_ip}')" class="px-2 py-0.5 rounded bg-red-800 hover:bg-red-700 text-white font-bold transition">BLOCK IP</button>`
                    }
                </div>
            </div>
        `;
    }).join('');
}

function renderFullThreats() {
    const container = document.getElementById('threatsFullContainer');
    if (!container) return;

    if (alertsCache.length === 0) {
        container.innerHTML = `<div class="col-span-2 text-center py-12 text-slate-500 font-mono">No active threats detected. All perimeter traffic nominal.</div>`;
        return;
    }

    container.innerHTML = alertsCache.map(alt => {
        const sev = alt.severity || 'HIGH';
        const isCrit = sev === 'CRITICAL' || sev === 'HIGH';
        const isBlocked = blockedIpsCache.includes(alt.attacker_ip);

        return `
            <div class="glass-panel p-5 space-y-3 ${isCrit ? 'border-red-500/50' : 'border-amber-500/50'}">
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-2">
                        <span class="px-2.5 py-0.5 rounded text-xs font-bold ${isCrit ? 'bg-red-900 text-white' : 'bg-amber-900 text-amber-200'}">${sev}</span>
                        <h3 class="font-bold text-white text-sm">${alt.rule || alt.rule_name || 'Network Intrusion Event'}</h3>
                    </div>
                    <span class="text-xs font-mono text-slate-400">${(alt.timestamp || '').toString().slice(0,19)}</span>
                </div>
                <p class="text-xs text-slate-300 leading-relaxed">${alt.details || alt.description || 'Sliding window heuristic anomaly alert.'}</p>
                <div class="p-3 rounded-lg bg-black/50 border border-slate-800 text-xs font-mono flex items-center justify-between">
                    <div>
                        <span class="text-slate-500">Attacker IP: </span><span class="text-red-400 font-bold">${alt.attacker_ip}</span>
                        <span class="text-slate-500 ml-3">Target IP: </span><span class="text-cyan-400 font-bold">${alt.target_ip}</span>
                    </div>
                    <div>
                        ${isBlocked
                            ? `<button onclick="unblockIP('${alt.attacker_ip}')" class="px-3 py-1 rounded bg-emerald-950 border border-emerald-500/50 text-emerald-400 font-bold text-xs hover:bg-emerald-900 transition">UNBLOCK IP</button>`
                            : `<button onclick="blockIP('${alt.attacker_ip}')" class="px-3 py-1 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow-md transition">🛑 BAN ATTACKER</button>`
                        }
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function renderTalkers() {
    const tbody = document.getElementById('talkersTableBody');
    if (!tbody) return;

    if (talkersCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-slate-500 font-mono">Sampling talker endpoints...</td></tr>`;
        return;
    }

    tbody.innerHTML = talkersCache.map((t, idx) => {
        const isBlocked = blockedIpsCache.includes(t.ip);
        return `
            <tr class="hover:bg-blue-950/40 transition border-b border-slate-800/40 font-mono">
                <td class="py-3 px-4 text-blue-400 font-bold">#${idx + 1}</td>
                <td class="py-3 px-4 text-white font-bold">${t.ip}</td>
                <td class="py-3 px-4 text-slate-300">${t.packets.toLocaleString()}</td>
                <td class="py-3 px-4 text-cyan-300">${t.formatted_bytes}</td>
                <td class="py-3 px-4">
                    <div class="flex items-center gap-2">
                        <div class="w-24 bg-slate-800 rounded-full h-2 overflow-hidden">
                            <div class="bg-blue-500 h-2 rounded-full" style="width: ${Math.min(t.percent, 100)}%"></div>
                        </div>
                        <span class="text-xs text-slate-400">${t.percent}%</span>
                    </div>
                </td>
                <td class="py-3 px-4 text-right">
                    <button onclick="scanHostPorts('${t.ip}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-blue-600 text-white text-xs mr-2 transition">Scan Ports</button>
                    ${isBlocked
                        ? `<button onclick="unblockIP('${t.ip}')" class="px-2.5 py-1 rounded bg-emerald-950 border border-emerald-500/50 text-emerald-400 text-xs font-bold transition">Unblock</button>`
                        : `<button onclick="blockIP('${t.ip}')" class="px-2.5 py-1 rounded bg-red-950 border border-red-500/40 text-red-300 hover:bg-red-900 text-xs font-bold transition">Block</button>`
                    }
                </td>
            </tr>
        `;
    }).join('');
}

function renderFullSockets() {
    const tbody = document.getElementById('fullSocketTableBody');
    if (!tbody) return;
    if (socketsCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-slate-500">Polling local system sockets...</td></tr>`;
        return;
    }

    tbody.innerHTML = socketsCache.map(s => `
        <tr class="hover:bg-blue-950/40 transition border-b border-slate-800/40 font-mono">
            <td class="py-3 px-4"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${s.proto === 'TCP' ? 'bg-blue-950 text-blue-400 border border-blue-500/40' : 'bg-indigo-950 text-indigo-400 border border-indigo-500/40'}">${s.proto}</span></td>
            <td class="py-3 px-4 font-semibold text-white">${s.pname}</td>
            <td class="py-3 px-4 text-slate-400 font-mono">${s.pid}</td>
            <td class="py-3 px-4 text-cyan-300 font-mono">${s.local}</td>
            <td class="py-3 px-4 text-yellow-300 font-mono">${s.remote}</td>
            <td class="py-3 px-4 text-center"><span class="px-2 py-0.5 rounded text-[10px] font-mono ${s.state === 'LISTEN' ? 'bg-purple-950 text-purple-400 border border-purple-800 font-bold' : (s.state === 'ESTABLISHED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400')}">${s.state}</span></td>
        </tr>
    `).join('');
}

function renderHosts() {
    const tbody = document.getElementById('hostsTableBody');
    if (!tbody) return;
    if (hostsCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-slate-500 font-mono">No LAN devices found yet. Click "SCAN LOCAL SUBNET NOW".</td></tr>`;
        return;
    }

    tbody.innerHTML = hostsCache.map(h => `
        <tr class="hover:bg-blue-950/40 transition border-b border-slate-800/40 font-mono">
            <td class="py-3 px-4 font-bold text-cyan-400">${h.ip}</td>
            <td class="py-3 px-4 text-white">${h.hostname || 'Host'}</td>
            <td class="py-3 px-4 text-slate-400 font-mono">${h.mac || 'Unknown'}</td>
            <td class="py-3 px-4 text-slate-300">${h.vendor || 'OEM / Network Device'}</td>
            <td class="py-3 px-4 text-slate-400">${(h.last_seen || '').toString().slice(11,19) || 'Just now'}</td>
            <td class="py-3 px-4 text-right">
                <button onclick="scanHostPorts('${h.ip}')" class="px-3 py-1 rounded bg-slate-800 hover:bg-blue-600 text-white text-xs font-mono transition">
                    Scan Ports
                </button>
            </td>
        </tr>
    `).join('');
}

async function blockIP(ip) {
    try {
        await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, reason: 'Manual web ban' })
        });
        if (!blockedIpsCache.includes(ip)) blockedIpsCache.push(ip);
        renderAlerts();
        renderFullThreats();
        renderTalkers();
    } catch (e) {
        console.error(e);
    }
}

async function unblockIP(ip) {
    try {
        await fetch('/api/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        blockedIpsCache = blockedIpsCache.filter(x => x !== ip);
        renderAlerts();
        renderFullThreats();
        renderTalkers();
    } catch (e) {
        console.error(e);
    }
}

async function toggleAutoBlock() {
    try {
        const res = await fetch('/api/firewall/toggle-autoblock', { method: 'POST' });
        const data = await res.json();
        const btn = document.getElementById('btnAutoBlock');
        if (btn) {
            btn.textContent = data.autoblock_enabled ? 'ON' : 'OFF';
            btn.className = data.autoblock_enabled
                ? 'px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/50 hover:scale-105 transition font-bold'
                : 'px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/50 hover:scale-105 transition font-bold';
        }
    } catch (e) {}
}

async function simulateAttack(type) {
    try {
        const res = await fetch('/api/simulate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: type })
        });
        const data = await res.json();
        if (data.active_threats) {
            const altsRes = await fetch('/api/alerts');
            alertsCache = await altsRes.json();
            renderAlerts();
            if (currentTab === 'threats') renderFullThreats();
        }
    } catch (e) {
        console.error(e);
    }
}

async function scanLocalSubnet() {
    const btn = document.getElementById('btnSubnetScan');
    const spin = document.getElementById('scanSpin');
    if (btn) btn.disabled = true;
    if (spin) spin.classList.remove('hidden');

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
        if (btn) btn.disabled = false;
        if (spin) spin.classList.add('hidden');
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
            <div class="p-2.5 rounded bg-black/50 border border-blue-500/30 flex items-center justify-between">
                <div>
                    <span class="text-cyan-400 font-bold">Port ${p.port}</span> (${p.service})
                    <div class="text-[10px] text-slate-400">${p.description}</div>
                </div>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${p.risk === 'HIGH' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">${p.risk}</span>
            </div>
        `).join('');

        document.getElementById('portModalBody').innerHTML = `
            <div class="p-3 rounded bg-black/60 border border-blue-500/40 mb-3">
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
        <div class="p-3 bg-black/60 rounded-lg border border-blue-500/30 space-y-1">
            <p><strong class="text-blue-400">Timestamp:</strong> ${pkt.formatted_time}</p>
            <p><strong class="text-blue-400">Protocol:</strong> ${pkt.protocol}</p>
            <p><strong class="text-blue-400">Length:</strong> ${pkt.length} bytes</p>
            <p><strong class="text-blue-400">Source:</strong> ${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</p>
            <p><strong class="text-blue-400">Destination:</strong> ${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</p>
            ${pkt.flags ? `<p><strong class="text-blue-400">Flags:</strong> ${pkt.flags}</p>` : ''}
            <p><strong class="text-blue-400">Summary:</strong> ${pkt.summary}</p>
        </div>
        ${pkt.raw_hex_preview ? `
        <div class="p-3 bg-black/60 rounded-lg border border-blue-500/30 space-y-1">
            <p class="text-slate-400 font-bold mb-1">Raw Hex & ASCII Payload Preview:</p>
            <div class="p-2 bg-black rounded font-mono text-[10px] text-emerald-400 break-all select-all">${pkt.raw_hex_preview}</div>
        </div>` : ''}
    `;
    document.getElementById('packetModal').classList.remove('hidden');
}

function closeModal() {
    document.getElementById('packetModal').classList.add('hidden');
}

// URL Route Handler: support #threats, #scan, #sockets, #talkers or ?tab=threats
function handleUrlRouting() {
    const urlParams = new URLSearchParams(window.location.search);
    const tabParam = urlParams.get('tab');
    const hash = window.location.hash.replace('#', '');
    const targetTab = tabParam || hash;

    if (targetTab) {
        if (targetTab === 'scan' || targetTab === 'radar') {
            switchTab('hosts');
        } else {
            switchTab(targetTab);
        }
    }
}

window.addEventListener('hashchange', handleUrlRouting);
window.addEventListener('DOMContentLoaded', () => {
    handleUrlRouting();
    connectWebSocket();
});

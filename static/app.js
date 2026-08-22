// CyberShield Live SOC Dashboard v2.5 (Dual-Mode: Real Python Backend & GitHub Pages Simulator)
let packetsCache = [];
let alertsCache = [];
let hostsCache = [
    { ip: "192.168.1.1", hostname: "gateway.local", mac: "00:50:56:C0:00:01", vendor: "Cisco Systems", last_seen: "Just now" },
    { ip: "192.168.1.105", hostname: "soc-operator-host", mac: "D4:5D:64:88:B1:20", vendor: "Intel Corporate", last_seen: "Just now" },
    { ip: "192.168.1.120", hostname: "storage-nas.lan", mac: "00:11:32:45:67:89", vendor: "Synology Inc", last_seen: "1 min ago" },
    { ip: "192.168.1.145", hostname: "workstation-dev.lan", mac: "3C:D9:2B:11:22:33", vendor: "Dell Inc", last_seen: "30s ago" }
];
let socketsCache = [];
let talkersCache = [];
let blockedIpsCache = [];
let throughputData = new Array(60).fill(0);
let reconnectDelay = 1000;
let ws = null;
let currentFilter = 'ALL';
let currentTab = 'hud';
let isStaticMode = window.location.hostname.includes('github.io') || window.location.protocol === 'file:';

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
            animation: { duration: 0 },
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
}

// -------------------------------------------------------------
// 3D CYBER GLOBE ENGINE (Real-Time Network Traffic Vector Sphere)
// -------------------------------------------------------------
let globeData = { TCP: 0, UDP: 0, ICMP: 0, DNS: 0, HTTP: 0, HTTPS: 0, OTHER: 0 };
let globeArcs = [];

(function init3DCyberGlobe() {
    const canvas = document.getElementById('cyberGlobeCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let W = canvas.width = canvas.parentElement.clientWidth || 300;
    let H = canvas.height = canvas.parentElement.clientHeight || 180;

    window.addEventListener('resize', () => {
        if (canvas.parentElement) {
            W = canvas.width = canvas.parentElement.clientWidth || 300;
            H = canvas.height = canvas.parentElement.clientHeight || 180;
        }
    });

    const GLOBE_RADIUS = Math.min(W, H) * 0.38;
    let rotX = 0.28;
    let rotY = 0;
    let autoRotSpeed = 0.008;

    // Defined 3D Global Nodes (Latitude, Longitude in radians)
    const nodes = [
        { lat: 0.65, lon: -1.3, label: 'Local SOC', color: '#00dcff' },     // Local Host
        { lat: 0.72, lon: -2.1, label: 'US-West Gateway', color: '#1d6dff' },// Gateway 1
        { lat: 0.70, lon: -1.25, label: 'US-East DNS', color: '#10b981' },   // Gateway 2
        { lat: 0.90, lon: 0.2, label: 'EU-North Core', color: '#1d6dff' },   // Gateway 3
        { lat: 0.85, lon: 0.4, label: 'Frankfurt Hub', color: '#00dcff' },   // Gateway 4
        { lat: 0.50, lon: 1.35, label: 'APAC-Tokyo', color: '#f59e0b' },     // Gateway 5
        { lat: 0.22, lon: 1.8, label: 'Singapore Edge', color: '#10b981' },  // Gateway 6
        { lat: -0.58, lon: 2.6, label: 'Sydney Cloud', color: '#00dcff' },   // Gateway 7
        { lat: -0.40, lon: -0.8, label: 'SA-SaoPaulo', color: '#ec4899' }    // Gateway 8
    ];

    function latLonTo3D(lat, lon, r) {
        return {
            x: r * Math.cos(lat) * Math.sin(lon),
            y: -r * Math.sin(lat),
            z: r * Math.cos(lat) * Math.cos(lon)
        };
    }

    function project3D(p3, rx, ry, cx, cy) {
        const cosY = Math.cos(ry), sinY = Math.sin(ry);
        const x1 = p3.x * cosY + p3.z * sinY;
        const z1 = -p3.x * sinY + p3.z * cosY;

        const cosX = Math.cos(rx), sinX = Math.sin(rx);
        const y2 = p3.y * cosX - z1 * sinX;
        const z2 = p3.y * sinX + z1 * cosX;

        const cameraDist = 450;
        const scale = cameraDist / (cameraDist + z2);

        return {
            x: cx + x1 * scale,
            y: cy + y2 * scale,
            z: z2,
            scale: scale,
            visible: z2 < 60
        };
    }

    window.spawnGlobeTrafficArc = function(proto = 'TCP') {
        const fromIdx = Math.floor(Math.random() * nodes.length);
        let toIdx = Math.floor(Math.random() * nodes.length);
        if (toIdx === fromIdx) toIdx = (fromIdx + 1) % nodes.length;

        let arcColor = '#00dcff';
        if (proto === 'TCP') arcColor = '#1d6dff';
        else if (proto === 'DNS') arcColor = '#10b981';
        else if (proto === 'HTTP' || proto === 'HTTPS') arcColor = '#f59e0b';
        else if (proto === 'ICMP') arcColor = '#ec4899';
        else if (proto === 'THREAT') arcColor = '#ef4444';

        globeArcs.push({
            from: nodes[fromIdx],
            to: nodes[toIdx],
            progress: 0,
            speed: 0.02 + Math.random() * 0.025,
            color: arcColor
        });

        if (globeArcs.length > 25) globeArcs.shift();
    };

    function renderGlobe() {
        ctx.clearRect(0, 0, W, H);
        const cx = W / 2;
        const cy = H / 2;
        const R = Math.min(W, H) * 0.38;

        rotY += autoRotSpeed;

        const grad = ctx.createRadialGradient(cx, cy, R * 0.6, cx, cy, R * 1.15);
        grad.addColorStop(0, 'rgba(0, 220, 255, 0.08)');
        grad.addColorStop(0.7, 'rgba(29, 109, 255, 0.04)');
        grad.addColorStop(1, 'transparent');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(cx, cy, R * 1.15, 0, Math.PI * 2);
        ctx.fill();

        ctx.lineWidth = 0.75;
        const latSteps = [-1.1, -0.7, -0.35, 0, 0.35, 0.7, 1.1];
        latSteps.forEach(lat => {
            ctx.beginPath();
            let first = true;
            for (let lon = 0; lon <= Math.PI * 2 + 0.1; lon += 0.2) {
                const p3 = latLonTo3D(lat, lon, R);
                const proj = project3D(p3, rotX, rotY, cx, cy);
                if (proj.z > 0) {
                    ctx.strokeStyle = `rgba(0, 220, 255, ${0.08 + (proj.z / R) * 0.12})`;
                } else {
                    ctx.strokeStyle = 'rgba(0, 220, 255, 0.03)';
                }
                if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
                else ctx.lineTo(proj.x, proj.y);
            }
            ctx.stroke();
        });

        for (let m = 0; m < 8; m++) {
            const lon = (m / 8) * Math.PI * 2;
            ctx.beginPath();
            let first = true;
            for (let lat = -Math.PI/2; lat <= Math.PI/2 + 0.1; lat += 0.15) {
                const p3 = latLonTo3D(lat, lon, R);
                const proj = project3D(p3, rotX, rotY, cx, cy);
                if (proj.z > 0) {
                    ctx.strokeStyle = `rgba(0, 220, 255, ${0.08 + (proj.z / R) * 0.12})`;
                } else {
                    ctx.strokeStyle = 'rgba(0, 220, 255, 0.03)';
                }
                if (first) { ctx.moveTo(proj.x, proj.y); first = false; }
                else ctx.lineTo(proj.x, proj.y);
            }
            ctx.stroke();
        }

        for (let i = globeArcs.length - 1; i >= 0; i--) {
            const arc = globeArcs[i];
            arc.progress += arc.speed;

            const p1 = latLonTo3D(arc.from.lat, arc.from.lon, R);
            const p2 = latLonTo3D(arc.to.lat, arc.to.lon, R);

            const midX = (p1.x + p2.x) * 0.5;
            const midY = (p1.y + p2.y) * 0.5;
            const midZ = (p1.z + p2.z) * 0.5;
            const midLen = Math.hypot(midX, midY, midZ) || 1;
            const arcHeight = R * 1.35;
            const elevatedMid = {
                x: (midX / midLen) * arcHeight,
                y: (midY / midLen) * arcHeight,
                z: (midZ / midLen) * arcHeight
            };

            const t = arc.progress;
            const omt = 1 - t;
            const curr3D = {
                x: omt * omt * p1.x + 2 * omt * t * elevatedMid.x + t * t * p2.x,
                y: omt * omt * p1.y + 2 * omt * t * elevatedMid.y + t * t * p2.y,
                z: omt * omt * p1.z + 2 * omt * t * elevatedMid.z + t * t * p2.z
            };

            const projCurr = project3D(curr3D, rotX, rotY, cx, cy);

            if (projCurr.z > -R * 0.4) {
                ctx.beginPath();
                ctx.arc(projCurr.x, projCurr.y, 2.5 * projCurr.scale, 0, Math.PI * 2);
                ctx.fillStyle = '#ffffff';
                ctx.shadowColor = arc.color;
                ctx.shadowBlur = 8;
                ctx.fill();
                ctx.shadowBlur = 0;

                const projStart = project3D(p1, rotX, rotY, cx, cy);
                ctx.beginPath();
                ctx.moveTo(projStart.x, projStart.y);
                ctx.lineTo(projCurr.x, projCurr.y);
                ctx.strokeStyle = arc.color;
                ctx.lineWidth = 1.2 * projCurr.scale;
                ctx.stroke();
            }

            if (arc.progress >= 1) {
                globeArcs.splice(i, 1);
            }
        }

        nodes.forEach(node => {
            const p3 = latLonTo3D(node.lat, node.lon, R);
            const proj = project3D(p3, rotX, rotY, cx, cy);

            if (proj.z > -R * 0.3) {
                const alpha = Math.max(0.2, (proj.z + R) / (2 * R));
                ctx.beginPath();
                ctx.arc(proj.x, proj.y, 3 * proj.scale, 0, Math.PI * 2);
                ctx.fillStyle = node.color;
                ctx.shadowColor = node.color;
                ctx.shadowBlur = 6;
                ctx.fill();
                ctx.shadowBlur = 0;

                ctx.beginPath();
                ctx.arc(proj.x, proj.y, 5.5 * proj.scale, 0, Math.PI * 2);
                ctx.strokeStyle = `rgba(255, 255, 255, ${alpha * 0.6})`;
                ctx.lineWidth = 0.8;
                ctx.stroke();
            }
        });

        requestAnimationFrame(renderGlobe);
    }

    renderGlobe();
})();

// Switch Tabs (HUD, Threats, Talkers, Sockets, Hosts/Scan, Manual)
async function switchTab(tabName) {
    if (tabName === 'scan') tabName = 'hosts';
    if (tabName === 'ps') tabName = 'sockets';
    currentTab = tabName;

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
                tabEl.className = 'px-3 py-1.5 rounded-lg font-bold bg-cyan-500 text-black shadow-md transition';
            } else {
                tabEl.className = 'px-3 py-1.5 rounded-lg font-bold text-slate-400 hover:text-white hover:bg-slate-800/80 transition';
            }
        }
    });

    if (tabName === 'threats') {
        if (!isStaticMode && alertsCache.length === 0) {
            try {
                const r = await fetch('/api/alerts');
                alertsCache = await r.json();
            } catch(e) {}
        }
        renderFullThreats();
    } else if (tabName === 'talkers') {
        if (!isStaticMode && talkersCache.length === 0) {
            try {
                const r = await fetch('/api/talkers');
                talkersCache = await r.json();
            } catch(e) {}
        }
        renderTalkers();
    } else if (tabName === 'sockets') {
        if (!isStaticMode && socketsCache.length === 0) {
            try {
                const r = await fetch('/api/sockets');
                socketsCache = await r.json();
            } catch(e) {}
        }
        renderFullSockets();
    } else if (tabName === 'hosts') {
        if (!isStaticMode && hostsCache.length === 0) {
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

// -------------------------------------------------------------
// GITHUB PAGES / STATIC SIMULATION ENGINE
// -------------------------------------------------------------
let simStats = {
    total_packets: 4820,
    total_bytes: 3482100,
    packets_per_sec: 24.5,
    bytes_per_sec: 18540,
    protocols: { TCP: 2840, UDP: 980, ICMP: 120, DNS: 540, HTTP: 340, HTTPS: 0, OTHER: 0 },
    alert_count: 1,
    active_threats: 0,
    autoblock_enabled: true
};

function initStaticSimulation() {
    const dot = document.getElementById('wsDot');
    const txt = document.getElementById('wsText');
    if (dot) dot.className = 'inline-block w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping';
    if (txt) {
        txt.textContent = '● SOC LIVE';
        txt.className = 'text-cyan-400 font-bold';
    }

    // Populate initial simulated sockets
    socketsCache = [
        { proto: 'TCP', pname: 'chrome.exe', pid: '14280', local: '192.168.1.105:54210', remote: '142.250.190.46:443', state: 'ESTABLISHED' },
        { proto: 'TCP', pname: 'code.exe', pid: '9840', local: '192.168.1.105:51340', remote: '20.189.173.1:443', state: 'ESTABLISHED' },
        { proto: 'UDP', pname: 'svchost.exe', pid: '1120', local: '192.168.1.105:5353', remote: '224.0.0.251:5353', state: 'LISTENING' },
        { proto: 'UDP', pname: 'system', pid: '4', local: '192.168.1.105:53', remote: '8.8.8.8:53', state: 'LISTENING' },
        { proto: 'TCP', pname: 'discord.exe', pid: '19240', local: '192.168.1.105:58230', remote: '162.159.135.232:443', state: 'ESTABLISHED' },
        { proto: 'TCP', pname: 'spotify.exe', pid: '8732', local: '192.168.1.105:59102', remote: '35.186.224.25:443', state: 'ESTABLISHED' }
    ];

    // Populate initial talkers
    talkersCache = [
        { ip: '142.250.190.46', packets: 1840, formatted_bytes: '1.42 MB', percent: 40.8, is_blocked: false },
        { ip: '192.168.1.1', packets: 980, formatted_bytes: '720.5 KB', percent: 20.7, is_blocked: false },
        { ip: '8.8.8.8', packets: 540, formatted_bytes: '380.2 KB', percent: 10.9, is_blocked: false },
        { ip: '20.189.173.1', packets: 420, formatted_bytes: '290.4 KB', percent: 8.3, is_blocked: false },
        { ip: '162.159.135.232', packets: 340, formatted_bytes: '210.1 KB', percent: 6.0, is_blocked: false }
    ];

    // Run continuous simulation loop
    setInterval(() => {
        const protocols = ['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS'];
        const chosenProto = protocols[Math.floor(Math.random() * protocols.length)];
        const pktsBatch = Math.floor(Math.random() * 5) + 2;
        const bytesBatch = pktsBatch * (Math.floor(Math.random() * 800) + 120);

        simStats.total_packets += pktsBatch;
        simStats.total_bytes += bytesBatch;
        simStats.packets_per_sec = (pktsBatch * 4 + Math.random() * 2).toFixed(1);
        simStats.bytes_per_sec = (bytesBatch * 4).toFixed(0);
        simStats.protocols[chosenProto] = (simStats.protocols[chosenProto] || 0) + pktsBatch;

        throughputData.push(parseFloat(simStats.packets_per_sec));
        if (throughputData.length > 60) throughputData.shift();
        if (throughputChart) {
            throughputChart.data.datasets[0].data = throughputData;
            throughputChart.update();
        }

        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
        const remoteIps = ['142.250.190.46', '8.8.8.8', '1.1.1.1', '20.189.173.1', '162.159.135.232', '192.168.1.1'];
        const rIp = remoteIps[Math.floor(Math.random() * remoteIps.length)];
        const rPort = chosenProto === 'DNS' ? 53 : (chosenProto === 'HTTP' ? 80 : 443);

        const newPkt = {
            id: simStats.total_packets,
            timestamp: Date.now() / 1000,
            formatted_time: timeStr,
            src_ip: '192.168.1.105',
            dst_ip: rIp,
            src_port: Math.floor(Math.random() * 20000) + 40000,
            dst_port: rPort,
            protocol: chosenProto,
            length: bytesBatch,
            flags: 'A',
            summary: `${chosenProto} 192.168.1.105 -> ${rIp}:${rPort} [ESTABLISHED]`,
            raw_hex_preview: '4500003c' + Math.floor(Math.random()*999999).toString(16) + '08004500'
        };

        packetsCache.unshift(newPkt);
        if (packetsCache.length > 100) packetsCache.length = 100;

        if (window.spawnGlobeTrafficArc && Math.random() > 0.3) {
            window.spawnGlobeTrafficArc(chosenProto);
        }

        updateMetrics(simStats, simStats.active_threats > 0 ? 'CRITICAL' : 'NOMINAL');
        updateProtocols(simStats.protocols);
        if (currentTab === 'hud') renderPackets();
    }, 450);
}

// Connect WebSocket with Automatic Recovery
function connectWebSocket() {
    if (isStaticMode) {
        initStaticSimulation();
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
        ws = new WebSocket(wsUrl);
    } catch(e) {
        initStaticSimulation();
        return;
    }

    let opened = false;
    ws.onopen = () => {
        opened = true;
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
                        if (window.spawnGlobeTrafficArc && Math.random() > 0.4) {
                            window.spawnGlobeTrafficArc(data.new_packets[i].protocol);
                        }
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
        } catch (err) {
            console.error('WebSocket parse error:', err);
        }
    };

    ws.onerror = () => {
        if (!opened) {
            initStaticSimulation();
        }
    };

    ws.onclose = () => {
        if (!opened) {
            initStaticSimulation();
            return;
        }
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
    if (!p) return;
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
    const legD = document.getElementById('legDNS');
    if (legT) legT.textContent = tcp;
    if (legU) legU.textContent = udp;
    if (legI) legI.textContent = icmp;
    if (legD) legD.textContent = dns;

    globeData = { TCP: tcp, UDP: udp, ICMP: icmp, DNS: dns, HTTP: http, HTTPS: https, OTHER: other };
}

// -------------------------------------------------------------
// PROTOCOL FILTERING (ALL, TCP, UDP, DNS, HTTP/S)
// -------------------------------------------------------------
function setProtoFilter(proto) {
    currentFilter = proto;
    ['ALL', 'TCP', 'UDP', 'DNS', 'HTTP'].forEach(p => {
        const btn = document.getElementById(`btnFilter${p}`);
        if (btn) {
            if (p === proto) {
                btn.className = 'px-2.5 py-1 rounded bg-cyan-500 text-black font-bold shadow-md transition';
            } else {
                btn.className = 'px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white transition';
            }
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
    const searchVal = (document.getElementById('packetSearch')?.value || '').toLowerCase().trim();

    let filtered = packetsCache;

    if (currentFilter !== 'ALL') {
        if (currentFilter === 'UDP') {
            filtered = filtered.filter(p => {
                const proto = (p.protocol || '').toUpperCase();
                const sum = (p.summary || '').toUpperCase();
                return proto === 'UDP' || proto === 'DNS' || sum.includes('UDP') || sum.includes(':53');
            });
        } else if (currentFilter === 'TCP') {
            filtered = filtered.filter(p => {
                const proto = (p.protocol || '').toUpperCase();
                const sum = (p.summary || '').toUpperCase();
                return proto === 'TCP' || proto === 'HTTP' || proto === 'HTTPS' || sum.includes('TCP');
            });
        } else if (currentFilter === 'DNS') {
            filtered = filtered.filter(p => {
                const proto = (p.protocol || '').toUpperCase();
                const sum = (p.summary || '').toUpperCase();
                return proto === 'DNS' || sum.includes('DNS') || sum.includes(':53') || sum.includes('QUERY');
            });
        } else if (currentFilter === 'HTTP') {
            filtered = filtered.filter(p => {
                const proto = (p.protocol || '').toUpperCase();
                const sum = (p.summary || '').toUpperCase();
                return proto === 'HTTP' || proto === 'HTTPS' || sum.includes('HTTP') || sum.includes(':80') || sum.includes(':443');
            });
        }
    }

    if (searchVal) {
        filtered = filtered.filter(p => 
            (p.src_ip && p.src_ip.includes(searchVal)) || 
            (p.dst_ip && p.dst_ip.includes(searchVal)) ||
            (p.summary && p.summary.toLowerCase().includes(searchVal)) ||
            (p.protocol && p.protocol.toLowerCase().includes(searchVal))
        );
    }

    if (filtered.length === 0) {
        const msg = currentFilter === 'ALL'
            ? 'Listening on interface... Intercepting live traffic.'
            : `No ${currentFilter} packets in current buffer. Capturing network traffic...`;
        tbody.innerHTML = `<tr><td colspan="5" class="py-12 text-center text-slate-500 font-mono">${msg}</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.slice(0, 35).map((pkt, idx) => {
        let protoClass = 'bg-blue-950/80 text-blue-400 border border-blue-500/40';
        const protoUpper = (pkt.protocol || '').toUpperCase();
        if (protoUpper === 'UDP') protoClass = 'bg-indigo-950/80 text-indigo-400 border border-indigo-500/40';
        else if (protoUpper === 'ICMP') protoClass = 'bg-pink-950/80 text-pink-400 border border-pink-500/40';
        else if (protoUpper === 'DNS') protoClass = 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40';
        else if (protoUpper === 'HTTP' || protoUpper === 'HTTPS') protoClass = 'bg-amber-950/80 text-amber-400 border border-amber-500/40';

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
        container.innerHTML = `
            <div class="col-span-2 text-center py-12 text-slate-500 font-mono">
                No active threats detected. All perimeter traffic nominal.
            </div>
        `;
        return;
    }

    container.innerHTML = alertsCache.map(alt => {
        const isBlocked = blockedIpsCache.includes(alt.attacker_ip);
        const sev = alt.severity || 'HIGH';
        const isCrit = sev === 'CRITICAL' || sev === 'HIGH';

        return `
            <div class="p-4 rounded-xl border ${isCrit ? 'border-red-500/50 bg-red-950/20' : 'border-amber-500/50 bg-amber-950/20'} space-y-2 backdrop-blur-sm">
                <div class="flex items-center justify-between">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isCrit ? 'bg-red-900 text-white' : 'bg-amber-900 text-amber-200'}">${sev}</span>
                    <span class="text-xs font-mono text-slate-400">${(alt.timestamp || '').toString().slice(0,19)}</span>
                </div>
                <h3 class="text-sm font-bold text-white">${alt.rule || alt.rule_name || 'Threat Detected'}</h3>
                <p class="text-xs text-slate-300">${alt.details || alt.description || 'Heuristic anomaly trigger.'}</p>
                <div class="text-xs font-mono text-slate-400">
                    <div>Attacker: <span class="text-red-400 font-bold">${alt.attacker_ip}</span> &rarr; Target: <span class="text-cyan-400">${alt.target_ip}</span></div>
                </div>
                <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
                    ${isBlocked
                        ? `<button onclick="unblockIP('${alt.attacker_ip}')" class="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 font-mono text-xs font-bold transition">UNBLOCK IP</button>`
                        : `<button onclick="blockIP('${alt.attacker_ip}')" class="px-3 py-1 rounded bg-red-700 hover:bg-red-600 text-white font-mono text-xs font-bold transition">BLOCK ATTACKER</button>`
                    }
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
            <tr class="hover:bg-slate-800/40 transition border-b border-slate-800/40">
                <td class="py-3 px-4 text-cyan-400 font-bold">#${idx + 1}</td>
                <td class="py-3 px-4 text-white font-bold">${t.ip}</td>
                <td class="py-3 px-4 text-slate-300 font-mono">${(t.packets || 0).toLocaleString()}</td>
                <td class="py-3 px-4 text-blue-300 font-mono">${t.formatted_bytes || '0 KB'}</td>
                <td class="py-3 px-4">
                    <div class="flex items-center gap-2">
                        <div class="w-24 bg-slate-800 rounded-full h-2 overflow-hidden">
                            <div class="bg-gradient-to-r from-blue-500 to-cyan-400 h-2" style="width: ${Math.min(t.percent || 0, 100)}%"></div>
                        </div>
                        <span class="text-xs text-slate-400 font-mono">${t.percent || 0}%</span>
                    </div>
                </td>
                <td class="py-3 px-4 text-right">
                    ${isBlocked 
                        ? `<button onclick="unblockIP('${t.ip}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 text-xs font-bold transition">UNBLOCK</button>`
                        : `<button onclick="blockIP('${t.ip}')" class="px-2.5 py-1 rounded bg-red-800/80 hover:bg-red-700 text-white text-xs font-bold transition">BLOCK</button>`
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
        tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-slate-500 font-mono">Polling local system sockets...</td></tr>`;
        return;
    }

    tbody.innerHTML = socketsCache.map(s => {
        const isEst = s.state === 'ESTABLISHED';
        const isListen = s.state === 'LISTEN' || s.state === 'LISTENING';
        let stateClass = 'bg-slate-800 text-slate-400';
        if (isEst) stateClass = 'bg-emerald-950 text-emerald-400 border border-emerald-500/30';
        else if (isListen) stateClass = 'bg-cyan-950 text-cyan-400 border border-cyan-500/30';

        return `
            <tr class="hover:bg-slate-800/40 transition border-b border-slate-800/40 text-xs font-mono">
                <td class="py-2.5 px-4 font-bold ${s.proto === 'TCP' ? 'text-cyan-400' : 'text-blue-400'}">${s.proto}</td>
                <td class="py-2.5 px-4 text-white font-bold truncate max-w-[150px]">${s.pname || 'System'}</td>
                <td class="py-2.5 px-4 text-slate-400">${s.pid}</td>
                <td class="py-2.5 px-4 text-slate-300">${s.local}</td>
                <td class="py-2.5 px-4 text-slate-300">${s.remote}</td>
                <td class="py-2.5 px-4 text-center"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${stateClass}">${s.state}</span></td>
            </tr>
        `;
    }).join('');
}

function renderHosts() {
    const tbody = document.getElementById('hostsTableBody');
    if (!tbody) return;

    if (hostsCache.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-slate-500 font-mono">Click "SCAN LOCAL SUBNET NOW" to discover active LAN assets.</td></tr>`;
        return;
    }

    tbody.innerHTML = hostsCache.map(h => {
        return `
            <tr class="hover:bg-slate-800/40 transition border-b border-slate-800/40 text-xs font-mono">
                <td class="py-3 px-4 font-bold text-emerald-400">${h.ip}</td>
                <td class="py-3 px-4 text-white font-bold">${h.hostname || 'Host'}</td>
                <td class="py-3 px-4 text-slate-400">${h.mac || '--'}</td>
                <td class="py-3 px-4 text-slate-300">${h.vendor || 'Network Device / OEM'}</td>
                <td class="py-3 px-4 text-slate-400">${h.last_seen || '--'}</td>
                <td class="py-3 px-4 text-right">
                    <button onclick="openPortScanModal('${h.ip}')" class="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold transition">
                        Scan Ports
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

async function blockIP(ip) {
    if (isStaticMode) {
        if (!blockedIpsCache.includes(ip)) blockedIpsCache.push(ip);
        renderAlerts();
        if (currentTab === 'threats') renderFullThreats();
        if (currentTab === 'talkers') renderTalkers();
        return;
    }
    try {
        const res = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: 'Admin dashboard manual action' })
        });
        const data = await res.json();
        if (data.success) {
            blockedIpsCache.push(ip);
            renderAlerts();
            if (currentTab === 'threats') renderFullThreats();
            if (currentTab === 'talkers') renderTalkers();
        }
    } catch(e) {
        console.error('Block IP error:', e);
    }
}

async function unblockIP(ip) {
    if (isStaticMode) {
        blockedIpsCache = blockedIpsCache.filter(item => item !== ip);
        renderAlerts();
        if (currentTab === 'threats') renderFullThreats();
        if (currentTab === 'talkers') renderTalkers();
        return;
    }
    try {
        const res = await fetch('/api/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (data.success) {
            blockedIpsCache = blockedIpsCache.filter(item => item !== ip);
            renderAlerts();
            if (currentTab === 'threats') renderFullThreats();
            if (currentTab === 'talkers') renderTalkers();
        }
    } catch(e) {
        console.error('Unblock IP error:', e);
    }
}

async function toggleAutoBlock() {
    if (isStaticMode) {
        simStats.autoblock_enabled = !simStats.autoblock_enabled;
        const btn = document.getElementById('btnAutoBlock');
        if (btn) {
            if (simStats.autoblock_enabled) {
                btn.textContent = 'ON';
                btn.className = 'px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/50 hover:scale-105 transition font-bold text-[11px]';
            } else {
                btn.textContent = 'OFF';
                btn.className = 'px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/50 hover:scale-105 transition font-bold text-[11px]';
            }
        }
        return;
    }
    try {
        const res = await fetch('/api/firewall/toggle-autoblock', { method: 'POST' });
        const data = await res.json();
        const btn = document.getElementById('btnAutoBlock');
        if (btn) {
            if (data.autoblock_enabled) {
                btn.textContent = 'ON';
                btn.className = 'px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/50 hover:scale-105 transition font-bold text-[11px]';
            } else {
                btn.textContent = 'OFF';
                btn.className = 'px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/50 hover:scale-105 transition font-bold text-[11px]';
            }
        }
    } catch(e) {}
}

async function simulateAttack(type) {
    if (isStaticMode) {
        const attackerIp = `10.173.122.${Math.floor(Math.random() * 150) + 100}`;
        const alertObj = {
            id: Date.now(),
            timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
            rule: type === 'port_scan' ? 'Port Scan Probe Detected' : (type === 'syn_flood' ? 'SYN Flood Denial-of-Service' : (type === 'icmp_sweep' ? 'ICMP Subnet Sweep' : 'DNS Data Exfiltration Tunnel')),
            severity: 'CRITICAL',
            attacker_ip: attackerIp,
            target_ip: '192.168.1.105',
            details: `Automated heuristic trigger: ${type.toUpperCase()} attack pattern detected on interface.`
        };

        alertsCache.unshift(alertObj);
        simStats.active_threats += 1;
        simStats.alert_count += 1;

        if (simStats.autoblock_enabled) {
            blockedIpsCache.push(attackerIp);
        }

        renderAlerts();
        if (currentTab === 'threats') renderFullThreats();

        if (window.spawnGlobeTrafficArc) {
            for (let i = 0; i < 6; i++) {
                setTimeout(() => window.spawnGlobeTrafficArc('THREAT'), i * 80);
            }
        }
        return;
    }
    try {
        const res = await fetch('/api/simulate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: type })
        });
        const data = await res.json();
        if (window.spawnGlobeTrafficArc) {
            for (let i = 0; i < 6; i++) {
                setTimeout(() => window.spawnGlobeTrafficArc('THREAT'), i * 80);
            }
        }
    } catch(e) {}
}

async function scanLocalSubnet() {
    const spin = document.getElementById('scanSpin');
    const btn = document.getElementById('btnSubnetScan');
    if (spin) spin.classList.remove('hidden');
    if (btn) btn.disabled = true;

    if (isStaticMode) {
        setTimeout(() => {
            hostsCache = [
                { ip: "192.168.1.1", hostname: "gateway.local", mac: "00:50:56:C0:00:01", vendor: "Cisco Systems", last_seen: "Just now" },
                { ip: "192.168.1.105", hostname: "soc-operator-host", mac: "D4:5D:64:88:B1:20", vendor: "Intel Corporate", last_seen: "Just now" },
                { ip: "192.168.1.120", hostname: "storage-nas.lan", mac: "00:11:32:45:67:89", vendor: "Synology Inc", last_seen: "Just now" },
                { ip: "192.168.1.145", hostname: "workstation-dev.lan", mac: "3C:D9:2B:11:22:33", vendor: "Dell Inc", last_seen: "Just now" },
                { ip: "192.168.1.188", hostname: "smart-tv-hub.lan", mac: "64:16:66:89:AB:CD", vendor: "Samsung Electronics", last_seen: "Just now" },
                { ip: "192.168.1.210", hostname: "cctv-ipcam-01.lan", mac: "E0:51:63:12:34:56", vendor: "Hikvision Digital", last_seen: "Just now" }
            ];
            renderHosts();
            if (spin) spin.classList.add('hidden');
            if (btn) btn.disabled = false;
        }, 800);
        return;
    }

    try {
        const res = await fetch('/api/real/scan-subnet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        if (data.devices) {
            hostsCache = data.devices;
            renderHosts();
        }
    } catch(e) {
        console.error('Subnet scan error:', e);
    } finally {
        if (spin) spin.classList.add('hidden');
        if (btn) btn.disabled = false;
    }
}

async function openPortScanModal(ip) {
    const modal = document.getElementById('portModal');
    const ipSpan = document.getElementById('portModalIp');
    const body = document.getElementById('portModalBody');
    if (!modal || !body) return;

    if (ipSpan) ipSpan.textContent = ip;
    body.innerHTML = `<div class="py-8 text-center text-cyan-400 font-mono animate-pulse">Running full port probe against ${ip}...</div>`;
    modal.classList.remove('hidden');

    if (isStaticMode) {
        setTimeout(() => {
            const ports = [
                { port: 22, service: 'SSH', banner: 'OpenSSH 8.9p1 Ubuntu' },
                { port: 80, service: 'HTTP', banner: 'nginx/1.22.0' },
                { port: 443, service: 'HTTPS', banner: 'TLSv1.3 Encrypted' },
                { port: 8080, service: 'HTTP-Proxy', banner: 'CyberShield Agent v2.5' }
            ];
            body.innerHTML = `
                <div class="space-y-3">
                    <p class="text-xs text-emerald-400 font-bold">Discovered ${ports.length} Open Service Ports:</p>
                    <div class="grid grid-cols-2 gap-2">
                        ${ports.map(p => `
                            <div class="p-2.5 rounded bg-black/60 border border-cyan-500/30 text-xs">
                                <span class="text-cyan-400 font-bold">Port ${p.port}</span> (${p.service})
                                <div class="text-[10px] text-slate-400 truncate">${p.banner}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }, 600);
        return;
    }

    try {
        const res = await fetch('/api/real/scan-ports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_ip: ip })
        });
        const data = await res.json();
        if (data.open_ports && data.open_ports.length > 0) {
            body.innerHTML = `
                <div class="space-y-3">
                    <p class="text-xs text-emerald-400 font-bold">Discovered ${data.open_ports.length} Open Service Ports:</p>
                    <div class="grid grid-cols-2 gap-2">
                        ${data.open_ports.map(p => `
                            <div class="p-2.5 rounded bg-black/60 border border-cyan-500/30 text-xs">
                                <span class="text-cyan-400 font-bold">Port ${p.port}</span> (${p.service || 'Service'})
                                <div class="text-[10px] text-slate-400 truncate">${p.banner || 'Open'}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } else {
            body.innerHTML = `<div class="py-8 text-center text-slate-400 font-mono">No open ports detected in standard scan range. Host is secure.</div>`;
        }
    } catch(e) {
        body.innerHTML = `<div class="py-8 text-center text-red-400 font-mono">Scan error: ${e.message}</div>`;
    }
}

function openPacketModal(idx) {
    const pkt = packetsCache[idx];
    if (!pkt) return;
    const modal = document.getElementById('packetModal');
    const body = document.getElementById('modalBody');
    if (!modal || !body) return;

    body.innerHTML = `
        <div class="space-y-2">
            <div class="grid grid-cols-2 gap-2 text-xs">
                <div><span class="text-slate-400">Timestamp:</span> <span class="text-white">${pkt.formatted_time || '--'}</span></div>
                <div><span class="text-slate-400">Protocol:</span> <span class="text-cyan-400 font-bold">${pkt.protocol}</span></div>
                <div><span class="text-slate-400">Source:</span> <span class="text-yellow-400">${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</span></div>
                <div><span class="text-slate-400">Destination:</span> <span class="text-emerald-400">${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</span></div>
                <div><span class="text-slate-400">Length:</span> <span class="text-white">${pkt.length} Bytes</span></div>
                <div><span class="text-slate-400">TCP Flags:</span> <span class="text-purple-400">${pkt.flags || 'NONE'}</span></div>
            </div>
            <div class="pt-2">
                <span class="text-slate-400 text-xs font-bold">Packet Summary:</span>
                <div class="p-2 rounded bg-black/60 border border-slate-800 text-slate-300 text-xs mt-1">${pkt.summary || '--'}</div>
            </div>
            <div class="pt-2">
                <span class="text-slate-400 text-xs font-bold">Raw Hex Inspector Preview:</span>
                <pre class="p-3 rounded bg-black/90 border border-cyan-500/30 text-cyan-300 text-[11px] font-mono overflow-x-auto mt-1">${pkt.raw_hex_preview || '4500003c0000400040060000'}</pre>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
}

function closeModal() {
    const modal = document.getElementById('packetModal');
    if (modal) modal.classList.add('hidden');
}

// Start WebSocket and handle initial route
window.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    const hash = window.location.hash.replace('#', '');
    if (['threats', 'talkers', 'sockets', 'hosts', 'scan', 'ps', 'manual'].includes(hash)) {
        switchTab(hash);
    }
});
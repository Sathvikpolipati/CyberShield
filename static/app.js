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
    const nodes = [\n        { lat: 0.65, lon: -1.3, label: 'Local SOC', color: '#00dcff' },     // Local Host\n        { lat: 0.72, lon: -2.1, label: 'US-West Gateway', color: '#1d6dff' },// Gateway 1\n        { lat: 0.70, lon: -1.25, label: 'US-East DNS', color: '#10b981' },   // Gateway 2\n        { lat: 0.90, lon: 0.2, label: 'EU-North Core', color: '#1d6dff' },   // Gateway 3\n        { lat: 0.85, lon: 0.4, label: 'Frankfurt Hub', color: '#00dcff' },   // Gateway 4\n        { lat: 0.50, lon: 1.35, label: 'APAC-Tokyo', color: '#f59e0b' },     // Gateway 5\n        { lat: 0.22, lon: 1.8, label: 'Singapore Edge', color: '#10b981' },  // Gateway 6\n        { lat: -0.58, lon: 2.6, label: 'Sydney Cloud', color: '#00dcff' },   // Gateway 7\n        { lat: -0.40, lon: -0.8, label: 'SA-SaoPaulo', color: '#ec4899' }    // Gateway 8\n    ];

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
            } catch(e) {}\n        }\n        renderTalkers();\n    } else if (tabName === 'sockets') {\n        if (!isStaticMode && socketsCache.length === 0) {\n            try {\n                const r = await fetch('/api/sockets');\n                socketsCache = await r.json();\n            } catch(e) {}\n        }\n        renderFullSockets();\n    } else if (tabName === 'hosts') {\n        if (!isStaticMode && hostsCache.length === 0) {\n            try {\n                const r = await fetch('/api/hosts');\n                hostsCache = await r.json();\n            } catch(e) {}\n        }\n        renderHosts();\n    } else if (tabName === 'hud') {\n        renderPackets();\n        renderAlerts();\n    }\n}\n\n// -------------------------------------------------------------\n// GITHUB PAGES / STATIC SIMULATION ENGINE\n// -------------------------------------------------------------\nlet simStats = {\n    total_packets: 4820,\n    total_bytes: 3482100,\n    packets_per_sec: 24.5,\n    bytes_per_sec: 18540,\n    protocols: { TCP: 2840, UDP: 980, ICMP: 120, DNS: 540, HTTP: 340, HTTPS: 0, OTHER: 0 },\n    alert_count: 1,\n    active_threats: 0,\n    autoblock_enabled: true\n};\n\nfunction initStaticSimulation() {\n    const dot = document.getElementById('wsDot');\n    const txt = document.getElementById('wsText');\n    if (dot) dot.className = 'inline-block w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping';\n    if (txt) {\n        txt.textContent = '● SOC LIVE';\n        txt.className = 'text-cyan-400 font-bold';\n    }\n\n    // Populate initial simulated sockets\n    socketsCache = [\n        { proto: 'TCP', pname: 'chrome.exe', pid: '14280', local: '192.168.1.105:54210', remote: '142.250.190.46:443', state: 'ESTABLISHED' },\n        { proto: 'TCP', pname: 'code.exe', pid: '9840', local: '192.168.1.105:51340', remote: '20.189.173.1:443', state: 'ESTABLISHED' },\n        { proto: 'UDP', pname: 'svchost.exe', pid: '1120', local: '192.168.1.105:5353', remote: '224.0.0.251:5353', state: 'LISTENING' },\n        { proto: 'UDP', pname: 'system', pid: '4', local: '192.168.1.105:53', remote: '8.8.8.8:53', state: 'LISTENING' },\n        { proto: 'TCP', pname: 'discord.exe', pid: '19240', local: '192.168.1.105:58230', remote: '162.159.135.232:443', state: 'ESTABLISHED' },\n        { proto: 'TCP', pname: 'spotify.exe', pid: '8732', local: '192.168.1.105:59102', remote: '35.186.224.25:443', state: 'ESTABLISHED' }\n    ];\n\n    // Populate initial talkers\n    talkersCache = [\n        { ip: '142.250.190.46', packets: 1840, formatted_bytes: '1.42 MB', percent: 40.8, is_blocked: false },\n        { ip: '192.168.1.1', packets: 980, formatted_bytes: '720.5 KB', percent: 20.7, is_blocked: false },\n        { ip: '8.8.8.8', packets: 540, formatted_bytes: '380.2 KB', percent: 10.9, is_blocked: false },\n        { ip: '20.189.173.1', packets: 420, formatted_bytes: '290.4 KB', percent: 8.3, is_blocked: false },\n        { ip: '162.159.135.232', packets: 340, formatted_bytes: '210.1 KB', percent: 6.0, is_blocked: false }\n    ];\n\n    // Run continuous simulation loop\n    setInterval(() => {\n        const protocols = ['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS'];\n        const chosenProto = protocols[Math.floor(Math.random() * protocols.length)];\n        const pktsBatch = Math.floor(Math.random() * 5) + 2;\n        const bytesBatch = pktsBatch * (Math.floor(Math.random() * 800) + 120);\n\n        simStats.total_packets += pktsBatch;\n        simStats.total_bytes += bytesBatch;\n        simStats.packets_per_sec = (pktsBatch * 4 + Math.random() * 2).toFixed(1);\n        simStats.bytes_per_sec = (bytesBatch * 4).toFixed(0);\n        simStats.protocols[chosenProto] = (simStats.protocols[chosenProto] || 0) + pktsBatch;\n\n        throughputData.push(parseFloat(simStats.packets_per_sec));\n        if (throughputData.length > 60) throughputData.shift();\n        if (throughputChart) {\n            throughputChart.data.datasets[0].data = throughputData;\n            throughputChart.update();\n        }\n\n        const now = new Date();\n        const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');\n        const remoteIps = ['142.250.190.46', '8.8.8.8', '1.1.1.1', '20.189.173.1', '162.159.135.232', '192.168.1.1'];\n        const rIp = remoteIps[Math.floor(Math.random() * remoteIps.length)];\n        const rPort = chosenProto === 'DNS' ? 53 : (chosenProto === 'HTTP' ? 80 : 443);\n\n        const newPkt = {\n            id: simStats.total_packets,\n            timestamp: Date.now() / 1000,\n            formatted_time: timeStr,\n            src_ip: '192.168.1.105',\n            dst_ip: rIp,\n            src_port: Math.floor(Math.random() * 20000) + 40000,\n            dst_port: rPort,\n            protocol: chosenProto,\n            length: bytesBatch,\n            flags: 'A',\n            summary: `${chosenProto} 192.168.1.105 -> ${rIp}:${rPort} [ESTABLISHED]`,\n            raw_hex_preview: '4500003c' + Math.floor(Math.random()*999999).toString(16) + '08004500'\n        };\n\n        packetsCache.unshift(newPkt);\n        if (packetsCache.length > 100) packetsCache.length = 100;\n\n        if (window.spawnGlobeTrafficArc && Math.random() > 0.3) {\n            window.spawnGlobeTrafficArc(chosenProto);\n        }\n\n        updateMetrics(simStats, simStats.active_threats > 0 ? 'CRITICAL' : 'NORMAL');\n        updateProtocols(simStats.protocols);\n        if (currentTab === 'hud') renderPackets();\n    }, 450);\n}\n\n// Connect WebSocket with Automatic Recovery\nfunction connectWebSocket() {\n    if (isStaticMode) {\n        initStaticSimulation();\n        return;\n    }\n\n    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';\n    const wsUrl = `${protocol}//${window.location.host}/ws`;\n    \n    try {\n        ws = new WebSocket(wsUrl);\n    } catch(e) {\n        initStaticSimulation();\n        return;\n    }\n\n    let opened = false;\n    ws.onopen = () => {\n        opened = true;\n        const dot = document.getElementById('wsDot');\n        const txt = document.getElementById('wsText');\n        if (dot) dot.className = 'inline-block w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping';\n        if (txt) {\n            txt.textContent = '● LIVE';\n            txt.className = 'text-emerald-400 font-bold';\n        }\n        reconnectDelay = 1000;\n    };\n\n    ws.onmessage = (event) => {\n        try {\n            const data = JSON.parse(event.data);\n            if (data.type === 'init') {\n                packetsCache = data.packets || [];\n                alertsCache = data.alerts || [];\n                hostsCache = data.hosts || [];\n                socketsCache = data.sockets || [];\n                talkersCache = data.talkers || [];\n                blockedIpsCache = data.blocked_ips || [];\n                renderPackets();\n                renderAlerts();\n                if (currentTab === 'threats') renderFullThreats();\n                if (currentTab === 'talkers') renderTalkers();\n                if (currentTab === 'hosts') renderHosts();\n                if (currentTab === 'sockets') renderFullSockets();\n                if (data.stats) updateMetrics(data.stats, data.threat_level || 'NORMAL');\n                if (data.throughput && throughputChart) {\n                    throughputChart.data.datasets[0].data = data.throughput;\n                    throughputChart.update();\n                }\n            } else if (data.type === 'tick') {\n                if (data.stats) updateMetrics(data.stats, data.threat_level);\n                if (data.throughput && throughputChart) {\n                    throughputChart.data.datasets[0].data = data.throughput;\n                    throughputChart.update();\n                }\n                if (data.protocols) updateProtocols(data.protocols);\n                if (data.new_packets && data.new_packets.length > 0) {\n                    for (let i = data.new_packets.length - 1; i >= 0; i--) {\n                        packetsCache.unshift(data.new_packets[i]);\n                        if (window.spawnGlobeTrafficArc && Math.random() > 0.4) {\n                            window.spawnGlobeTrafficArc(data.new_packets[i].protocol);\n                        }\n                    }\n                    if (packetsCache.length > 100) packetsCache.length = 100;\n                    if (currentTab === 'hud') renderPackets();\n                }\n                if (data.sockets) {\n                    socketsCache = data.sockets;\n                    if (currentTab === 'sockets') renderFullSockets();\n                }\n                if (data.talkers) {\n                    talkersCache = data.talkers;\n                    if (currentTab === 'talkers') renderTalkers();\n                }\n                if (data.blocked_ips) blockedIpsCache = data.blocked_ips;\n            }\n        } catch (err) {\n            console.error('WebSocket parse error:', err);\n        }\n    };\n\n    ws.onerror = () => {\n        if (!opened) {\n            initStaticSimulation();\n        }\n    };\n\n    ws.onclose = () => {\n        if (!opened) {\n            initStaticSimulation();\n            return;\n        }\n        const dot = document.getElementById('wsDot');\n        const txt = document.getElementById('wsText');\n        if (dot) dot.className = 'inline-block w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse';\n        if (txt) {\n            txt.textContent = '● RECONNECTING';\n            txt.className = 'text-amber-400 font-bold';\n        }\n        setTimeout(connectWebSocket, reconnectDelay);\n        reconnectDelay = Math.min(reconnectDelay * 1.5, 5000);\n    };\n}\n\nfunction updateMetrics(s, threatLevel) {\n    if (!s) return;\n    const pElem = document.getElementById('statPackets');\n    if (pElem) pElem.textContent = (s.total_packets || 0).toLocaleString();\n    const bElem = document.getElementById('statBytes');\n    if (bElem) bElem.textContent = `${((s.total_bytes || 0) / 1024).toFixed(1)} KB`;\n    const rElem = document.getElementById('statRate');\n    if (rElem) rElem.textContent = s.packets_per_sec || 0;\n    const bpsElem = document.getElementById('statBps');\n    if (bpsElem) bpsElem.textContent = ((s.bytes_per_sec || 0) / 1024).toFixed(1);\n    const thElem = document.getElementById('statThreats');\n    if (thElem) thElem.textContent = s.active_threats || s.threat_count || 0;\n    const tcElem = document.getElementById('statThreatCount');\n    if (tcElem) tcElem.textContent = s.alert_count || s.threat_count || 0;\n\n    const navBadge = document.getElementById('navThreatBadge');\n    if (navBadge) navBadge.textContent = s.active_threats || s.threat_count || 0;\n\n    const tElem = document.getElementById('statThreatLevel');\n    if (tElem) {\n        tElem.textContent = threatLevel || 'NORMAL';\n        if (threatLevel === 'CRITICAL') {\n            tElem.className = 'text-3xl font-bold font-mono text-red-500 animate-pulse';\n        } else if (threatLevel === 'ELEVATED') {\n            tElem.className = 'text-3xl font-bold font-mono text-amber-400';\n        } else {\n            tElem.className = 'text-3xl font-bold font-mono text-emerald-400';\n        }\n    }\n}\n\nfunction updateProtocols(p) {\n    if (!p) return;\n    const tcp = p.TCP || 0;\n    const udp = p.UDP || 0;\n    const icmp = p.ICMP || 0;\n    const dns = p.DNS || 0;\n    const http = p.HTTP || 0;\n    const https = p.HTTPS || 0;\n    const other = p.OTHER || 0;\n\n    const legT = document.getElementById('legTCP');\n    const legU = document.getElementById('legUDP');\n    const legI = document.getElementById('legICMP');\n    const legD = document.getElementById('legDNS');\n    if (legT) legT.textContent = tcp;\n    if (legU) legU.textContent = udp;\n    if (legI) legI.textContent = icmp;\n    if (legD) legD.textContent = dns;\n\n    globeData = { TCP: tcp, UDP: udp, ICMP: icmp, DNS: dns, HTTP: http, HTTPS: https, OTHER: other };\n}\n\n// -------------------------------------------------------------\n// PROTOCOL FILTERING (ALL, TCP, UDP, DNS, HTTP/S)\n// -------------------------------------------------------------\nfunction setProtoFilter(proto) {\n    currentFilter = proto;\n    ['ALL', 'TCP', 'UDP', 'DNS', 'HTTP'].forEach(p => {\n        const btn = document.getElementById(`btnFilter${p}`);\n        if (btn) {\n            if (p === proto) {\n                btn.className = 'px-2.5 py-1 rounded bg-cyan-500 text-black font-bold shadow-md transition';\n            } else {\n                btn.className = 'px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white transition';\n            }\n        }\n    });\n    renderPackets();\n}\n\nfunction filterPackets() {\n    renderPackets();\n}\n\nfunction renderPackets() {\n    const tbody = document.getElementById('packetTableBody');\n    if (!tbody) return;\n    const searchVal = (document.getElementById('packetSearch')?.value || '').toLowerCase().trim();\n\n    let filtered = packetsCache;\n\n    if (currentFilter !== 'ALL') {\n        if (currentFilter === 'UDP') {\n            filtered = filtered.filter(p => {\n                const proto = (p.protocol || '').toUpperCase();\n                const sum = (p.summary || '').toUpperCase();\n                return proto === 'UDP' || proto === 'DNS' || sum.includes('UDP') || sum.includes(':53');\n            });\n        } else if (currentFilter === 'TCP') {\n            filtered = filtered.filter(p => {\n                const proto = (p.protocol || '').toUpperCase();\n                const sum = (p.summary || '').toUpperCase();\n                return proto === 'TCP' || proto === 'HTTP' || proto === 'HTTPS' || sum.includes('TCP');\n            });\n        } else if (currentFilter === 'DNS') {\n            filtered = filtered.filter(p => {\n                const proto = (p.protocol || '').toUpperCase();\n                const sum = (p.summary || '').toUpperCase();\n                return proto === 'DNS' || sum.includes('DNS') || sum.includes(':53') || sum.includes('QUERY');\n            });\n        } else if (currentFilter === 'HTTP') {\n            filtered = filtered.filter(p => {\n                const proto = (p.protocol || '').toUpperCase();\n                const sum = (p.summary || '').toUpperCase();\n                return proto === 'HTTP' || proto === 'HTTPS' || sum.includes('HTTP') || sum.includes(':80') || sum.includes(':443');\n            });\n        }\n    }\n\n    if (searchVal) {\n        filtered = filtered.filter(p => \n            (p.src_ip && p.src_ip.includes(searchVal)) || \n            (p.dst_ip && p.dst_ip.includes(searchVal)) ||\n            (p.summary && p.summary.toLowerCase().includes(searchVal)) ||\n            (p.protocol && p.protocol.toLowerCase().includes(searchVal))\n        );\n    }\n\n    if (filtered.length === 0) {\n        const msg = currentFilter === 'ALL'\n            ? 'Listening on interface... Intercepting live traffic.'\n            : `No ${currentFilter} packets in current buffer. Capturing network traffic...`;\n        tbody.innerHTML = `<tr><td colspan=\"5\" class=\"py-12 text-center text-slate-500 font-mono\">${msg}</td></tr>`;\n        return;\n    }\n\n    tbody.innerHTML = filtered.slice(0, 35).map((pkt, idx) => {\n        let protoClass = 'bg-blue-950/80 text-blue-400 border border-blue-500/40';\n        const protoUpper = (pkt.protocol || '').toUpperCase();\n        if (protoUpper === 'UDP') protoClass = 'bg-indigo-950/80 text-indigo-400 border border-indigo-500/40';\n        else if (protoUpper === 'ICMP') protoClass = 'bg-pink-950/80 text-pink-400 border border-pink-500/40';\n        else if (protoUpper === 'DNS') protoClass = 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40';\n        else if (protoUpper === 'HTTP' || protoUpper === 'HTTPS') protoClass = 'bg-amber-950/80 text-amber-400 border border-amber-500/40';\n\n        const timeStr = pkt.formatted_time ? pkt.formatted_time.split(' ')[1] || pkt.formatted_time : '00:00:00';\n        const src = `${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}`;\n        const dst = `${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}`;\n\n        return `\n            <tr onclick=\"openPacketModal(${idx})\" class=\"hover:bg-blue-950/40 cursor-pointer transition border-b border-slate-800/40\">\n                <td class=\"py-2 px-3 text-slate-400 text-[11px]\">${timeStr}</td>\n                <td class=\"py-2 px-2\"><span class=\"px-1.5 py-0.5 rounded text-[10px] font-bold ${protoClass}\">${pkt.protocol}</span></td>\n                <td class=\"py-2 px-3 text-slate-200\">${src} &rarr; ${dst}</td>\n                <td class=\"py-2 px-2 text-right text-slate-400 font-mono\">${pkt.length}</td>\n                <td class=\"py-2 px-3 text-slate-400 truncate max-w-[200px]\" title=\"${pkt.summary || ''}\">${pkt.summary || '--'}</td>\n            </tr>\n        `;\n    }).join('');\n}\n\nfunction renderAlerts() {\n    const container = document.getElementById('alertContainer');\n    const noMsg = document.getElementById('noAlertsMsg');\n    if (!container) return;\n\n    if (alertsCache.length === 0) {\n        if (noMsg) noMsg.classList.remove('hidden');\n        return;\n    }\n    if (noMsg) noMsg.classList.add('hidden');\n\n    container.innerHTML = alertsCache.slice(0, 15).map(alt => {\n        const sev = alt.severity || 'HIGH';\n        const isCrit = sev === 'CRITICAL' || sev === 'HIGH';\n        const isBlocked = blockedIpsCache.includes(alt.attacker_ip);\n\n        return `\n            <div class=\"p-3.5 rounded-xl border ${isCrit ? 'border-red-500/40 bg-red-950/30' : 'border-amber-500/40 bg-amber-950/30'} space-y-1.5 backdrop-blur-sm shadow-md\">\n                <div class=\"flex items-center justify-between\">\n                    <span class=\"px-2 py-0.5 rounded text-[10px] font-bold ${isCrit ? 'bg-red-900 text-white' : 'bg-amber-900 text-amber-200'}\">${sev}</span>\n                    <span class=\"text-[10px] font-mono text-slate-400\">${(alt.timestamp || '').toString().slice(0,19)}</span>\n                </div>\n                <h4 class=\"text-xs font-bold text-white\">${alt.rule || alt.rule_name || 'Threat Detected'}</h4>\n                <p class=\"text-xs text-slate-300 leading-relaxed\">${alt.details || alt.description || 'Heuristic anomaly trigger.'}</p>\n                <div class=\"flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-700/50\">\n                    <span>${alt.attacker_ip} &rarr; ${alt.target_ip}</span>\n                    ${isBlocked \n                        ? `<span class=\"text-emerald-400 font-bold\">🛑 ISOLATED</span>`\n                        : `<button onclick=\"blockIP('${alt.attacker_ip}')\" class=\"px-2 py-0.5 rounded bg-red-800 hover:bg-red-700 text-white font-bold transition\">BLOCK IP</button>`\n                    }\n                </div>\n            </div>\n        `;\n    }).join('');\n}\n\nfunction renderFullThreats() {\n    const container = document.getElementById('threatsFullContainer');\n    if (!container) return;\n\n    if (alertsCache.length === 0) {\n        container.innerHTML = `\n            <div class=\"col-span-2 text-center py-12 text-slate-500 font-mono\">\n                No active threats detected. All perimeter traffic nominal.\n            </div>\n        `;\n        return;\n    }\n\n    container.innerHTML = alertsCache.map(alt => {\n        const isBlocked = blockedIpsCache.includes(alt.attacker_ip);\n        const sev = alt.severity || 'HIGH';\n        const isCrit = sev === 'CRITICAL' || sev === 'HIGH';\n\n        return `\n            <div class=\"p-4 rounded-xl border ${isCrit ? 'border-red-500/50 bg-red-950/20' : 'border-amber-500/50 bg-amber-950/20'} space-y-2 backdrop-blur-sm\">\n                <div class=\"flex items-center justify-between\">\n                    <span class=\"px-2 py-0.5 rounded text-[10px] font-bold ${isCrit ? 'bg-red-900 text-white' : 'bg-amber-900 text-amber-200'}\">${sev}</span>\n                    <span class=\"text-xs font-mono text-slate-400\">${(alt.timestamp || '').toString().slice(0,19)}</span>\n                </div>\n                <h3 class=\"text-sm font-bold text-white\">${alt.rule || alt.rule_name || 'Threat Detected'}</h3>\n                <p class=\"text-xs text-slate-300\">${alt.details || alt.description || 'Heuristic anomaly trigger.'}</p>\n                <div class=\"text-xs font-mono text-slate-400\">\n                    <div>Attacker: <span class=\"text-red-400 font-bold\">${alt.attacker_ip}</span> &rarr; Target: <span class=\"text-cyan-400\">${alt.target_ip}</span></div>\n                </div>\n                <div class=\"pt-2 flex justify-end gap-2 border-t border-slate-800\">\n                    ${isBlocked\n                        ? `<button onclick=\"unblockIP('${alt.attacker_ip}')\" class=\"px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 font-mono text-xs font-bold transition\">UNBLOCK IP</button>`\n                        : `<button onclick=\"blockIP('${alt.attacker_ip}')\" class=\"px-3 py-1 rounded bg-red-700 hover:bg-red-600 text-white font-mono text-xs font-bold transition\">BLOCK ATTACKER</button>`\n                    }\n                </div>\n            </div>\n        `;\n    }).join('');\n}\n\nfunction renderTalkers() {\n    const tbody = document.getElementById('talkersTableBody');\n    if (!tbody) return;\n\n    if (talkersCache.length === 0) {\n        tbody.innerHTML = `<tr><td colspan=\"6\" class=\"py-8 text-center text-slate-500 font-mono\">Sampling talker endpoints...</td></tr>`;\n        return;\n    }\n\n    tbody.innerHTML = talkersCache.map((t, idx) => {\n        const isBlocked = blockedIpsCache.includes(t.ip);\n        return `\n            <tr class=\"hover:bg-slate-800/40 transition border-b border-slate-800/40\">\n                <td class=\"py-3 px-4 text-cyan-400 font-bold\">#${idx + 1}</td>\n                <td class=\"py-3 px-4 text-white font-bold\">${t.ip}</td>\n                <td class=\"py-3 px-4 text-slate-300 font-mono\">${(t.packets || 0).toLocaleString()}</td>\n                <td class=\"py-3 px-4 text-blue-300 font-mono\">${t.formatted_bytes || '0 KB'}</td>\n                <td class=\"py-3 px-4\">\n                    <div class=\"flex items-center gap-2\">\n                        <div class=\"w-24 bg-slate-800 rounded-full h-2 overflow-hidden\">\n                            <div class=\"bg-gradient-to-r from-blue-500 to-cyan-400 h-2\" style=\"width: ${Math.min(t.percent || 0, 100)}%\"></div>\n                        </div>\n                        <span class=\"text-xs text-slate-400 font-mono\">${t.percent || 0}%</span>\n                    </div>\n                </td>\n                <td class=\"py-3 px-4 text-right\">\n                    ${isBlocked \n                        ? `<button onclick=\"unblockIP('${t.ip}')\" class=\"px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 text-xs font-bold transition\">UNBLOCK</button>`\n                        : `<button onclick=\"blockIP('${t.ip}')\" class=\"px-2.5 py-1 rounded bg-red-800/80 hover:bg-red-700 text-white text-xs font-bold transition\">BLOCK</button>`\n                    }\n                </td>\n            </tr>\n        `;\n    }).join('');\n}\n\nfunction renderFullSockets() {\n    const tbody = document.getElementById('fullSocketTableBody');\n    if (!tbody) return;\n\n    if (socketsCache.length === 0) {\n        tbody.innerHTML = `<tr><td colspan=\"6\" class=\"py-8 text-center text-slate-500 font-mono\">Polling local system sockets...</td></tr>`;\n        return;\n    }\n\n    tbody.innerHTML = socketsCache.map(s => {\n        const isEst = s.state === 'ESTABLISHED';\n        const isListen = s.state === 'LISTEN' || s.state === 'LISTENING';\n        let stateClass = 'bg-slate-800 text-slate-400';\n        if (isEst) stateClass = 'bg-emerald-950 text-emerald-400 border border-emerald-500/30';\n        else if (isListen) stateClass = 'bg-cyan-950 text-cyan-400 border border-cyan-500/30';\n\n        return `\n            <tr class=\"hover:bg-slate-800/40 transition border-b border-slate-800/40 text-xs font-mono\">\n                <td class=\"py-2.5 px-4 font-bold ${s.proto === 'TCP' ? 'text-cyan-400' : 'text-blue-400'}\">${s.proto}</td>\n                <td class=\"py-2.5 px-4 text-white font-bold truncate max-w-[150px]\">${s.pname || 'System'}</td>\n                <td class=\"py-2.5 px-4 text-slate-400\">${s.pid}</td>\n                <td class=\"py-2.5 px-4 text-slate-300\">${s.local}</td>\n                <td class=\"py-2.5 px-4 text-slate-300\">${s.remote}</td>\n                <td class=\"py-2.5 px-4 text-center\"><span class=\"px-2 py-0.5 rounded text-[10px] font-bold ${stateClass}\">${s.state}</span></td>\n            </tr>\n        `;\n    }).join('');\n}\n\nfunction renderHosts() {\n    const tbody = document.getElementById('hostsTableBody');\n    if (!tbody) return;\n\n    if (hostsCache.length === 0) {\n        tbody.innerHTML = `<tr><td colspan=\"6\" class=\"py-8 text-center text-slate-500 font-mono\">Click \"SCAN LOCAL SUBNET NOW\" to discover active LAN assets.</td></tr>`;\n        return;\n    }\n\n    tbody.innerHTML = hostsCache.map(h => {\n        return `\n            <tr class=\"hover:bg-slate-800/40 transition border-b border-slate-800/40 text-xs font-mono\">\n                <td class=\"py-3 px-4 font-bold text-emerald-400\">${h.ip}</td>\n                <td class=\"py-3 px-4 text-white font-bold\">${h.hostname || 'Host'}</td>\n                <td class=\"py-3 px-4 text-slate-400\">${h.mac || '--'}</td>\n                <td class=\"py-3 px-4 text-slate-300\">${h.vendor || 'Network Device / OEM'}</td>\n                <td class=\"py-3 px-4 text-slate-400\">${h.last_seen || '--'}</td>\n                <td class=\"py-3 px-4 text-right\">\n                    <button onclick=\"openPortScanModal('${h.ip}')\" class=\"px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold transition\">\n                        Scan Ports\n                    </button>\n                </td>\n            </tr>\n        `;\n    }).join('');\n}\n\nasync function blockIP(ip) {\n    if (isStaticMode) {\n        if (!blockedIpsCache.includes(ip)) blockedIpsCache.push(ip);\n        renderAlerts();\n        if (currentTab === 'threats') renderFullThreats();\n        if (currentTab === 'talkers') renderTalkers();\n        return;\n    }\n    try {\n        const res = await fetch('/api/firewall/block', {\n            method: 'POST',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({ ip, reason: 'Admin dashboard manual action' })\n        });\n        const data = await res.json();\n        if (data.success) {\n            blockedIpsCache.push(ip);\n            renderAlerts();\n            if (currentTab === 'threats') renderFullThreats();\n            if (currentTab === 'talkers') renderTalkers();\n        }\n    } catch(e) {\n        console.error('Block IP error:', e);\n    }\n}\n\nasync function unblockIP(ip) {\n    if (isStaticMode) {\n        blockedIpsCache = blockedIpsCache.filter(item => item !== ip);\n        renderAlerts();\n        if (currentTab === 'threats') renderFullThreats();\n        if (currentTab === 'talkers') renderTalkers();\n        return;\n    }\n    try {\n        const res = await fetch('/api/firewall/unblock', {\n            method: 'POST',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({ ip })\n        });\n        const data = await res.json();\n        if (data.success) {\n            blockedIpsCache = blockedIpsCache.filter(item => item !== ip);\n            renderAlerts();\n            if (currentTab === 'threats') renderFullThreats();\n            if (currentTab === 'talkers') renderTalkers();\n        }\n    } catch(e) {\n        console.error('Unblock IP error:', e);\n    }\n}\n\nasync function toggleAutoBlock() {\n    if (isStaticMode) {\n        simStats.autoblock_enabled = !simStats.autoblock_enabled;\n        const btn = document.getElementById('btnAutoBlock');\n        if (btn) {\n            if (simStats.autoblock_enabled) {\n                btn.textContent = 'ON';\n                btn.className = 'px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/50 hover:scale-105 transition font-bold text-[11px]';\n            } else {\n                btn.textContent = 'OFF';\n                btn.className = 'px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/50 hover:scale-105 transition font-bold text-[11px]';\n            }\n        }\n        return;\n    }\n    try {\n        const res = await fetch('/api/firewall/toggle-autoblock', { method: 'POST' });\n        const data = await res.json();\n        const btn = document.getElementById('btnAutoBlock');\n        if (btn) {\n            if (data.autoblock_enabled) {\n                btn.textContent = 'ON';\n                btn.className = 'px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/50 hover:scale-105 transition font-bold text-[11px]';\n            } else {\n                btn.textContent = 'OFF';\n                btn.className = 'px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/50 hover:scale-105 transition font-bold text-[11px]';\n            }\n        }\n    } catch(e) {}\n}\n\nasync function simulateAttack(type) {\n    if (isStaticMode) {\n        const attackerIp = `10.173.122.${Math.floor(Math.random() * 150) + 100}`;\n        const alertObj = {\n            id: Date.now(),\n            timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),\n            rule: type === 'port_scan' ? 'Port Scan Probe Detected' : (type === 'syn_flood' ? 'SYN Flood Denial-of-Service' : (type === 'icmp_sweep' ? 'ICMP Subnet Sweep' : 'DNS Data Exfiltration Tunnel')),\n            severity: 'CRITICAL',\n            attacker_ip: attackerIp,\n            target_ip: '192.168.1.105',\n            details: `Automated heuristic trigger: ${type.toUpperCase()} attack pattern detected on interface.`\n        };\n\n        alertsCache.unshift(alertObj);\n        simStats.active_threats += 1;\n        simStats.alert_count += 1;\n\n        if (simStats.autoblock_enabled) {\n            blockedIpsCache.push(attackerIp);\n        }\n\n        renderAlerts();\n        if (currentTab === 'threats') renderFullThreats();\n\n        if (window.spawnGlobeTrafficArc) {\n            for (let i = 0; i < 6; i++) {\n                setTimeout(() => window.spawnGlobeTrafficArc('THREAT'), i * 80);\n            }\n        }\n        return;\n    }\n    try {\n        const res = await fetch('/api/simulate-attack', {\n            method: 'POST',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({ attack_type: type })\n        });\n        const data = await res.json();\n        if (window.spawnGlobeTrafficArc) {\n            for (let i = 0; i < 6; i++) {\n                setTimeout(() => window.spawnGlobeTrafficArc('THREAT'), i * 80);\n            }\n        }\n    } catch(e) {}\n}\n\nasync function scanLocalSubnet() {\n    const spin = document.getElementById('scanSpin');\n    const btn = document.getElementById('btnSubnetScan');\n    if (spin) spin.classList.remove('hidden');\n    if (btn) btn.disabled = true;\n\n    if (isStaticMode) {\n        setTimeout(() => {\n            hostsCache = [\n                { ip: \"192.168.1.1\", hostname: \"gateway.local\", mac: \"00:50:56:C0:00:01\", vendor: \"Cisco Systems\", last_seen: \"Just now\" },\n                { ip: \"192.168.1.105\", hostname: \"soc-operator-host\", mac: \"D4:5D:64:88:B1:20\", vendor: \"Intel Corporate\", last_seen: \"Just now\" },\n                { ip: \"192.168.1.120\", hostname: \"storage-nas.lan\", mac: \"00:11:32:45:67:89\", vendor: \"Synology Inc\", last_seen: \"Just now\" },\n                { ip: \"192.168.1.145\", hostname: \"workstation-dev.lan\", mac: \"3C:D9:2B:11:22:33\", vendor: \"Dell Inc\", last_seen: \"Just now\" },\n                { ip: \"192.168.1.188\", hostname: \"smart-tv-hub.lan\", mac: \"64:16:66:89:AB:CD\", vendor: \"Samsung Electronics\", last_seen: \"Just now\" },\n                { ip: \"192.168.1.210\", hostname: \"cctv-ipcam-01.lan\", mac: \"E0:51:63:12:34:56\", vendor: \"Hikvision Digital\", last_seen: \"Just now\" }\n            ];\n            renderHosts();\n            if (spin) spin.classList.add('hidden');\n            if (btn) btn.disabled = false;\n        }, 800);\n        return;\n    }\n\n    try {\n        const res = await fetch('/api/real/scan-subnet', {\n            method: 'POST',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({})\n        });\n        const data = await res.json();\n        if (data.devices) {\n            hostsCache = data.devices;\n            renderHosts();\n        }\n    } catch(e) {\n        console.error('Subnet scan error:', e);\n    } finally {\n        if (spin) spin.classList.add('hidden');\n        if (btn) btn.disabled = false;\n    }\n}\n\nasync function openPortScanModal(ip) {\n    const modal = document.getElementById('portModal');\n    const ipSpan = document.getElementById('portModalIp');\n    const body = document.getElementById('portModalBody');\n    if (!modal || !body) return;\n\n    if (ipSpan) ipSpan.textContent = ip;\n    body.innerHTML = `<div class=\"py-8 text-center text-cyan-400 font-mono animate-pulse\">Running full port probe against ${ip}...</div>`;\n    modal.classList.remove('hidden');\n\n    if (isStaticMode) {\n        setTimeout(() => {\n            const ports = [\n                { port: 22, service: 'SSH', banner: 'OpenSSH 8.9p1 Ubuntu' },\n                { port: 80, service: 'HTTP', banner: 'nginx/1.22.0' },\n                { port: 443, service: 'HTTPS', banner: 'TLSv1.3 Encrypted' },\n                { port: 8080, service: 'HTTP-Proxy', banner: 'CyberShield Agent v2.5' }\n            ];\n            body.innerHTML = `\n                <div class=\"space-y-3\">\n                    <p class=\"text-xs text-emerald-400 font-bold\">Discovered ${ports.length} Open Service Ports:</p>\n                    <div class=\"grid grid-cols-2 gap-2\">\n                        ${ports.map(p => `\n                            <div class=\"p-2.5 rounded bg-black/60 border border-cyan-500/30 text-xs\">\n                                <span class=\"text-cyan-400 font-bold\">Port ${p.port}</span> (${p.service})\n                                <div class=\"text-[10px] text-slate-400 truncate\">${p.banner}</div>\n                            </div>\n                        `).join('')}\n                    </div>\n                </div>\n            `;\n        }, 600);\n        return;\n    }\n\n    try {\n        const res = await fetch('/api/real/scan-ports', {\n            method: 'POST',\n            headers: { 'Content-Type': 'application/json' },\n            body: JSON.stringify({ target_ip: ip })\n        });\n        const data = await res.json();\n        if (data.open_ports && data.open_ports.length > 0) {\n            body.innerHTML = `\n                <div class=\"space-y-3\">\n                    <p class=\"text-xs text-emerald-400 font-bold\">Discovered ${data.open_ports.length} Open Service Ports:</p>\n                    <div class=\"grid grid-cols-2 gap-2\">\n                        ${data.open_ports.map(p => `\n                            <div class=\"p-2.5 rounded bg-black/60 border border-cyan-500/30 text-xs\">\n                                <span class=\"text-cyan-400 font-bold\">Port ${p.port}</span> (${p.service || 'Service'})\n                                <div class=\"text-[10px] text-slate-400 truncate\">${p.banner || 'Open'}</div>\n                            </div>\n                        `).join('')}\n                    </div>\n                </div>\n            `;\n        } else {\n            body.innerHTML = `<div class=\"py-8 text-center text-slate-400 font-mono\">No open ports detected in standard scan range. Host is secure.</div>`;\n        }\n    } catch(e) {\n        body.innerHTML = `<div class=\"py-8 text-center text-red-400 font-mono\">Scan error: ${e.message}</div>`;\n    }\n}\n\nfunction openPacketModal(idx) {\n    const pkt = packetsCache[idx];\n    if (!pkt) return;\n    const modal = document.getElementById('packetModal');\n    const body = document.getElementById('modalBody');\n    if (!modal || !body) return;\n\n    body.innerHTML = `\n        <div class=\"space-y-2\">\n            <div class=\"grid grid-cols-2 gap-2 text-xs\">\n                <div><span class=\"text-slate-400\">Timestamp:</span> <span class=\"text-white\">${pkt.formatted_time || '--'}</span></div>\n                <div><span class=\"text-slate-400\">Protocol:</span> <span class=\"text-cyan-400 font-bold\">${pkt.protocol}</span></div>\n                <div><span class=\"text-slate-400\">Source:</span> <span class=\"text-yellow-400\">${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</span></div>\n                <div><span class=\"text-slate-400\">Destination:</span> <span class=\"text-emerald-400\">${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</span></div>\n                <div><span class=\"text-slate-400\">Length:</span> <span class=\"text-white\">${pkt.length} Bytes</span></div>\n                <div><span class=\"text-slate-400\">TCP Flags:</span> <span class=\"text-purple-400\">${pkt.flags || 'NONE'}</span></div>\n            </div>\n            <div class=\"pt-2\">\n                <span class=\"text-slate-400 text-xs font-bold\">Packet Summary:</span>\n                <div class=\"p-2 rounded bg-black/60 border border-slate-800 text-slate-300 text-xs mt-1\">${pkt.summary || '--'}</div>\n            </div>\n            <div class=\"pt-2\">\n                <span class=\"text-slate-400 text-xs font-bold\">Raw Hex Inspector Preview:</span>\n                <pre class=\"p-3 rounded bg-black/90 border border-cyan-500/30 text-cyan-300 text-[11px] font-mono overflow-x-auto mt-1\">${pkt.raw_hex_preview || '4500003c0000400040060000'}</pre>\n            </div>\n        </div>\n    `;\n    modal.classList.remove('hidden');\n}\n\nfunction closeModal() {\n    const modal = document.getElementById('packetModal');\n    if (modal) modal.classList.add('hidden');\n}\n\n// Start WebSocket and handle initial route\nwindow.addEventListener('DOMContentLoaded', () => {\n    connectWebSocket();\n    const hash = window.location.hash.replace('#', '');\n    if (['threats', 'talkers', 'sockets', 'hosts', 'scan', 'ps', 'manual'].includes(hash)) {\n        switchTab(hash);\n    }\n});\n
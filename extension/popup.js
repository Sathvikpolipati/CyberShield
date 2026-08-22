const BASE_URL = "http://localhost:8000";

async function fetchStats() {
    try {
        const res = await fetch(`${BASE_URL}/api/stats`);
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById("statPackets").textContent = data.total_packets.toLocaleString();
        document.getElementById("statBytes").textContent = `${(data.total_bytes / 1024).toFixed(0)} KB`;
        
        const threats = (data.alert_counts.HIGH || 0) + (data.alert_counts.CRITICAL || 0) + (data.alert_counts.MEDIUM || 0);
        document.getElementById("statThreats").textContent = threats;

        const badge = document.getElementById("statusBadge");
        if (threats > 0) {
            badge.textContent = "ELEVATED";
            badge.className = "badge threat";
        } else {
            badge.textContent = "NOMINAL";
            badge.className = "badge nominal";
        }
    } catch (e) {
        document.getElementById("statusBadge").textContent = "OFFLINE";
        document.getElementById("statusBadge").className = "badge";
    }
}

async function fetchAlerts() {
    try {
        const res = await fetch(`${BASE_URL}/api/alerts?limit=5`);
        if (!res.ok) return;
        const alerts = await res.json();
        const container = document.getElementById("alertList");
        if (alerts.length === 0) {
            container.innerHTML = `<div class="empty">No security threats detected.</div>`;
            return;
        }
        container.innerHTML = alerts.map(a => `
            <div class="alert-item">
                <strong>[${a.severity}]</strong> ${a.rule_name}
                <div style="color: #9CA3AF; font-size: 9px;">${a.attacker_ip} &rarr; ${a.target_ip}</div>
            </div>
        `).join('');
    } catch (e) {}
}

async function triggerAttack(type) {
    try {
        await fetch(`${BASE_URL}/api/simulate/attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack_type: type })
        });
        setTimeout(() => { fetchStats(); fetchAlerts(); }, 400);
    } catch (e) {}
}

document.getElementById("btnScan").addEventListener("click", () => triggerAttack("port_scan"));
document.getElementById("btnSyn").addEventListener("click", () => triggerAttack("syn_flood"));

fetchStats();
fetchAlerts();
setInterval(() => {
    fetchStats();
    fetchAlerts();
}, 2000);

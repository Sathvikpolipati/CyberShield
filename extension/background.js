chrome.alarms.create("poll_server", { periodInMinutes: 0.1 });

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "poll_server") {
        checkHealth();
    }
});

async function checkHealth() {
    try {
        const res = await fetch("http://localhost:8000/api/stats");
        if (res.ok) {
            const data = await res.json();
            const totalThreats = (data.alert_counts.HIGH || 0) + (data.alert_counts.CRITICAL || 0);
            if (totalThreats > 0) {
                chrome.action.setBadgeText({ text: "!" });
                chrome.action.setBadgeBackgroundColor({ color: "#EF4444" });
            } else {
                chrome.action.setBadgeText({ text: "OK" });
                chrome.action.setBadgeBackgroundColor({ color: "#10B981" });
            }
        }
    } catch (e) {
        chrome.action.setBadgeText({ text: "" });
    }
}

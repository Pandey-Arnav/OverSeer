(async function () {
  const statusLine = document.getElementById("status-line");
  const protectionToggle = document.getElementById("protection-toggle");
  const aiToggle = document.getElementById("ai-toggle");
  const countToday = document.getElementById("count-today");
  const countBlocked = document.getElementById("count-blocked");
  const countWarned = document.getElementById("count-warned");
  const recentList = document.getElementById("recent-list");
  const openDashboardBtn = document.getElementById("open-dashboard");

  function isToday(isoTimestamp) {
    const d = new Date(isoTimestamp);
    const now = new Date();
    return d.toDateString() === now.toDateString();
  }

  function hostnameOf(url) {
    try {
      return new URL(url).hostname;
    } catch {
      return url || "unknown";
    }
  }

  function renderStatus(settings) {
    protectionToggle.checked = settings.protectionEnabled;
    aiToggle.checked = settings.aiExplanationsEnabled;
    if (settings.protectionEnabled) {
      statusLine.textContent = "Protection is active — watching page behavior in real time.";
      statusLine.className = "status-line enabled";
    } else {
      statusLine.textContent = "Protection is OFF — nothing is being monitored.";
      statusLine.className = "status-line disabled";
    }
  }

  function renderCounts(incidents) {
    const todays = incidents.filter((i) => isToday(i.timestamp));
    countToday.textContent = String(todays.length);
    countBlocked.textContent = String(todays.filter((i) => i.decision === "blocked").length);
    countWarned.textContent = String(todays.filter((i) => i.decision === "warn").length);
  }

  function renderRecent(incidents) {
    recentList.innerHTML = "";
    const recent = incidents.slice(0, 3);
    if (recent.length === 0) {
      recentList.innerHTML = '<li class="empty">No incidents yet</li>';
      return;
    }
    for (const incident of recent) {
      const li = document.createElement("li");
      const badge = document.createElement("span");
      badge.className = `badge badge-${incident.decision}`;
      badge.textContent = incident.decision.replace(/_/g, " ");
      const domain = document.createElement("span");
      domain.className = "recent-domain";
      domain.textContent = hostnameOf(incident.destinationUrl || incident.pageUrl);
      const score = document.createElement("span");
      score.className = "recent-score";
      score.textContent = incident.score;
      li.append(badge, domain, score);
      recentList.appendChild(li);
    }
  }

  async function refresh() {
    const [settings, incidents] = await Promise.all([Sentinel.getSettings(), Sentinel.getIncidents()]);
    renderStatus(settings);
    renderCounts(incidents);
    renderRecent(incidents);
  }

  protectionToggle.addEventListener("change", async () => {
    await Sentinel.updateSettings({ protectionEnabled: protectionToggle.checked });
    refresh();
  });

  aiToggle.addEventListener("change", async () => {
    await Sentinel.updateSettings({ aiExplanationsEnabled: aiToggle.checked });
  });

  openDashboardBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("dashboard/dashboard.html") });
  });

  await refresh();
})();

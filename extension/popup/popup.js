(function () {
  "use strict";

  const elements = {
    statusCard: document.getElementById("status-card"),
    statusTitle: document.getElementById("status-title"),
    statusDescription: document.getElementById("status-description"),
    statusBadge: document.getElementById("status-badge"),
    statusCheck: document.getElementById("status-check"),
    toggleLabel: document.getElementById("toggle-label"),
    protectionToggle: document.getElementById("protection-toggle"),
    aiToggle: document.getElementById("ai-toggle"),
    countToday: document.getElementById("count-today"),
    countBlocked: document.getElementById("count-blocked"),
    countWarned: document.getElementById("count-warned"),
    todayDate: document.getElementById("today-date"),
    recentCount: document.getElementById("recent-count"),
    recentList: document.getElementById("recent-list"),
    openDashboard: document.getElementById("open-dashboard"),
  };

  const decisionLabels = {
    allow: "Allowed",
    warn: "Warning",
    blocked: "Blocked",
    detected_not_blocked: "Detected",
  };

  const eventLabels = {
    fetch_request: "Fetch request",
    xhr_request: "XHR request",
    send_beacon: "Background beacon",
    form_submission: "Form submission",
    redirect: "Redirect",
    history_change: "History change",
    clipboard_access: "Clipboard access",
    hidden_iframe: "Hidden iframe",
  };

  let currentSettings = {
    protectionEnabled: true,
    aiExplanationsEnabled: true,
  };

  function isToday(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    if (Number.isNaN(date.getTime())) return false;

    return (
      date.getFullYear() === now.getFullYear() &&
      date.getMonth() === now.getMonth() &&
      date.getDate() === now.getDate()
    );
  }

  function hostnameOf(incident) {
    const value =
      incident.destinationUrl ||
      incident.destinationOrigin ||
      incident.pageUrl ||
      incident.pageOrigin;

    if (!value) return "Unknown destination";

    try {
      return new URL(value).hostname || value;
    } catch {
      return String(value);
    }
  }

  function formatTime(timestamp) {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return "Unknown time";

    return new Intl.DateTimeFormat(undefined, {
      hour: "numeric",
      minute: "2-digit",
    }).format(date);
  }

  function renderStatus(settings) {
    const enabled = settings.protectionEnabled !== false;
    elements.protectionToggle.checked = enabled;
    elements.aiToggle.checked = settings.aiExplanationsEnabled !== false;
    elements.statusCard.classList.toggle("disabled", !enabled);
    elements.statusCard.classList.remove("error");

    elements.toggleLabel.textContent = enabled ? "Protection on" : "Protection off";
    elements.statusTitle.textContent = enabled
      ? "Protection is active"
      : "Protection is paused";
    elements.statusDescription.textContent = enabled
      ? "Monitoring browser behavior in real time."
      : "Runtime events are not being evaluated.";
    elements.statusBadge.textContent = enabled ? "Protected" : "Paused";
    elements.statusCheck.setAttribute(
      "d",
      enabled ? "m9.1 12 1.8 1.8 4.2-4.2" : "m9 9 6 6m0-6-6 6",
    );
  }

  function renderCounts(incidents) {
    const today = incidents.filter((incident) => isToday(incident.timestamp));
    const blocked = today.filter(
      (incident) => incident.decision === "blocked",
    ).length;
    const warned = today.filter((incident) =>
      ["warn", "detected_not_blocked"].includes(incident.decision),
    ).length;

    elements.countToday.textContent = String(today.length);
    elements.countBlocked.textContent = String(blocked);
    elements.countWarned.textContent = String(warned);
    elements.todayDate.textContent = new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
    }).format(new Date());
  }

  function renderRecent(incidents) {
    elements.recentList.replaceChildren();

    const recent = [...incidents]
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 4);

    elements.recentCount.textContent = `${incidents.length} ${
      incidents.length === 1 ? "event" : "events"
    }`;

    if (recent.length === 0) {
      const empty = document.createElement("li");
      empty.className = "empty-state";

      const icon = document.createElement("span");
      icon.className = "empty-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = "✓";

      const title = document.createElement("strong");
      title.textContent = "No incidents yet";

      const copy = document.createElement("p");
      copy.textContent =
        "Sentinel will surface suspicious browser behavior here.";

      empty.append(icon, title, copy);
      elements.recentList.append(empty);
      return;
    }

    for (const incident of recent) {
      elements.recentList.append(createIncidentRow(incident));
    }
  }

  function createIncidentRow(incident) {
    const decision = incident.decision || "allow";
    const row = document.createElement("li");
    row.className = `incident-row ${decisionClass(decision)}`;

    const severity = document.createElement("span");
    severity.className = "incident-severity";
    severity.setAttribute("aria-hidden", "true");

    const main = document.createElement("div");
    main.className = "incident-main";

    const text = document.createElement("div");
    text.className = "incident-text";

    const title = document.createElement("strong");
    title.className = "incident-title";
    title.textContent = hostnameOf(incident);
    title.title = title.textContent;

    const subtitle = document.createElement("span");
    subtitle.className = "incident-subtitle";
    subtitle.textContent =
      eventLabels[incident.eventType] ||
      String(incident.eventType || "Runtime event").replaceAll("_", " ");

    const score = document.createElement("span");
    score.className = "incident-score";
    score.textContent = String(Number.isFinite(incident.score) ? incident.score : 0);
    score.title = "Risk score out of 100";

    text.append(title, subtitle);
    main.append(text, score);

    const metadata = document.createElement("div");
    metadata.className = "incident-meta";

    const badge = document.createElement("span");
    badge.className = "decision-badge";
    badge.textContent = decisionLabels[decision] || "Observed";

    const time = document.createElement("span");
    time.className = "incident-time";
    time.textContent = formatTime(incident.timestamp);

    metadata.append(badge, time);
    row.append(severity, main, metadata);
    return row;
  }

  function decisionClass(decision) {
    if (decision === "blocked") return "blocked";
    if (decision === "warn") return "warned";
    if (decision === "detected_not_blocked") return "detected";
    return "allowed";
  }

  function renderError(message) {
    elements.statusCard.classList.add("error");
    elements.statusTitle.textContent = "Status unavailable";
    elements.statusDescription.textContent = message;
    elements.statusBadge.textContent = "Error";
  }

  async function refresh() {
    try {
      const [settings, incidents] = await Promise.all([
        Sentinel.getSettings(),
        Sentinel.getIncidents(),
      ]);

      currentSettings = settings;
      renderStatus(settings);
      renderCounts(incidents);
      renderRecent(incidents);
    } catch (error) {
      console.error("[Sentinel] popup refresh failed:", error);
      renderError("Could not read extension storage.");
    }
  }

  elements.protectionToggle.addEventListener("change", async () => {
    const previous = currentSettings.protectionEnabled !== false;
    const next = elements.protectionToggle.checked;
    elements.protectionToggle.disabled = true;

    try {
      currentSettings = await Sentinel.updateSettings({
        protectionEnabled: next,
      });
      renderStatus(currentSettings);
    } catch (error) {
      elements.protectionToggle.checked = previous;
      renderError("Could not update the protection setting.");
      console.error("[Sentinel] protection toggle failed:", error);
    } finally {
      elements.protectionToggle.disabled = false;
    }
  });

  elements.aiToggle.addEventListener("change", async () => {
    const previous = currentSettings.aiExplanationsEnabled !== false;
    elements.aiToggle.disabled = true;

    try {
      currentSettings = await Sentinel.updateSettings({
        aiExplanationsEnabled: elements.aiToggle.checked,
      });
    } catch (error) {
      elements.aiToggle.checked = previous;
      console.error("[Sentinel] AI explanation toggle failed:", error);
    } finally {
      elements.aiToggle.disabled = false;
    }
  });

  elements.openDashboard.addEventListener("click", async () => {
    elements.openDashboard.disabled = true;

    try {
      await chrome.tabs.create({
        url: chrome.runtime.getURL("dashboard/dashboard.html"),
      });
      window.close();
    } catch (error) {
      elements.openDashboard.disabled = false;
      renderError("Could not open the incident dashboard.");
      console.error("[Sentinel] dashboard open failed:", error);
    }
  });

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return;

    const keys = Sentinel.STORAGE_KEYS;
    if (changes[keys.INCIDENTS] || changes[keys.SETTINGS]) {
      void refresh();
    }
  });

  void refresh();
})();

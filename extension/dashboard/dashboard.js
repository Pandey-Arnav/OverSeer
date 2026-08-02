(function () {
  const filterSeverity = document.getElementById("filter-severity");
  const filterDecision = document.getElementById("filter-decision");
  const filterEventType = document.getElementById("filter-event-type");
  const filterDomain = document.getElementById("filter-domain");
  const rowsContainer = document.getElementById("incident-rows");
  const emptyState = document.getElementById("empty-state");
  const clearHistoryBtn = document.getElementById("clear-history");
  const confirmOverlay = document.getElementById("confirm-overlay");
  const confirmClearBtn = document.getElementById("confirm-clear");
  const cancelClearBtn = document.getElementById("cancel-clear");
  const aegisStatus = document.getElementById("aegis-status");
  const agentStatus = document.getElementById("agent-status");

  let allIncidents = [];
  let settings = { aiExplanationsEnabled: true };
  let expandedId = null;

  function hostnameOf(url) {
    if (!url) return "—";
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  function formatTime(iso) {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function setRuntimeStatus(element, label, value) {
    const target = element?.querySelector("span:last-child");
    if (!target) return;
    const strong = document.createElement("strong");
    strong.textContent = label;
    target.replaceChildren(strong, document.createTextNode(` ${value}`));
  }

  function applyFilters(incidents) {
    const severity = filterSeverity.value;
    const decision = filterDecision.value;
    const eventType = filterEventType.value;
    const domain = filterDomain.value.trim().toLowerCase();

    return incidents.filter((incident) => {
      if (severity && incident.severity !== severity) return false;
      if (decision && incident.decision !== decision) return false;
      if (eventType && incident.eventType !== eventType) return false;
      if (domain) {
        const hardware = incident.hardware || {};
        const haystack = `${incident.pageOrigin || ""} ${incident.destinationOrigin || ""} ${hardware.device?.displayName || ""} ${hardware.device?.driveLetter || ""}`.toLowerCase();
        if (!haystack.includes(domain)) return false;
      }
      return true;
    });
  }

  function renderSummary(incidents) {
    document.getElementById("summary-total").textContent = incidents.length;
    document.getElementById("summary-blocked").textContent = incidents.filter((i) => i.decision === "blocked").length;
    document.getElementById("summary-warned").textContent = incidents.filter((i) => i.decision === "warn").length;
    const avg = incidents.length
      ? Math.round(incidents.reduce((sum, i) => sum + i.score, 0) / incidents.length)
      : 0;
    document.getElementById("summary-avg-score").textContent = avg;
  }

  function buildDetailRow(incident) {
    const tr = document.createElement("tr");
    tr.className = "detail-row";
    const td = document.createElement("td");
    td.colSpan = 7;

    const meta = document.createElement("div");
    meta.className = "detail-meta";
    if (incident.source === "hardware") {
      const hardware = incident.hardware || {};
      meta.textContent = `${incident.simulated ? "Simulated USB test" : "Windows USB agent"} · ${hardware.device?.displayName || "USB volume"} · ${hardware.device?.driveLetter || "drive unavailable"} · ${hardware.inventory?.totalFiles ?? 0} files inventoried`;
    } else {
      meta.textContent = `Tab ${incident.tabId ?? "—"} · Method ${incident.method || "—"} · Payload ~${
        incident.payloadSize != null ? incident.payloadSize + " bytes" : "unknown"
      }`;
    }

    const reasons = Array.isArray(incident.reasons) ? incident.reasons : [];
    const reasonsList = document.createElement("ul");
    reasonsList.className = "detail-reasons";
    if (reasons.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No individual rules triggered.";
      reasonsList.appendChild(li);
    } else {
      for (const reason of reasons) {
        const li = document.createElement("li");
        li.textContent = `${reason.label} (+${reason.points})`;
        reasonsList.appendChild(li);
      }
    }

    td.append(meta, reasonsList);

    if (incident.source === "hardware") {
      td.appendChild(renderHardwareDetails(incident));
      const note = document.createElement("p");
      note.className = "detail-meta";
      note.textContent = "Privacy boundary: GhostShield stores counts and verdicts only. File contents, filenames, and USB serial numbers are not sent to the dashboard or AEGIS.";
      td.appendChild(note);
    } else if (incident.explanation) {
      td.appendChild(renderExplanation(incident.explanation));
    } else if (settings.aiExplanationsEnabled) {
      const button = document.createElement("button");
      button.className = "explain-button";
      button.textContent = "Generate AI explanation";
      button.addEventListener("click", async (e) => {
        e.stopPropagation();
        button.disabled = true;
        button.textContent = "Generating…";
        try {
          const explanation = await requestExplanation(incident);
          incident.explanation = explanation;
          await Sentinel.updateIncident(incident.id, { explanation });
          td.replaceChild(renderExplanation(explanation), button);
        } catch (err) {
          button.disabled = false;
          button.textContent = "Generate AI explanation";
          const errorBox = document.createElement("p");
          errorBox.className = "detail-meta";
          errorBox.textContent = `Could not reach explanation service: ${err.message}`;
          td.appendChild(errorBox);
        }
      });
      td.appendChild(button);
    } else {
      const note = document.createElement("p");
      note.className = "detail-meta";
      note.textContent = "AI explanations are turned off (enable in the popup).";
      td.appendChild(note);
    }

    td.appendChild(buildForkGuardControl(incident));
    tr.appendChild(td);
    return tr;
  }

  function renderHardwareDetails(incident) {
    const hardware = incident.hardware || {};
    const inventory = hardware.inventory || {};
    const defender = hardware.defender || {};
    const panel = document.createElement("div");
    panel.className = "hardware-details";
    const items = [
      ["Scanner", defender.available ? "Microsoft Defender" : "Unavailable"],
      ["Scan", defender.completed ? "Completed" : "Incomplete"],
      ["Threats", String(defender.threatCount || 0)],
      ["Executables", String(inventory.executableCount || 0)],
      ["Scripts", String(inventory.scriptCount || 0)],
      ["Shortcuts", String(inventory.shortcutCount || 0)],
      ["Archives", String(inventory.archiveCount || 0)],
      ["File system", hardware.device?.fileSystem || "Unknown"],
    ];
    for (const [label, value] of items) {
      const item = document.createElement("div");
      const key = document.createElement("span");
      key.textContent = label;
      const result = document.createElement("strong");
      result.textContent = value;
      item.append(key, result);
      panel.appendChild(item);
    }
    return panel;
  }

  function buildForkGuardControl(incident) {
    const section = document.createElement("section");
    section.className = "forkguard-section";

    if (incident.forkguardAnalysis) {
      section.appendChild(renderForkGuard(incident.forkguardAnalysis));
      return section;
    }

    const heading = document.createElement("div");
    heading.className = "forkguard-heading";

    const copy = document.createElement("div");
    const eyebrow = document.createElement("span");
    eyebrow.className = "forkguard-eyebrow";
    eyebrow.textContent = "AEGIS FORKGUARD";
    const title = document.createElement("strong");
    title.textContent = "Evaluate four safer futures";
    const description = document.createElement("p");
    description.textContent = "Runs a Jac decision graph over this sanitized Sentinel incident. No page content or credentials are sent.";
    copy.append(eyebrow, title, description);

    const button = document.createElement("button");
    button.className = "forkguard-button";
    button.type = "button";
    button.textContent = "Run AEGIS review";
    button.addEventListener("click", async (event) => {
      event.stopPropagation();
      button.disabled = true;
      button.textContent = "Forking futures...";
      try {
        const analysis = await requestForkGuard(incident);
        incident.forkguardAnalysis = analysis;
        await Sentinel.updateIncident(incident.id, { forkguardAnalysis: analysis });
        section.replaceChildren(renderForkGuard(analysis));
      } catch (error) {
        button.disabled = false;
        button.textContent = "Retry AEGIS review";
        const errorMessage = document.createElement("p");
        errorMessage.className = "forkguard-error";
        errorMessage.textContent = error.message;
        section.appendChild(errorMessage);
      }
    });

    heading.append(copy, button);
    section.appendChild(heading);
    return section;
  }

  function renderForkGuard(analysis) {
    const container = document.createElement("div");
    container.className = "forkguard-result";
    const selectedBranch = analysis?.decision?.selectedBranch || "UNKNOWN";

    const summary = document.createElement("div");
    summary.className = "forkguard-result-summary";

    const title = document.createElement("div");
    const eyebrow = document.createElement("span");
    eyebrow.className = "forkguard-eyebrow";
    eyebrow.textContent = "AEGIS DECISION";
    const selected = document.createElement("strong");
    selected.textContent = selectedBranch;
    const status = document.createElement("span");
    status.className = "forkguard-status";
    status.textContent = String(analysis?.decision?.status || "REVIEW_COMPLETE").replaceAll("_", " ");
    title.append(eyebrow, selected, status);

    const summaryText = document.createElement("p");
    summaryText.textContent = analysis?.decision?.summary || "AEGIS completed its counterfactual review.";
    summary.append(title, summaryText);

    const branches = document.createElement("div");
    branches.className = "forkguard-branches";
    for (const branch of Array.isArray(analysis?.branches) ? analysis.branches : []) {
      const card = document.createElement("article");
      card.className = "forkguard-branch";
      if (branch.name === selectedBranch) card.classList.add("selected");
      if (branch.valid === false) card.classList.add("rejected");

      const branchName = document.createElement("strong");
      branchName.textContent = branch.name;
      const branchTitle = document.createElement("span");
      branchTitle.textContent = branch.title;
      const scores = document.createElement("small");
      scores.textContent = `Risk ${branch.riskScore} / Utility ${branch.utilityScore}`;
      const verdict = document.createElement("em");
      verdict.textContent = String(branch.verdict || "PENDING").replaceAll("_", " ");
      card.append(branchName, branchTitle, scores, verdict);
      branches.appendChild(card);
    }

    const footnote = document.createElement("p");
    footnote.className = "forkguard-footnote";
    footnote.textContent = `Jac graph ${analysis?.graph?.nodes?.length || 0} nodes / ${analysis?.graph?.edges?.length || 0} edges - simulated counterfactual review only.`;

    container.append(summary, branches, footnote);
    return container;
  }

  function renderExplanation(explanation) {
    const box = document.createElement("div");
    box.className = "explanation-box";
    box.innerHTML = `
      <h4>AI explanation</h4>
      <p>${explanation.summary}</p>
      <p><strong>Technical:</strong> ${explanation.technicalExplanation}</p>
      <p><strong>Recommendation:</strong> ${explanation.recommendation}</p>
    `;
    return box;
  }

  async function requestExplanation(incident) {
    const response = await fetch(`${Sentinel.BACKEND_URL}/api/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        eventType: incident.eventType,
        pageOrigin: incident.pageOrigin,
        destinationOrigin: incident.destinationOrigin,
        method: incident.method,
        payloadSize: incident.payloadSize,
        score: incident.score,
        reasons: incident.reasons,
      }),
    });
    if (!response.ok) throw new Error(`server responded ${response.status}`);
    return response.json();
  }

  async function requestForkGuard(incident) {
    const response = await fetch(`${Sentinel.BACKEND_URL}/api/forkguard/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incidentId: incident.id,
        eventType: incident.eventType,
        pageOrigin: incident.pageOrigin,
        destinationOrigin: incident.destinationOrigin,
        score: incident.score,
        decision: incident.decision,
        reasons: Array.isArray(incident.reasons) ? incident.reasons : [],
      }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `ForkGuard server responded ${response.status}`);
    return result;
  }

  async function refreshAegisStatus() {
    if (!aegisStatus) return;
    try {
      const response = await fetch(`${Sentinel.BACKEND_URL}/api/forkguard/health`);
      if (!response.ok) throw new Error("offline");
      aegisStatus.className = "aegis-status online";
      aegisStatus.querySelector("span:last-child").innerHTML = "<strong>AEGIS</strong> online";
    } catch {
      aegisStatus.className = "aegis-status offline";
      aegisStatus.querySelector("span:last-child").innerHTML = "<strong>AEGIS</strong> offline";
    }
  }

  async function refreshAgentStatus() {
    if (!agentStatus) return;
    try {
      const response = await fetch(`${Sentinel.BACKEND_URL}/api/hardware/health`);
      if (!response.ok) throw new Error("offline");
      const health = await response.json();
      const onlineAgent = Array.isArray(health.agents) ? health.agents.find((agent) => agent.online) : null;
      if (!health.online || !onlineAgent) throw new Error("offline");
      agentStatus.className = "aegis-status online";
      setRuntimeStatus(agentStatus, "USB AGENT", onlineAgent.status || "online");
    } catch {
      agentStatus.className = "aegis-status offline";
      setRuntimeStatus(agentStatus, "USB AGENT", "offline");
    }
  }

  async function fetchHardwareIncidents() {
    try {
      const response = await fetch(`${Sentinel.BACKEND_URL}/api/hardware/incidents?limit=500`);
      if (!response.ok) throw new Error("offline");
      const payload = await response.json();
      return Array.isArray(payload.incidents) ? payload.incidents : [];
    } catch {
      return [];
    }
  }

  function sourceLabel(incident) {
    return incident.source === "hardware"
      ? incident.simulated ? "Simulated USB test" : "Windows USB agent"
      : hostnameOf(incident.pageUrl);
  }

  function targetLabel(incident) {
    return incident.source === "hardware"
      ? incident.hardware?.device?.displayName || "USB volume"
      : hostnameOf(incident.destinationUrl);
  }

  function render() {
    const filtered = applyFilters(allIncidents);
    renderSummary(allIncidents);
    rowsContainer.innerHTML = "";
    emptyState.hidden = filtered.length !== 0;

    for (const incident of filtered) {
      const tr = document.createElement("tr");
      tr.className = "incident-row";
      tr.innerHTML = `
        <td>${formatTime(incident.timestamp)}</td>
        <td>${escapeHtml(sourceLabel(incident))}</td>
        <td>${escapeHtml(targetLabel(incident))}</td>
        <td>${incident.eventType.replace(/_/g, " ")}</td>
        <td><span class="severity-dot severity-${incident.severity}"></span>${incident.score}</td>
        <td><span class="badge badge-${incident.decision}">${incident.decision.replace(/_/g, " ")}</span></td>
        <td>${expandedId === incident.id ? "▾" : "▸"}</td>
      `;
      tr.addEventListener("click", () => {
        expandedId = expandedId === incident.id ? null : incident.id;
        render();
      });
      rowsContainer.appendChild(tr);

      if (expandedId === incident.id) {
        rowsContainer.appendChild(buildDetailRow(incident));
      }
    }
  }

  async function refresh() {
    const [browserIncidents, hardwareIncidents, currentSettings] = await Promise.all([
      Sentinel.getIncidents(),
      fetchHardwareIncidents(),
      Sentinel.getSettings(),
    ]);
    settings = currentSettings;
    allIncidents = [...browserIncidents, ...hardwareIncidents]
      .filter((incident, index, incidents) => incidents.findIndex((candidate) => candidate.id === incident.id) === index)
      .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp));
    render();
  }

  [filterSeverity, filterDecision, filterEventType].forEach((el) => el.addEventListener("change", render));
  filterDomain.addEventListener("input", render);

  clearHistoryBtn.addEventListener("click", () => {
    confirmOverlay.hidden = false;
  });
  cancelClearBtn.addEventListener("click", () => {
    confirmOverlay.hidden = true;
  });
  confirmClearBtn.addEventListener("click", async () => {
    await Sentinel.clearIncidents();
    await fetch(`${Sentinel.BACKEND_URL}/api/hardware/incidents`, { method: "DELETE" }).catch(() => null);
    confirmOverlay.hidden = true;
    expandedId = null;
    await refresh();
  });

  void refresh();
  void refreshAegisStatus();
  void refreshAgentStatus();
  setInterval(() => {
    void refresh();
    void refreshAegisStatus();
    void refreshAgentStatus();
  }, 5000);
})();

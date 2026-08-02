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
        const haystack = `${incident.pageOrigin || ""} ${incident.destinationOrigin || ""}`.toLowerCase();
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
    meta.textContent = `Tab ${incident.tabId ?? "—"} · Method ${incident.method || "—"} · Payload ~${
      incident.payloadSize != null ? incident.payloadSize + " bytes" : "unknown"
    }`;

    const reasonsList = document.createElement("ul");
    reasonsList.className = "detail-reasons";
    if (incident.reasons.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No individual rules triggered.";
      reasonsList.appendChild(li);
    } else {
      for (const reason of incident.reasons) {
        const li = document.createElement("li");
        li.textContent = `${reason.label} (+${reason.points})`;
        reasonsList.appendChild(li);
      }
    }

    td.append(meta, reasonsList);

    if (incident.explanation) {
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

    tr.appendChild(td);
    return tr;
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
        <td>${hostnameOf(incident.pageUrl)}</td>
        <td>${hostnameOf(incident.destinationUrl)}</td>
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
    [allIncidents, settings] = await Promise.all([Sentinel.getIncidents(), Sentinel.getSettings()]);
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
    confirmOverlay.hidden = true;
    expandedId = null;
    await refresh();
  });

  refresh();
})();

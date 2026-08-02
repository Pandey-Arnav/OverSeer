/**
 * Sentinel Agent dashboard — runs in a real browser tab (localhost),
 * bundled to public/dashboard.js by esbuild since the browser can't run
 * .ts directly. Talks to the same-origin Express API in server/app.ts.
 */
import type { AegisReport, AIExplanation, Decision, Incident, Settings } from "../shared/types.ts";

const REFRESH_INTERVAL_MS = 5000;

(function () {
  function requireEl<T extends Element>(id: string): T {
    const el = document.getElementById(id);
    if (!el) throw new Error(`Sentinel dashboard: missing #${id}`);
    return el as unknown as T;
  }

  const statusLine = requireEl<HTMLElement>("status-line");
  const protectionToggle = requireEl<HTMLInputElement>("protection-toggle");
  const aiToggle = requireEl<HTMLInputElement>("ai-toggle");
  const clearHistoryBtn = requireEl<HTMLButtonElement>("clear-history");
  const aegisStatus = requireEl<HTMLElement>("aegis-status");
  const aegisIndicator = requireEl<HTMLElement>("aegis-indicator");

  const filterCategory = requireEl<HTMLSelectElement>("filter-category");
  const filterSeverity = requireEl<HTMLSelectElement>("filter-severity");
  const filterDecision = requireEl<HTMLSelectElement>("filter-decision");
  const filterSearch = requireEl<HTMLInputElement>("filter-search");
  const rowsContainer = requireEl<HTMLTableSectionElement>("incident-rows");
  const emptyState = requireEl<HTMLElement>("empty-state");

  const confirmOverlay = requireEl<HTMLElement>("confirm-overlay");
  const confirmMessage = requireEl<HTMLElement>("confirm-message");
  const confirmYesBtn = requireEl<HTMLButtonElement>("confirm-yes");
  const confirmNoBtn = requireEl<HTMLButtonElement>("confirm-no");

  let allIncidents: Incident[] = [];
  let settings: Settings = { protectionEnabled: true, aiExplanationsEnabled: true };
  let expandedId: string | null = null;
  let pendingConfirmAction: (() => Promise<void>) | null = null;

  function hostnameOrName(incident: Incident): string {
    if (incident.category === "network_connection") {
      return incident.remoteAddress ? `${incident.remoteAddress}${incident.remotePort ? ":" + incident.remotePort : ""}` : "—";
    }
    return incident.deviceName || "—";
  }

  function formatTime(iso: string): string {
    return new Date(iso).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function applyFilters(incidents: Incident[]): Incident[] {
    const category = filterCategory.value;
    const severity = filterSeverity.value;
    const decision = filterDecision.value;
    const search = filterSearch.value.trim().toLowerCase();

    return incidents.filter((incident) => {
      if (category && incident.category !== category) return false;
      if (severity && incident.severity !== severity) return false;
      if (decision && incident.decision !== decision) return false;
      if (search) {
        const haystack = `${incident.processName || ""} ${incident.remoteAddress || ""} ${incident.deviceName || ""} ${incident.summary}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      return true;
    });
  }

  function renderSummary(incidents: Incident[]): void {
    requireEl<HTMLElement>("summary-total").textContent = String(incidents.length);
    requireEl<HTMLElement>("summary-blocked").textContent = String(incidents.filter((i) => i.decision === "blocked").length);
    requireEl<HTMLElement>("summary-warned").textContent = String(incidents.filter((i) => i.decision === "warn").length);
    const avg = incidents.length ? Math.round(incidents.reduce((sum, i) => sum + i.score, 0) / incidents.length) : 0;
    requireEl<HTMLElement>("summary-avg-score").textContent = String(avg);
  }

  function renderStatus(): void {
    const enabled = settings.protectionEnabled !== false;
    protectionToggle.checked = enabled;
    aiToggle.checked = settings.aiExplanationsEnabled !== false;
    statusLine.textContent = enabled ? "Protection active — monitoring network connections and USB devices." : "Protection paused — nothing is being monitored.";
    statusLine.className = `status-line ${enabled ? "enabled" : "disabled"}`;
  }

  function renderExplanation(explanation: AIExplanation): HTMLDivElement {
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

  function renderAegisReport(report: AegisReport): HTMLDivElement {
    const box = document.createElement("div");
    box.className = "aegis-box";

    const heading = document.createElement("h4");
    heading.textContent = `AEGIS ForkGuard · ${report.decision.selectedBranch}`;
    const summary = document.createElement("p");
    summary.textContent = report.decision.summary;
    const confidence = document.createElement("p");
    confidence.textContent = `Confidence ${Math.round(report.decision.confidence * 100)}% · ${report.decision.status}`;
    const branchGrid = document.createElement("div");
    branchGrid.className = "branch-grid";
    for (const branch of report.branches) {
      const chip = document.createElement("span");
      chip.className = `branch-chip${branch.name === report.decision.selectedBranch ? " selected" : ""}`;
      chip.textContent = `${branch.name} · ${branch.verdict}`;
      branchGrid.appendChild(chip);
    }
    box.append(heading, summary, confidence, branchGrid);
    return box;
  }

  async function requestExplanation(incident: Incident): Promise<AIExplanation> {
    const response = await fetch(`/api/incidents/${incident.id}/explain`, { method: "POST" });
    if (!response.ok) throw new Error(`server responded ${response.status}`);
    return response.json();
  }

  async function requestRemediation(incident: Incident): Promise<{ ok: boolean; message: string }> {
    const response = await fetch(`/api/incidents/${incident.id}/remediate`, { method: "POST" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({ error: `server responded ${response.status}` }));
      throw new Error(body.error || `server responded ${response.status}`);
    }
    return response.json();
  }

  async function requestAegisReview(incident: Incident): Promise<AegisReport> {
    const response = await fetch(`/api/incidents/${incident.id}/aegis`, { method: "POST" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({ error: `server responded ${response.status}` }));
      throw new Error(body.error || `server responded ${response.status}`);
    }
    return response.json();
  }

  async function refreshAegisHealth(): Promise<void> {
    try {
      const response = await fetch("/api/aegis/health");
      const health = await response.json();
      const online = response.ok && health.status === "ok";
      aegisStatus.textContent = online ? "Online · ready" : "Offline · Sentinel active";
      aegisIndicator.className = `pulse-dot ${online ? "online" : "offline"}`;
    } catch {
      aegisStatus.textContent = "Offline · Sentinel active";
      aegisIndicator.className = "pulse-dot offline";
    }
  }

  function buildDetailRow(incident: Incident): HTMLTableRowElement {
    const tr = document.createElement("tr");
    tr.className = "detail-row";
    const td = document.createElement("td");
    td.colSpan = 6;

    const meta = document.createElement("div");
    meta.className = "detail-meta";
    const metaParts = [
      incident.processName ? `Process: ${incident.processName}` : null,
      incident.processPath ? `Path: ${incident.processPath}` : null,
    ].filter(Boolean);
    meta.textContent = metaParts.join(" · ") || "No additional process metadata.";

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

    if (incident.defenderScanStatus) {
      const defender = document.createElement("span");
      defender.className = "defender-note";
      defender.textContent =
        incident.defenderScanStatus === "threat_found"
          ? `Microsoft Defender: ${incident.defenderThreatCount ?? 1} threat(s) detected`
          : incident.defenderScanStatus === "clean"
            ? "Microsoft Defender: scan completed clean"
            : "Microsoft Defender: scan unavailable";
      td.appendChild(defender);
    }

    const actionRow = document.createElement("div");
    actionRow.className = "action-row";

    if (incident.explanation) {
      td.appendChild(renderExplanation(incident.explanation));
    } else if (settings.aiExplanationsEnabled) {
      const explainBtn = document.createElement("button");
      explainBtn.className = "explain-button";
      explainBtn.textContent = "Generate AI explanation";
      explainBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        explainBtn.disabled = true;
        explainBtn.textContent = "Generating…";
        try {
          const explanation = await requestExplanation(incident);
          incident.explanation = explanation;
          explainBtn.remove();
          td.appendChild(renderExplanation(explanation));
        } catch (err) {
          explainBtn.disabled = false;
          explainBtn.textContent = "Generate AI explanation";
          console.error(err);
        }
      });
      actionRow.appendChild(explainBtn);
    }

    if (incident.aegisReport) {
      td.appendChild(renderAegisReport(incident.aegisReport));
    } else {
      const aegisBtn = document.createElement("button");
      aegisBtn.className = "aegis-button";
      aegisBtn.textContent = "Run AEGIS analysis";
      aegisBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        aegisBtn.disabled = true;
        aegisBtn.textContent = "Forking futures…";
        try {
          const report = await requestAegisReview(incident);
          incident.aegisReport = report;
          aegisBtn.remove();
          td.appendChild(renderAegisReport(report));
        } catch (err) {
          aegisBtn.disabled = false;
          aegisBtn.textContent = "AEGIS offline · retry";
          console.error(err);
          void refreshAegisHealth();
        }
      });
      actionRow.appendChild(aegisBtn);
    }

    if (incident.remediation?.available && !incident.remediation.applied) {
      const remediateBtn = document.createElement("button");
      remediateBtn.className = "remediate-button";
      remediateBtn.textContent =
        incident.remediation.action === "terminate_process" ? "Terminate process" : "Eject device";
      remediateBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        confirmMessage.textContent =
          incident.remediation!.action === "terminate_process"
            ? `Terminate process "${incident.processName}" (pid ${incident.remediation!.pid})? This cannot be undone.`
            : `Eject "${incident.deviceName}"? Make sure no files are being written to it.`;
        pendingConfirmAction = async () => {
          remediateBtn.disabled = true;
          remediateBtn.textContent = "Working…";
          try {
            const result = await requestRemediation(incident);
            remediateBtn.textContent = result.ok ? "Done" : "Failed";
            if (!result.ok) console.error(result.message);
            await refresh();
          } catch (err) {
            remediateBtn.disabled = false;
            remediateBtn.textContent = "Terminate process";
            console.error(err);
          }
        };
        confirmOverlay.hidden = false;
      });
      actionRow.appendChild(remediateBtn);
    } else if (incident.remediation && !incident.remediation.available) {
      const note = document.createElement("p");
      note.className = "detail-meta";
      note.textContent = incident.remediation.reason;
      actionRow.appendChild(note);
    } else if (incident.remediation?.applied) {
      const note = document.createElement("p");
      note.className = "detail-meta";
      note.textContent = `Remediation applied at ${incident.remediation.appliedAt ? formatTime(incident.remediation.appliedAt) : "unknown time"}.`;
      actionRow.appendChild(note);
    }

    if (actionRow.children.length > 0) td.appendChild(actionRow);

    tr.appendChild(td);
    return tr;
  }

  function decisionLabel(decision: Decision): string {
    if (decision === "blocked") return "action available";
    if (decision === "detected_not_blocked") return "detected";
    return decision;
  }

  function render(): void {
    const filtered = applyFilters(allIncidents);
    renderSummary(allIncidents);
    rowsContainer.innerHTML = "";
    emptyState.hidden = filtered.length !== 0;

    for (const incident of filtered) {
      const tr = document.createElement("tr");
      tr.className = "incident-row";
      tr.innerHTML = `
        <td>${formatTime(incident.timestamp)}</td>
        <td>${incident.category.replace(/_/g, " ")}</td>
        <td>${incident.summary} <span style="color:#9ca3af;">(${hostnameOrName(incident)})</span></td>
        <td><span class="severity-dot severity-${incident.severity}"></span>${incident.score}</td>
        <td><span class="badge badge-${incident.decision}">${decisionLabel(incident.decision)}</span></td>
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

  async function refresh(): Promise<void> {
    const [incidentsRes, settingsRes] = await Promise.all([fetch("/api/incidents"), fetch("/api/settings")]);
    allIncidents = await incidentsRes.json();
    settings = await settingsRes.json();
    renderStatus();
    render();
    void refreshAegisHealth();
  }

  [filterCategory, filterSeverity, filterDecision].forEach((el) => el.addEventListener("change", render));
  filterSearch.addEventListener("input", render);

  protectionToggle.addEventListener("change", async () => {
    settings = await (await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ protectionEnabled: protectionToggle.checked }),
    })).json();
    renderStatus();
  });

  aiToggle.addEventListener("change", async () => {
    settings = await (await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ aiExplanationsEnabled: aiToggle.checked }),
    })).json();
  });

  clearHistoryBtn.addEventListener("click", () => {
    confirmMessage.textContent = "Clear all stored incidents? This cannot be undone.";
    pendingConfirmAction = async () => {
      await fetch("/api/incidents/clear", { method: "POST" });
      expandedId = null;
      await refresh();
    };
    confirmOverlay.hidden = false;
  });

  confirmNoBtn.addEventListener("click", () => {
    confirmOverlay.hidden = true;
    pendingConfirmAction = null;
  });
  confirmYesBtn.addEventListener("click", async () => {
    confirmOverlay.hidden = true;
    if (pendingConfirmAction) await pendingConfirmAction();
    pendingConfirmAction = null;
  });

  void refresh();
  setInterval(() => void refresh(), REFRESH_INTERVAL_MS);
})();

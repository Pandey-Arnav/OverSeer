/**
 * Sentinel Agent dashboard — runs in a real browser tab (localhost),
 * bundled to public/dashboard.js by esbuild since the browser can't run
 * .ts directly. Talks to the same-origin Express API in server/app.ts.
 */
import type {
  AegisReport,
  AIExplanation,
  AnalyticsMetric,
  Decision,
  FrameworkMapping,
  Incident,
  SecurityInsights,
  Settings,
} from "../shared/types.ts";

const REFRESH_INTERVAL_MS = 5000;

interface BankIncidentHandoff {
  incidentId: string;
  timestamp: string;
  user: string;
  originalRecipient: string;
  modifiedRecipient: string;
  originalAmount: number | string;
  modifiedAmount: number | string;
  originalAccount?: string;
  modifiedAccount?: string;
  attackType: string;
  confidence: number;
  outcome: "Frozen" | "User Override";
  actionsTaken: string[];
  timeline?: string[];
}

(function () {
  function requireEl<T extends Element>(id: string): T {
    const el = document.getElementById(id);
    if (!el) throw new Error(`Sentinel dashboard: missing #${id}`);
    return el as unknown as T;
  }

  const statusLine = requireEl<HTMLElement>("status-line");
  const protectionToggle = requireEl<HTMLInputElement>("protection-toggle");
  const aiToggle = requireEl<HTMLInputElement>("ai-toggle");
  const honeypotToggle = requireEl<HTMLInputElement>("honeypot-toggle");
  const clearHistoryBtn = requireEl<HTMLButtonElement>("clear-history");
  const aegisStatus = requireEl<HTMLElement>("aegis-status");
  const aegisIndicator = requireEl<HTMLElement>("aegis-indicator");

  const filterCategory = requireEl<HTMLSelectElement>("filter-category");
  const filterSeverity = requireEl<HTMLSelectElement>("filter-severity");
  const filterDecision = requireEl<HTMLSelectElement>("filter-decision");
  const filterSearch = requireEl<HTMLInputElement>("filter-search");
  const rowsContainer = requireEl<HTMLTableSectionElement>("incident-rows");
  const emptyState = requireEl<HTMLElement>("empty-state");
  const alertsList = requireEl<HTMLElement>("alerts-list");
  const alertsEmpty = requireEl<HTMLElement>("alerts-empty");
  const timelineList = requireEl<HTMLElement>("timeline-list");
  const timelineEmpty = requireEl<HTMLElement>("timeline-empty");
  const correlationList = requireEl<HTMLElement>("correlation-list");
  const correlationEmpty = requireEl<HTMLElement>("correlation-empty");
  const analyticsCategories = requireEl<HTMLElement>("analytics-categories");
  const analyticsSeverities = requireEl<HTMLElement>("analytics-severities");
  const analyticsMappings = requireEl<HTMLElement>("analytics-mappings");
  const attackHistoryList = requireEl<HTMLElement>("attack-history-list");
  const historyEmpty = requireEl<HTMLElement>("history-empty");

  const confirmOverlay = requireEl<HTMLElement>("confirm-overlay");
  const confirmMessage = requireEl<HTMLElement>("confirm-message");
  const confirmYesBtn = requireEl<HTMLButtonElement>("confirm-yes");
  const confirmNoBtn = requireEl<HTMLButtonElement>("confirm-no");

  let allIncidents: Incident[] = [];
  let settings: Settings = { protectionEnabled: true, aiExplanationsEnabled: true, honeypotArmed: false };
  let insights: SecurityInsights | null = null;
  let expandedId: string | null = null;
  let bankHandoffOpened = false;
  let focusBankHandoff = false;
  let pendingConfirmAction: (() => Promise<void>) | null = null;

  function readBankIncidentHandoff(): BankIncidentHandoff | null {
    const encoded = new URLSearchParams(window.location.search).get("bankIncident");
    if (!encoded) return null;
    try {
      const value = JSON.parse(encoded) as Partial<BankIncidentHandoff>;
      if (!value.incidentId || !value.timestamp || !value.originalRecipient || !value.modifiedRecipient) return null;
      const clean = (input: unknown): string => String(input ?? "").replace(/[<>&\u0000-\u001f]/g, "").slice(0, 240);
      return {
        incidentId: clean(value.incidentId),
        timestamp: clean(value.timestamp),
        user: clean(value.user),
        originalRecipient: clean(value.originalRecipient),
        modifiedRecipient: clean(value.modifiedRecipient),
        originalAmount: clean(value.originalAmount),
        modifiedAmount: clean(value.modifiedAmount),
        originalAccount: clean(value.originalAccount),
        modifiedAccount: clean(value.modifiedAccount),
        attackType: clean(value.attackType || "DOM Injection"),
        confidence: Math.min(100, Math.max(0, Number(value.confidence) || 0)),
        outcome: value.outcome === "User Override" ? "User Override" : "Frozen",
        actionsTaken: Array.isArray(value.actionsTaken) ? value.actionsTaken.map(clean).slice(0, 12) : [],
        timeline: Array.isArray(value.timeline) ? value.timeline.map(clean).slice(0, 16) : [],
      };
    } catch {
      return null;
    }
  }

  function bankIncidentToDashboardIncident(bank: BankIncidentHandoff): Incident {
    const original = `${bank.originalRecipient} · $${bank.originalAmount}${bank.originalAccount ? ` · account ${bank.originalAccount}` : ""}`;
    const modified = `${bank.modifiedRecipient} · $${bank.modifiedAmount}${bank.modifiedAccount ? ` · account ${bank.modifiedAccount}` : ""}`;
    return {
      id: bank.incidentId,
      timestamp: bank.timestamp,
      category: "transaction_tampering",
      summary: `${bank.attackType}: ${bank.originalRecipient} → ${bank.modifiedRecipient}`,
      processName: null,
      processPath: null,
      remoteAddress: null,
      remotePort: null,
      deviceName: "Northstar Bank Demo",
      pageOrigin: "Northstar Bank Demo",
      tamperedFieldNames: ["recipient", "amount", "account number"],
      scriptFindings: [
        `User: ${bank.user}`,
        `Confidence: ${bank.confidence}%`,
        `Original transaction: ${original}`,
        `Modified transaction: ${modified}`,
        `Outcome: ${bank.outcome}`,
        ...bank.actionsTaken,
      ],
      honeypotCommand: null,
      score: 100,
      severity: "high",
      decision: bank.outcome === "Frozen" ? "blocked" : "detected_not_blocked",
      reasons: [
        { ruleId: "bank-dom-injection", label: `${bank.attackType} detected with ${bank.confidence}% confidence`, points: 100 },
        { ruleId: "bank-user", label: `User: ${bank.user}`, points: 0 },
        { ruleId: "bank-original", label: `Original transaction: ${original}`, points: 0 },
        { ruleId: "bank-modified", label: `Modified transaction: ${modified}`, points: 0 },
        { ruleId: "bank-outcome", label: `Status: ${bank.outcome} · ${bank.actionsTaken.join(", ")}`, points: 0 },
        ...(bank.timeline ?? []).map((step, index) => ({ ruleId: `bank-timeline-${index + 1}`, label: `${index + 1}. ${step}`, points: 0 })),
      ],
      explanation: null,
      aegisReport: null,
      remediation: null,
      defenderScanStatus: null,
      defenderThreatCount: null,
    };
  }

  function mergeBankHandoff(bank: BankIncidentHandoff, fetchedInsights: SecurityInsights): void {
    const incident = bankIncidentToDashboardIncident(bank);
    allIncidents = [incident, ...allIncidents.filter((item) => item.id !== incident.id)];
    insights = {
      ...fetchedInsights,
      liveRiskScore: 100,
      liveRiskLevel: "critical",
      activeAlertCount: fetchedInsights.activeAlertCount + 1,
      alerts: [{
        incidentId: incident.id,
        timestamp: incident.timestamp,
        title: incident.summary,
        severity: "high",
        score: incident.score,
        decision: incident.decision,
        recommendation: bank.outcome === "Frozen" ? "Transaction frozen and recipient added to the watchlist." : "User overrode the warning; review the completed malicious transfer.",
      }, ...fetchedInsights.alerts.filter((alert) => alert.incidentId !== incident.id)],
      correlations: [{
        id: `bank-${incident.id}`,
        title: "Northstar transaction manipulation",
        description: `${bank.attackType} modified recipient and amount during transfer submission. Outcome: ${bank.outcome}.`,
        signal: "DOM mutation → transaction integrity violation",
        incidentIds: [incident.id],
        firstSeen: incident.timestamp,
        lastSeen: incident.timestamp,
        score: 100,
        severity: "high",
      }, ...fetchedInsights.correlations.filter((item) => !item.incidentIds.includes(incident.id))],
      mappingsByIncident: { ...fetchedInsights.mappingsByIncident, [incident.id]: [] },
    };
    if (!bankHandoffOpened) {
      expandedId = incident.id;
      bankHandoffOpened = true;
      focusBankHandoff = true;
    }
  }

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

  function renderSummary(): void {
    const liveRisk = insights?.liveRiskScore ?? 0;
    const liveRiskEl = requireEl<HTMLElement>("summary-live-risk");
    liveRiskEl.textContent = String(liveRisk);
    liveRiskEl.className = `card-value risk-value level-${insights?.liveRiskLevel ?? "normal"}`;
    requireEl<HTMLElement>("summary-risk-level").textContent = `${insights?.liveRiskLevel ?? "normal"} · last 15 minutes`;
    requireEl<HTMLElement>("summary-alerts").textContent = String(insights?.activeAlertCount ?? 0);
    requireEl<HTMLElement>("summary-correlations").textContent = String(insights?.correlations.length ?? 0);
    requireEl<HTMLElement>("summary-attack-events").textContent = String(
      insights?.history.reduce((sum, bucket) => sum + bucket.total, 0) ?? 0,
    );
  }

  function renderStatus(): void {
    const enabled = settings.protectionEnabled !== false;
    protectionToggle.checked = enabled;
    aiToggle.checked = settings.aiExplanationsEnabled !== false;
    honeypotToggle.checked = settings.honeypotArmed === true;
    statusLine.textContent = enabled ? "Protection active — monitoring network connections and USB devices." : "Protection paused — nothing is being monitored.";
    statusLine.className = `status-line ${enabled ? "enabled" : "disabled"}`;
  }

  function openIncident(incidentId: string): void {
    expandedId = incidentId;
    window.location.hash = "incidents";
    render();
    requireEl<HTMLElement>("incidents").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function renderAlerts(): void {
    alertsList.innerHTML = "";
    const alerts = insights?.alerts ?? [];
    alertsEmpty.hidden = alerts.length !== 0;
    requireEl<HTMLElement>("alert-count-chip").textContent = `${alerts.length} active`;

    for (const alert of alerts) {
      const item = document.createElement("button");
      item.type = "button";
      item.className = `alert-item alert-${alert.severity}`;

      const score = document.createElement("span");
      score.className = "alert-score";
      score.textContent = String(alert.score);

      const copy = document.createElement("span");
      copy.className = "alert-copy";
      const heading = document.createElement("strong");
      heading.textContent = alert.title;
      const recommendation = document.createElement("span");
      recommendation.textContent = alert.recommendation;
      copy.append(heading, recommendation);

      const time = document.createElement("time");
      time.dateTime = alert.timestamp;
      time.textContent = formatTime(alert.timestamp);
      item.append(score, copy, time);
      item.addEventListener("click", () => openIncident(alert.incidentId));
      alertsList.appendChild(item);
    }
  }

  function renderTimeline(): void {
    timelineList.innerHTML = "";
    const bank = readBankIncidentHandoff();
    if (bank?.timeline?.length) {
      timelineEmpty.hidden = true;
      bank.timeline.forEach((step, index) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = "timeline-item";
        const marker = document.createElement("span");
        marker.className = `timeline-marker severity-${bank.outcome === "Frozen" ? "high" : "medium"}`;
        const copy = document.createElement("span");
        copy.className = "timeline-copy";
        const heading = document.createElement("strong");
        heading.textContent = step;
        const meta = document.createElement("span");
        meta.textContent = `Northstar Bank · ${bank.attackType}`;
        copy.append(heading, meta);
        const time = document.createElement("time");
        const stepTime = new Date(Date.parse(bank.timestamp) + index * 1000);
        time.dateTime = stepTime.toISOString();
        time.textContent = formatTime(stepTime.toISOString());
        item.append(marker, copy, time);
        item.addEventListener("click", () => openIncident(bank.incidentId));
        timelineList.appendChild(item);
      });
      return;
    }
    const recent = [...allIncidents]
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
      .slice(0, 8);
    timelineEmpty.hidden = recent.length !== 0;

    for (const incident of recent) {
      const item = document.createElement("button");
      item.type = "button";
      item.className = "timeline-item";
      const marker = document.createElement("span");
      marker.className = `timeline-marker severity-${incident.severity}`;
      const copy = document.createElement("span");
      copy.className = "timeline-copy";
      const heading = document.createElement("strong");
      heading.textContent = incident.summary;
      const meta = document.createElement("span");
      meta.textContent = `${incident.category.replace(/_/g, " ")} · risk ${incident.score}`;
      copy.append(heading, meta);
      const time = document.createElement("time");
      time.dateTime = incident.timestamp;
      time.textContent = formatTime(incident.timestamp);
      item.append(marker, copy, time);
      item.addEventListener("click", () => openIncident(incident.id));
      timelineList.appendChild(item);
    }
  }

  function renderCorrelations(): void {
    correlationList.innerHTML = "";
    const correlations = insights?.correlations ?? [];
    correlationEmpty.hidden = correlations.length !== 0;

    for (const correlation of correlations) {
      const item = document.createElement("article");
      item.className = `correlation-card correlation-${correlation.severity}`;
      const top = document.createElement("div");
      top.className = "correlation-top";
      const heading = document.createElement("h3");
      heading.textContent = correlation.title;
      const score = document.createElement("span");
      score.className = "correlation-score";
      score.textContent = `Risk ${correlation.score}`;
      top.append(heading, score);
      const description = document.createElement("p");
      description.textContent = correlation.description;
      const footer = document.createElement("div");
      footer.className = "correlation-footer";
      const range = document.createElement("span");
      range.textContent = `${formatTime(correlation.firstSeen)} → ${formatTime(correlation.lastSeen)}`;
      const review = document.createElement("button");
      review.type = "button";
      review.className = "secondary-button";
      review.textContent = `Review ${correlation.incidentIds.length} events`;
      review.addEventListener("click", () => openIncident(correlation.incidentIds[0]!));
      footer.append(range, review);
      item.append(top, description, footer);
      correlationList.appendChild(item);
    }
  }

  function renderMetricList(container: HTMLElement, metrics: AnalyticsMetric[], emptyLabel: string): void {
    container.innerHTML = "";
    if (metrics.length === 0) {
      const empty = document.createElement("p");
      empty.className = "metric-empty";
      empty.textContent = emptyLabel;
      container.appendChild(empty);
      return;
    }
    const maximum = Math.max(...metrics.map((item) => item.count), 1);
    for (const item of metrics.slice(0, 7)) {
      const row = document.createElement("div");
      row.className = "metric-row";
      const heading = document.createElement("div");
      heading.className = "metric-heading";
      const label = document.createElement("span");
      label.textContent = item.label;
      const value = document.createElement("strong");
      value.textContent = `${item.count} · avg ${item.averageScore}`;
      heading.append(label, value);
      const track = document.createElement("div");
      track.className = "metric-track";
      const fill = document.createElement("span");
      fill.style.width = `${Math.max(4, (item.count / maximum) * 100)}%`;
      track.appendChild(fill);
      row.append(heading, track);
      container.appendChild(row);
    }
  }

  function renderAnalytics(): void {
    const analytics = insights?.analytics;
    requireEl<HTMLElement>("analytics-total").textContent = `${allIncidents.length} events analyzed`;
    renderMetricList(analyticsCategories, analytics?.categories ?? [], "No category data yet.");
    renderMetricList(analyticsSeverities, analytics?.severities ?? [], "No severity data yet.");
    renderMetricList(analyticsMappings, analytics?.mappings ?? [], "No framework-aligned events yet.");
  }

  function renderHistory(): void {
    attackHistoryList.innerHTML = "";
    const history = insights?.history ?? [];
    historyEmpty.hidden = history.length !== 0;
    const maximum = Math.max(...history.map((bucket) => bucket.total), 1);
    for (const bucket of history) {
      const item = document.createElement("article");
      item.className = "history-item";
      const date = document.createElement("time");
      date.dateTime = bucket.date;
      date.textContent = new Date(`${bucket.date}T12:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });
      const bar = document.createElement("div");
      bar.className = "history-track";
      const high = document.createElement("span");
      high.className = "history-high";
      high.style.width = `${(bucket.high / maximum) * 100}%`;
      const medium = document.createElement("span");
      medium.className = "history-medium";
      medium.style.width = `${(bucket.medium / maximum) * 100}%`;
      bar.append(high, medium);
      const count = document.createElement("strong");
      count.textContent = `${bucket.total} events · peak ${bucket.peakScore}`;
      item.append(date, bar, count);
      attackHistoryList.appendChild(item);
    }
  }

  function renderFrameworkMappings(mappings: FrameworkMapping[]): HTMLElement | null {
    if (mappings.length === 0) return null;
    const section = document.createElement("div");
    section.className = "framework-mappings";
    const heading = document.createElement("h4");
    heading.textContent = "Potential framework mappings";
    const note = document.createElement("p");
    note.textContent = "Behavioral alignment only; this does not prove the technique succeeded.";
    const chips = document.createElement("div");
    chips.className = "mapping-chips";
    for (const mapping of mappings) {
      const link = document.createElement("a");
      link.href = mapping.url;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = `${mapping.framework} · ${mapping.id} · ${mapping.name}`;
      chips.appendChild(link);
    }
    section.append(heading, note, chips);
    return section;
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

  function hardwareVerdictLabel(incident: Incident): string | null {
    const verdict = incident.hardwareAssessment?.verdict;
    if (!verdict) return null;
    if (verdict === "observing") return "observing";
    if (verdict === "no_harmful_behavior_observed") return "no harm observed";
    if (verdict === "suspicious") return "suspicious";
    return "harmful";
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
      incident.honeypotCommand ? `Command: ${incident.honeypotCommand}` : null,
      incident.vendorId || incident.productId ? `VID/PID: ${incident.vendorId ?? "?"}/${incident.productId ?? "?"}` : null,
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

    td.appendChild(meta);

    if (incident.hardwareAssessment) {
      const assessment = document.createElement("section");
      assessment.className = `hardware-assessment hardware-${incident.hardwareAssessment.verdict}`;
      const heading = document.createElement("strong");
      heading.textContent = `Hardware verdict: ${hardwareVerdictLabel(incident)}`;
      const explanation = document.createElement("p");
      explanation.textContent = `${incident.hardwareAssessment.reason} Confidence: ${incident.hardwareAssessment.confidence}.`;
      assessment.append(heading, explanation);
      if (incident.hardwareAssessment.evidence.length > 0) {
        const evidence = document.createElement("ul");
        for (const item of incident.hardwareAssessment.evidence) {
          const li = document.createElement("li");
          li.textContent = item;
          evidence.appendChild(li);
        }
        assessment.appendChild(evidence);
      }
      td.appendChild(assessment);
    }

    td.appendChild(reasonsList);

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

    const frameworkMappings = renderFrameworkMappings(insights?.mappingsByIncident[incident.id] ?? []);
    if (frameworkMappings) td.appendChild(frameworkMappings);

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
    renderSummary();
    renderAlerts();
    renderTimeline();
    renderCorrelations();
    renderAnalytics();
    renderHistory();
    rowsContainer.innerHTML = "";
    emptyState.hidden = filtered.length !== 0;

    for (const incident of filtered) {
      const tr = document.createElement("tr");
      tr.className = "incident-row";
      const hardwareLabel = hardwareVerdictLabel(incident);
      const hardwareBadge = incident.hardwareAssessment && hardwareLabel
        ? `<span class="hardware-verdict hardware-${incident.hardwareAssessment.verdict}">${hardwareLabel}</span>`
        : "";
      tr.innerHTML = `
        <td>${formatTime(incident.timestamp)}</td>
        <td>${incident.category.replace(/_/g, " ")}</td>
        <td>${incident.summary} <span style="color:#9ca3af;">(${hostnameOrName(incident)})</span> ${hardwareBadge}</td>
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
    const [incidentsRes, settingsRes, insightsRes] = await Promise.all([
      fetch("/api/incidents"),
      fetch("/api/settings"),
      fetch("/api/insights"),
    ]);
    allIncidents = await incidentsRes.json();
    settings = await settingsRes.json();
    const fetchedInsights: SecurityInsights = await insightsRes.json();
    const bankHandoff = readBankIncidentHandoff();
    insights = fetchedInsights;
    if (bankHandoff) mergeBankHandoff(bankHandoff, fetchedInsights);
    renderStatus();
    render();
    if (focusBankHandoff) {
      requireEl<HTMLElement>("incidents").scrollIntoView({ block: "start" });
      focusBankHandoff = false;
    }
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

  honeypotToggle.addEventListener("change", async () => {
    settings = await (await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ honeypotArmed: honeypotToggle.checked }),
    })).json();
    renderStatus();
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

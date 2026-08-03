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
import { buildDecisionGraphSeries, decisionGraphLabel } from "./decision-graph.ts";

const REFRESH_INTERVAL_MS = 5000;
const SVG_NAMESPACE = "http://www.w3.org/2000/svg";

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
  const decisionGraph = requireEl<SVGSVGElement>("decision-graph");
  const decisionGraphEmpty = requireEl<HTMLElement>("decision-graph-empty");
  const decisionGraphCount = requireEl<HTMLElement>("decision-graph-count");
  const decisionGraphCurrent = requireEl<HTMLElement>("decision-graph-current");
  const decisionGraphRisk = requireEl<HTMLElement>("decision-graph-risk");
  const decisionGraphTime = requireEl<HTMLElement>("decision-graph-time");
  const decisionGraphLatest = requireEl<HTMLElement>("decision-graph-latest");

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

  function createSvgElement(tag: string, attributes: Record<string, string | number>): SVGElement {
    const element = document.createElementNS(SVG_NAMESPACE, tag);
    for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, String(value));
    return element;
  }

  function appendSvgText(text: string, attributes: Record<string, string | number>): void {
    const label = createSvgElement("text", attributes);
    label.textContent = text;
    decisionGraph.appendChild(label);
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

  function renderDecisionGraph(): void {
    const points = buildDecisionGraphSeries(allIncidents);
    const width = 960;
    const height = 250;
    const left = 52;
    const right = 22;
    const top = 16;
    const bottom = 35;
    const plotWidth = width - left - right;
    const plotHeight = height - top - bottom;
    const scoreY = (score: number): number => top + ((100 - score) / 100) * plotHeight;
    const pointX = (index: number): number =>
      points.length === 1 ? left + plotWidth / 2 : left + (index / (points.length - 1)) * plotWidth;

    decisionGraph.replaceChildren();
    decisionGraphEmpty.hidden = points.length !== 0;
    decisionGraphCount.textContent = `${points.length} decision${points.length === 1 ? "" : "s"} plotted`;

    const zones = [
      { high: 100, low: 70, fill: "#ef3038", opacity: 0.055, label: "HIGH · 70+" },
      { high: 70, low: 40, fill: "#f4c84b", opacity: 0.04, label: "WARN · 40–69" },
      { high: 40, low: 0, fill: "#4bd59b", opacity: 0.025, label: "LOW · 0–39" },
    ];
    for (const zone of zones) {
      decisionGraph.appendChild(createSvgElement("rect", {
        x: left,
        y: scoreY(zone.high),
        width: plotWidth,
        height: scoreY(zone.low) - scoreY(zone.high),
        fill: zone.fill,
        opacity: zone.opacity,
      }));
      appendSvgText(zone.label, {
        x: width - right - 7,
        y: (scoreY(zone.high) + scoreY(zone.low)) / 2 + 3,
        class: "decision-zone-label",
        "text-anchor": "end",
      });
    }

    for (const score of [100, 70, 40, 0]) {
      const y = scoreY(score);
      decisionGraph.appendChild(createSvgElement("line", {
        x1: left,
        y1: y,
        x2: width - right,
        y2: y,
        class: `decision-grid-line${score === 70 || score === 40 ? " threshold" : ""}`,
      }));
      appendSvgText(String(score), { x: left - 12, y: y + 3, class: "decision-axis-label", "text-anchor": "end" });
    }

    if (points.length === 0) {
      decisionGraph.setAttribute("aria-label", "Live decision graph awaiting security events");
      decisionGraphCurrent.className = "decision-current-value";
      decisionGraphCurrent.textContent = "Awaiting data";
      decisionGraphRisk.textContent = "0 / 100";
      decisionGraphTime.textContent = "—";
      decisionGraphLatest.textContent = "New incident decisions will appear here automatically.";
      return;
    }

    const coordinates = points.map((point, index) => ({ x: pointX(index), y: scoreY(point.score), point }));
    if (coordinates.length > 1) {
      const linePath = coordinates.map(({ x, y }, index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
      const areaPath = `${linePath} L${coordinates.at(-1)!.x.toFixed(1)} ${scoreY(0).toFixed(1)} L${coordinates[0]!.x.toFixed(1)} ${scoreY(0).toFixed(1)} Z`;
      decisionGraph.appendChild(createSvgElement("path", { d: areaPath, class: "decision-area" }));
      decisionGraph.appendChild(createSvgElement("path", { d: linePath, class: "decision-line" }));
    }

    const decisionColors: Record<Decision, string> = {
      allow: "#4bd59b",
      warn: "#f4c84b",
      blocked: "#ef3038",
      detected_not_blocked: "#d7a6aa",
    };
    for (const [index, coordinate] of coordinates.entries()) {
      const isLatest = index === coordinates.length - 1;
      if (isLatest) {
        decisionGraph.appendChild(createSvgElement("circle", {
          cx: coordinate.x,
          cy: coordinate.y,
          r: 10,
          class: "decision-latest-ring",
          stroke: decisionColors[coordinate.point.decision],
        }));
      }
      const marker = createSvgElement("circle", {
        cx: coordinate.x,
        cy: coordinate.y,
        r: isLatest ? 6 : 4.5,
        fill: decisionColors[coordinate.point.decision],
        class: `decision-point decision-${coordinate.point.decision}`,
        tabindex: 0,
        role: "button",
        "aria-label": `${decisionGraphLabel(coordinate.point.decision)}, risk ${coordinate.point.score}: ${coordinate.point.summary}`,
      });
      const title = createSvgElement("title", {});
      title.textContent = `${formatTime(coordinate.point.timestamp)} · ${decisionGraphLabel(coordinate.point.decision)} · risk ${coordinate.point.score}\n${coordinate.point.summary}`;
      marker.appendChild(title);
      marker.addEventListener("click", () => openIncident(coordinate.point.id));
      marker.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") openIncident(coordinate.point.id);
      });
      decisionGraph.appendChild(marker);
    }

    const first = points[0]!;
    const latest = points.at(-1)!;
    const timeLabel = (timestamp: string): string => new Date(timestamp).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    appendSvgText(timeLabel(first.timestamp), { x: pointX(0), y: height - 11, class: "decision-axis-label", "text-anchor": points.length === 1 ? "middle" : "start" });
    if (points.length > 1) {
      appendSvgText(timeLabel(latest.timestamp), { x: pointX(points.length - 1), y: height - 11, class: "decision-axis-label", "text-anchor": "end" });
    }

    decisionGraph.setAttribute(
      "aria-label",
      `Live graph of ${points.length} decisions. Latest: ${decisionGraphLabel(latest.decision)}, risk ${latest.score}.`,
    );
    decisionGraphCurrent.className = `decision-current-value decision-${latest.decision}`;
    decisionGraphCurrent.textContent = decisionGraphLabel(latest.decision);
    decisionGraphRisk.textContent = `${latest.score} / 100`;
    decisionGraphTime.textContent = formatTime(latest.timestamp);
    decisionGraphLatest.textContent = latest.summary;
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
      aegisStatus.textContent = online ? "Online · ready" : "Offline · Overseer active";
      aegisIndicator.className = `pulse-dot ${online ? "online" : "offline"}`;
    } catch {
      aegisStatus.textContent = "Offline · Overseer active";
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
    renderDecisionGraph();
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
    insights = await insightsRes.json();
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

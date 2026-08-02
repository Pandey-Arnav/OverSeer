import type {
  AnalyticsMetric,
  AttackHistoryBucket,
  EventCorrelation,
  FrameworkMapping,
  Incident,
  SecurityAlert,
  SecurityInsights,
  Severity,
} from "../shared/types.ts";

const ACTIVE_RISK_WINDOW_MS = 15 * 60 * 1000;
const ALERT_WINDOW_MS = 24 * 60 * 60 * 1000;
const CORRELATION_WINDOW_MS = 10 * 60 * 1000;

const MITRE = {
  REMOVABLE_MEDIA: {
    framework: "MITRE ATT&CK",
    id: "T1091",
    name: "Replication Through Removable Media",
    url: "https://attack.mitre.org/techniques/T1091/",
  },
  HARDWARE_ADDITIONS: {
    framework: "MITRE ATT&CK",
    id: "T1200",
    name: "Hardware Additions",
    url: "https://attack.mitre.org/techniques/T1200/",
  },
  DATA_MANIPULATION: {
    framework: "MITRE ATT&CK",
    id: "T1565.002",
    name: "Transmitted Data Manipulation",
    url: "https://attack.mitre.org/techniques/T1565/002/",
  },
  JAVASCRIPT: {
    framework: "MITRE ATT&CK",
    id: "T1059.007",
    name: "Command and Scripting Interpreter: JavaScript/JScript",
    url: "https://attack.mitre.org/techniques/T1059/007/",
  },
  NETWORK_SCANNING: {
    framework: "MITRE ATT&CK",
    id: "T1046",
    name: "Network Service Scanning",
    url: "https://attack.mitre.org/techniques/T1046/",
  },
  NON_STANDARD_PORT: {
    framework: "MITRE ATT&CK",
    id: "T1571",
    name: "Non-Standard Port",
    url: "https://attack.mitre.org/techniques/T1571/",
  },
} as const satisfies Record<string, FrameworkMapping>;

const OWASP = {
  INJECTION: {
    framework: "OWASP Top 10",
    id: "A05:2025",
    name: "Injection",
    url: "https://owasp.org/Top10/2025/A05_2025-Injection/",
  },
  INTEGRITY: {
    framework: "OWASP Top 10",
    id: "A08:2025",
    name: "Software or Data Integrity Failures",
    url: "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
  },
} as const satisfies Record<string, FrameworkMapping>;

function riskLevel(score: number): SecurityInsights["liveRiskLevel"] {
  if (score >= 70) return "critical";
  if (score >= 40) return "elevated";
  if (score >= 20) return "guarded";
  return "normal";
}

function scoreSeverity(score: number): Severity {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function uniqueMappings(mappings: FrameworkMapping[]): FrameworkMapping[] {
  return mappings.filter((mapping, index) => mappings.findIndex((item) => item.framework === mapping.framework && item.id === mapping.id) === index);
}

export function mapIncidentToFrameworks(incident: Incident): FrameworkMapping[] {
  const mappings: FrameworkMapping[] = [];
  const ruleIds = new Set(incident.reasons.map((reason) => reason.ruleId));

  if (incident.category === "usb_storage_device") mappings.push(MITRE.REMOVABLE_MEDIA);
  if (["usb_hid_device", "usb_network_device", "usb_other_device", "usb_badusb_keystroke"].includes(incident.category)) {
    mappings.push(MITRE.HARDWARE_ADDITIONS);
  }
  if (incident.category === "transaction_tampering") mappings.push(MITRE.DATA_MANIPULATION, OWASP.INTEGRITY);
  if (incident.category === "suspicious_script") mappings.push(MITRE.JAVASCRIPT, OWASP.INJECTION, OWASP.INTEGRITY);
  if (ruleIds.has("multiple-new-remote-hosts")) mappings.push(MITRE.NETWORK_SCANNING);
  if (ruleIds.has("suspicious-port")) mappings.push(MITRE.NON_STANDARD_PORT);

  return uniqueMappings(mappings);
}

function recommendationFor(incident: Incident): string {
  if (incident.remediation?.available && !incident.remediation.applied) {
    return incident.remediation.action === "eject_device"
      ? "Review the device and eject it from the incident details if it is not trusted."
      : "Review the process and terminate it from the incident details if it is not trusted.";
  }
  if (incident.category === "transaction_tampering") return "Keep the transaction frozen and verify the recipient and amount through a trusted channel.";
  if (incident.category.startsWith("usb_")) return "Disconnect unrecognized hardware and run a full Microsoft Defender scan.";
  if (incident.category === "suspicious_script") return "Close the affected page and inspect the flagged script source before continuing.";
  return incident.score >= 70
    ? "Investigate the process, destination, and triggered rules immediately."
    : "Confirm this activity is expected and monitor for repeated signals.";
}

function buildAlerts(incidents: Incident[], now: number): SecurityAlert[] {
  return incidents
    .filter((incident) => now - Date.parse(incident.timestamp) <= ALERT_WINDOW_MS)
    .filter((incident) => incident.score >= 40 || incident.decision === "blocked" || incident.decision === "detected_not_blocked")
    .sort((a, b) => b.score - a.score || Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .slice(0, 8)
    .map((incident) => ({
      incidentId: incident.id,
      timestamp: incident.timestamp,
      title: incident.summary,
      severity: incident.severity,
      score: incident.score,
      decision: incident.decision,
      recommendation: recommendationFor(incident),
    }));
}

function correlationKeys(incident: Incident): Array<{ key: string; label: string }> {
  const keys: Array<{ key: string; label: string }> = [];
  if (incident.processName) keys.push({ key: `process:${incident.processName.toLowerCase()}`, label: `process ${incident.processName}` });
  if (incident.remoteAddress) keys.push({ key: `remote:${incident.remoteAddress}`, label: `destination ${incident.remoteAddress}` });
  if (incident.deviceName) keys.push({ key: `device:${incident.deviceName.toLowerCase()}`, label: `device ${incident.deviceName}` });
  if (incident.pageOrigin) keys.push({ key: `origin:${incident.pageOrigin.toLowerCase()}`, label: `origin ${incident.pageOrigin}` });
  return keys;
}

function buildCorrelations(incidents: Incident[]): EventCorrelation[] {
  const groups = new Map<string, { label: string; incidents: Incident[] }>();
  for (const incident of incidents) {
    for (const { key, label } of correlationKeys(incident)) {
      const group = groups.get(key) ?? { label, incidents: [] };
      group.incidents.push(incident);
      groups.set(key, group);
    }
  }

  const correlations: EventCorrelation[] = [];
  const seenIncidentSets = new Set<string>();
  for (const [key, group] of groups) {
    const ordered = [...group.incidents].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    let cluster: Incident[] = [];
    const flush = () => {
      if (cluster.length < 2) return;
      const incidentIds = cluster.map((incident) => incident.id);
      const setKey = [...incidentIds].sort().join("|");
      if (seenIncidentSets.has(setKey)) return;
      seenIncidentSets.add(setKey);
      const score = Math.min(100, Math.max(...cluster.map((incident) => incident.score)) + Math.min(15, (cluster.length - 1) * 5));
      correlations.push({
        id: `${key}:${cluster[0]!.id}`,
        title: `Repeated activity linked to ${group.label}`,
        description: `${cluster.length} events appeared within a 10-minute window. Review them together as one possible attack sequence.`,
        signal: group.label,
        incidentIds,
        firstSeen: cluster[0]!.timestamp,
        lastSeen: cluster[cluster.length - 1]!.timestamp,
        score,
        severity: scoreSeverity(score),
      });
    };

    for (const incident of ordered) {
      const previous = cluster[cluster.length - 1];
      if (previous && Date.parse(incident.timestamp) - Date.parse(previous.timestamp) > CORRELATION_WINDOW_MS) {
        flush();
        cluster = [];
      }
      cluster.push(incident);
    }
    flush();
  }

  return correlations.sort((a, b) => b.score - a.score || Date.parse(b.lastSeen) - Date.parse(a.lastSeen)).slice(0, 6);
}

function metric(items: Incident[], label: string): AnalyticsMetric {
  return {
    label,
    count: items.length,
    averageScore: items.length ? Math.round(items.reduce((sum, incident) => sum + incident.score, 0) / items.length) : 0,
  };
}

function groupMetrics(incidents: Incident[], labelFor: (incident: Incident) => string): AnalyticsMetric[] {
  const groups = new Map<string, Incident[]>();
  for (const incident of incidents) {
    const label = labelFor(incident);
    groups.set(label, [...(groups.get(label) ?? []), incident]);
  }
  return [...groups.entries()]
    .map(([label, items]) => metric(items, label))
    .sort((a, b) => b.count - a.count || b.averageScore - a.averageScore);
}

function buildHistory(incidents: Incident[]): AttackHistoryBucket[] {
  const attacks = incidents.filter((incident) => incident.score >= 40);
  const dates = new Map<string, Incident[]>();
  for (const incident of attacks) {
    const date = incident.timestamp.slice(0, 10);
    dates.set(date, [...(dates.get(date) ?? []), incident]);
  }
  return [...dates.entries()]
    .map(([date, items]) => ({
      date,
      total: items.length,
      high: items.filter((incident) => incident.severity === "high").length,
      medium: items.filter((incident) => incident.severity === "medium").length,
      peakScore: Math.max(...items.map((incident) => incident.score)),
    }))
    .sort((a, b) => b.date.localeCompare(a.date))
    .slice(0, 14);
}

export function buildSecurityInsights(incidents: Incident[], now = Date.now()): SecurityInsights {
  const active = incidents.filter((incident) => {
    const timestamp = Date.parse(incident.timestamp);
    return Number.isFinite(timestamp) && now - timestamp <= ACTIVE_RISK_WINDOW_MS && timestamp <= now;
  });
  const liveRiskScore = active.length
    ? Math.min(
        100,
        Math.round(
          Math.max(...active.map((incident) => incident.score)) * 0.7 +
            (active.reduce((sum, incident) => sum + incident.score, 0) / active.length) * 0.3 +
            Math.min(15, (active.length - 1) * 3),
        ),
      )
    : 0;
  const mappingsByIncident = Object.fromEntries(incidents.map((incident) => [incident.id, mapIncidentToFrameworks(incident)]));
  const mappingGroups = new Map<string, Incident[]>();
  for (const incident of incidents) {
    for (const mapping of mappingsByIncident[incident.id] ?? []) {
      const key = `${mapping.framework} · ${mapping.id}`;
      mappingGroups.set(key, [...(mappingGroups.get(key) ?? []), incident]);
    }
  }
  const alerts = buildAlerts(incidents, now);

  return {
    generatedAt: new Date(now).toISOString(),
    liveRiskScore,
    liveRiskLevel: riskLevel(liveRiskScore),
    activeAlertCount: alerts.length,
    alerts,
    correlations: buildCorrelations(incidents),
    mappingsByIncident,
    history: buildHistory(incidents),
    analytics: {
      categories: groupMetrics(incidents, (incident) => incident.category.replace(/_/g, " ")),
      severities: groupMetrics(incidents, (incident) => incident.severity),
      decisions: groupMetrics(incidents, (incident) => incident.decision.replace(/_/g, " ")),
      mappings: [...mappingGroups.entries()]
        .map(([label, items]) => metric(items, label))
        .sort((a, b) => b.count - a.count || b.averageScore - a.averageScore),
    },
  };
}

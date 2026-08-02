/**
 * Sentinel Agent — shared types.
 *
 * A background daemon that watches OS-level signals (network connections,
 * USB device attachment) instead of in-browser behavior. Same
 * transparent-scoring philosophy as the original browser-extension
 * prototype, applied to a different observation surface.
 */

export type EventCategory =
  | "network_connection"
  | "usb_storage_device"
  | "usb_hid_device"
  | "usb_network_device"
  | "usb_other_device"
  | "usb_badusb_keystroke"
  | "transaction_tampering"
  | "suspicious_script";

export type Severity = "low" | "medium" | "high";

/**
 * "blocked" means one of two things depending on category:
 *   - network_connection / usb_storage_device: "crossed the action
 *     threshold AND a safe manual remediation exists" (terminate the
 *     process / eject the device) — the dashboard shows a button, but
 *     nothing happens until you click it. Killing a process or ejecting
 *     a drive is much higher-stakes than blocking one HTTP request, so
 *     there's no auto-block tier for these.
 *   - transaction_tampering: "the extension already froze this
 *     transaction client-side" — a completed fact, not an offered
 *     action. This is the one category where prevention already
 *     happened by the time the incident is logged, because holding a
 *     form submission for a synchronous decision is safe and cheap in a
 *     way killing a process or ejecting a drive is not.
 */
export type Decision = "allow" | "warn" | "blocked" | "detected_not_blocked";

export interface RuleFinding {
  ruleId: string;
  label: string;
  points: number;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  user: string;
  execPath: string | null;
  signed: boolean | null; // null = could not be determined (e.g. process exited before we could check)
  signedAdhoc: boolean;
  suspiciousPath: boolean;
}

/** The sanitized metadata for one observed OS-level action, before scoring. */
export interface SentinelEvent {
  category: EventCategory;
  timestamp: number;

  // network_connection fields
  process?: ProcessInfo;
  remoteAddress?: string;
  remotePort?: number;
  localPort?: number;
  connectionState?: "ESTABLISHED" | "LISTEN";
  isNewListeningPort?: boolean;
  distinctRemoteHostsInWindow?: number;

  // usb_* fields
  deviceName?: string;
  vendorId?: string;
  productId?: string;
  bsdName?: string | null; // for storage devices, used for eject
  defenderScanStatus?: "clean" | "threat_found" | "unavailable";
  defenderThreatCount?: number;

  // usb_badusb_keystroke fields — see monitors/keystroke-honeypot.ts
  keystrokeStats?: { meanIntervalMs: number; stdDevMs: number; keyCount: number };

  // transaction_tampering fields — reported by the browser extension
  pageOrigin?: string;
  pageUrl?: string;
  destinationUrl?: string;
  tamperedFieldNames?: string[];

  // suspicious_script fields — reported by the browser extension
  scriptOrigin?: string;
  scriptFindings?: string[];
}

/** Cross-event state a rule may use, when the caller has it available. */
export interface EvalContext {
  seenRemoteHosts?: Set<string>; // per-process "host:port we've seen before"
}

export type Rule = (event: SentinelEvent, context: EvalContext) => RuleFinding | null;

export interface RiskEvaluation {
  score: number;
  severity: Severity;
  decision: Decision;
  reasons: RuleFinding[];
}

/** The normalized, persisted incident. */
export interface Incident {
  id: string;
  timestamp: string;
  category: EventCategory;
  summary: string; // human-readable one-liner (process name + destination, or device name)
  processName: string | null;
  processPath: string | null;
  remoteAddress: string | null;
  remotePort: number | null;
  deviceName: string | null;
  pageOrigin: string | null;
  tamperedFieldNames: string[] | null;
  scriptFindings: string[] | null;
  score: number;
  severity: Severity;
  decision: Decision;
  reasons: RuleFinding[];
  explanation: AIExplanation | null;
  aegisReport: AegisReport | null;
  remediation: RemediationInfo | null;
  defenderScanStatus: "clean" | "threat_found" | "unavailable" | null;
  defenderThreatCount: number | null;
}

export interface AegisBranch {
  name: "ALLOW" | "WARN" | "BLOCK" | "CONTAIN";
  title: string;
  actionVariant: string;
  riskScore: number;
  utilityScore: number;
  valid: boolean;
  verdict: string;
  violations: Array<{ policyId: string; reason: string; severity: string }>;
}

export interface AegisReport {
  engine: "AEGIS_FORKGUARD";
  version: string;
  runId: string;
  sourceIncidentId: string;
  simulated: boolean;
  decision: {
    selectedBranch: "ALLOW" | "WARN" | "BLOCK" | "CONTAIN";
    status: string;
    confidence: number;
    summary: string;
  };
  branches: AegisBranch[];
  timeline: Array<{ seq: number; stage: string; details: string; timestamp: string }>;
  graph: {
    nodes: Array<{ id: string; kind: string; label: string; selected?: boolean }>;
    edges: Array<{ from: string; to: string; type: string }>;
  };
}

export interface RemediationInfo {
  available: boolean;
  action: "terminate_process" | "eject_device" | null;
  reason: string; // why available, or why not (e.g. "process is a critical system process")
  pid?: number;
  bsdName?: string;
  applied: boolean;
  appliedAt: string | null;
}

export interface AIExplanation {
  summary: string;
  technicalExplanation: string;
  recommendation: string;
}

export interface FrameworkMapping {
  framework: "MITRE ATT&CK" | "OWASP Top 10";
  id: string;
  name: string;
  url: string;
}

export interface SecurityAlert {
  incidentId: string;
  timestamp: string;
  title: string;
  severity: Severity;
  score: number;
  decision: Decision;
  recommendation: string;
}

export interface EventCorrelation {
  id: string;
  title: string;
  description: string;
  signal: string;
  incidentIds: string[];
  firstSeen: string;
  lastSeen: string;
  score: number;
  severity: Severity;
}

export interface AttackHistoryBucket {
  date: string;
  total: number;
  high: number;
  medium: number;
  peakScore: number;
}

export interface AnalyticsMetric {
  label: string;
  count: number;
  averageScore: number;
}

export interface SecurityInsights {
  generatedAt: string;
  liveRiskScore: number;
  liveRiskLevel: "normal" | "guarded" | "elevated" | "critical";
  activeAlertCount: number;
  alerts: SecurityAlert[];
  correlations: EventCorrelation[];
  mappingsByIncident: Record<string, FrameworkMapping[]>;
  history: AttackHistoryBucket[];
  analytics: {
    categories: AnalyticsMetric[];
    severities: AnalyticsMetric[];
    decisions: AnalyticsMetric[];
    mappings: AnalyticsMetric[];
  };
}

export interface Settings {
  protectionEnabled: boolean;
  aiExplanationsEnabled: boolean;
}

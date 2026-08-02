/**
 * Sentinel Agent — risk engine.
 *
 * Combines every rule in risk/rules.ts into a single score + decision,
 * and builds the normalized incident object. Side-effect-free and
 * synchronous (the async parts — process introspection, remediation
 * safety checks — happen in the monitors before this is called).
 */
import { DECISION, EVENT_CATEGORIES, REMEDIABLE_CATEGORIES, THRESHOLDS } from "../shared/constants.ts";
import { RULES } from "./rules.ts";
import type { Decision, EvalContext, EventCategory, Incident, RemediationInfo, RiskEvaluation, SentinelEvent } from "../shared/types.ts";

const VALID_CATEGORIES = new Set<EventCategory>(Object.values(EVENT_CATEGORIES));

function assertValidEvent(event: SentinelEvent): void {
  if (!event || typeof event !== "object") {
    throw new TypeError("Sentinel.evaluateRisk: event must be an object");
  }
  if (!VALID_CATEGORIES.has(event.category)) {
    throw new TypeError(`Sentinel.evaluateRisk: unknown event category "${event.category}"`);
  }
}

/**
 * Decides allow/warn/blocked/detected_not_blocked given a score + event
 * category + (for network events) whether a safe remediation target
 * exists. `blocked` means "crossed the action threshold AND a safe
 * manual remediation exists" — never that anything happened
 * automatically. See shared/types.ts Decision doc comment.
 */
export function decideAction(category: EventCategory, score: number, remediable: boolean): Decision {
  if (score >= THRESHOLDS.BLOCK) {
    const categoryIsRemediable = REMEDIABLE_CATEGORIES.has(category);
    return categoryIsRemediable && remediable ? DECISION.BLOCKED : DECISION.DETECTED_NOT_BLOCKED;
  }
  if (score >= THRESHOLDS.WARN) return DECISION.WARN;
  return DECISION.ALLOW;
}

export function evaluateRisk(event: SentinelEvent, context: EvalContext = {}, remediable = true): RiskEvaluation {
  assertValidEvent(event);

  const reasons = [];
  for (const rule of RULES) {
    const finding = rule(event, context);
    if (finding) reasons.push(finding);
  }

  const rawScore = reasons.reduce((sum, r) => sum + r.points, 0);
  const score = Math.max(0, Math.min(THRESHOLDS.MAX_SCORE, Math.round(rawScore)));
  const severity = score >= THRESHOLDS.BLOCK ? "high" : score >= THRESHOLDS.WARN ? "medium" : "low";
  const decision = decideAction(event.category, score, remediable);

  return { score, severity, decision, reasons };
}

function summarize(event: SentinelEvent): string {
  if (event.category === "network_connection") {
    const proc = event.process?.name ?? "unknown process";
    if (event.connectionState === "LISTEN") return `${proc} listening on port ${event.localPort}`;
    return `${proc} → ${event.remoteAddress}:${event.remotePort}`;
  }
  if (event.category === "transaction_tampering") {
    return `Transaction on ${event.pageOrigin ?? "unknown site"} — field(s) tampered: ${(event.tamperedFieldNames ?? []).join(", ")}`;
  }
  if (event.category === "suspicious_script") {
    return `Suspicious script on ${event.scriptOrigin ?? event.pageOrigin ?? "unknown site"}`;
  }
  if (event.category === "usb_badusb_keystroke") {
    const stats = event.keystrokeStats;
    return stats ? `Honeypot input: ${stats.keyCount} keys, ~${stats.meanIntervalMs.toFixed(1)}ms apart (σ=${stats.stdDevMs.toFixed(1)}ms)` : "Honeypot keystroke pattern";
  }
  return event.deviceName ?? "USB device";
}

export function buildIncident(event: SentinelEvent, evaluation: RiskEvaluation, remediation: RemediationInfo | null, id: string, timestamp: string): Incident {
  return {
    id,
    timestamp,
    category: event.category,
    summary: summarize(event),
    processName: event.process?.name ?? null,
    processPath: event.process?.execPath ?? null,
    remoteAddress: event.remoteAddress ?? null,
    remotePort: event.remotePort ?? null,
    deviceName: event.deviceName ?? null,
    pageOrigin: event.pageOrigin ?? null,
    tamperedFieldNames: event.tamperedFieldNames ?? null,
    scriptFindings: event.scriptFindings ?? null,
    score: evaluation.score,
    severity: evaluation.severity,
    decision: evaluation.decision,
    reasons: evaluation.reasons,
    explanation: null,
    remediation,
  };
}

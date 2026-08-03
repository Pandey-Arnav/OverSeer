import type { Decision, EventCategory, Incident, Severity } from "../shared/types.ts";

export const DECISION_GRAPH_EVENT_LIMIT = 24;

export interface DecisionGraphPoint {
  id: string;
  timestamp: string;
  score: number;
  decision: Decision;
  category: EventCategory;
  severity: Severity;
  reasonCount: number;
  summary: string;
}

export interface DecisionGraphSummary {
  averageRisk: number;
  peakRisk: number;
  escalatedCount: number;
  latestDelta: number;
  counts: Record<Decision, number>;
}

export function buildDecisionGraphSeries(
  incidents: Incident[],
  limit = DECISION_GRAPH_EVENT_LIMIT,
): DecisionGraphPoint[] {
  const boundedLimit = Math.max(1, Math.floor(limit));
  return [...incidents]
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
    .slice(-boundedLimit)
    .map((incident) => ({
      id: incident.id,
      timestamp: incident.timestamp,
      score: Math.max(0, Math.min(100, incident.score)),
      decision: incident.decision,
      category: incident.category,
      severity: incident.severity,
      reasonCount: incident.reasons.length,
      summary: incident.summary,
    }));
}

export function summarizeDecisionGraph(points: DecisionGraphPoint[]): DecisionGraphSummary {
  const counts: Record<Decision, number> = { allow: 0, warn: 0, blocked: 0, detected_not_blocked: 0 };
  for (const point of points) counts[point.decision] += 1;
  const latest = points.at(-1);
  const previous = points.at(-2);
  return {
    averageRisk: points.length === 0 ? 0 : Math.round(points.reduce((sum, point) => sum + point.score, 0) / points.length),
    peakRisk: points.length === 0 ? 0 : Math.max(...points.map((point) => point.score)),
    escalatedCount: points.filter((point) => point.decision !== "allow").length,
    latestDelta: latest && previous ? latest.score - previous.score : 0,
    counts,
  };
}

export function decisionGraphLabel(decision: Decision): string {
  if (decision === "blocked") return "Action available";
  if (decision === "detected_not_blocked") return "Detected only";
  if (decision === "warn") return "Warn";
  return "Allow";
}

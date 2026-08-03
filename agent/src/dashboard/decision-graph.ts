import type { Decision, Incident } from "../shared/types.ts";

export const DECISION_GRAPH_EVENT_LIMIT = 24;

export interface DecisionGraphPoint {
  id: string;
  timestamp: string;
  score: number;
  decision: Decision;
  summary: string;
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
      summary: incident.summary,
    }));
}

export function decisionGraphLabel(decision: Decision): string {
  if (decision === "blocked") return "Action available";
  if (decision === "detected_not_blocked") return "Detected only";
  if (decision === "warn") return "Warn";
  return "Allow";
}

import assert from "node:assert/strict";
import test from "node:test";
import { buildDecisionGraphSeries, decisionGraphLabel } from "./decision-graph.ts";
import type { Decision, Incident } from "../shared/types.ts";

function incident(id: string, timestamp: string, score: number, decision: Decision): Incident {
  return {
    id,
    timestamp,
    category: "network_connection",
    summary: `Incident ${id}`,
    processName: null,
    processPath: null,
    remoteAddress: null,
    remotePort: null,
    deviceName: null,
    pageOrigin: null,
    tamperedFieldNames: null,
    scriptFindings: null,
    honeypotCommand: null,
    score,
    severity: score >= 70 ? "high" : score >= 40 ? "medium" : "low",
    decision,
    reasons: [],
    explanation: null,
    aegisReport: null,
    remediation: null,
    defenderScanStatus: null,
    defenderThreatCount: null,
  };
}

test("decision graph sorts chronologically and keeps only the newest bounded events", () => {
  const series = buildDecisionGraphSeries([
    incident("newest", "2026-08-02T12:04:00.000Z", 90, "blocked"),
    incident("oldest", "2026-08-02T12:01:00.000Z", 10, "allow"),
    incident("middle", "2026-08-02T12:03:00.000Z", 55, "warn"),
  ], 2);

  assert.deepEqual(series.map((point) => point.id), ["middle", "newest"]);
});

test("decision graph clamps scores and exposes clear user-facing decision labels", () => {
  const series = buildDecisionGraphSeries([
    incident("low", "2026-08-02T12:01:00.000Z", -10, "allow"),
    incident("high", "2026-08-02T12:02:00.000Z", 120, "detected_not_blocked"),
  ]);

  assert.deepEqual(series.map((point) => point.score), [0, 100]);
  assert.equal(decisionGraphLabel("blocked"), "Action available");
  assert.equal(decisionGraphLabel("detected_not_blocked"), "Detected only");
});

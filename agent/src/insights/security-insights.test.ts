import assert from "node:assert/strict";
import test from "node:test";
import type { Incident } from "../shared/types.ts";
import { buildSecurityInsights, mapIncidentToFrameworks } from "./security-insights.ts";

const NOW = Date.parse("2026-08-02T20:00:00.000Z");

function incident(overrides: Partial<Incident> = {}): Incident {
  return {
    id: "incident-1",
    timestamp: new Date(NOW - 60_000).toISOString(),
    category: "network_connection",
    summary: "powershell.exe → 203.0.113.10:4444",
    processName: "powershell.exe",
    processPath: "C:\\Temp\\powershell.exe",
    remoteAddress: "203.0.113.10",
    remotePort: 4444,
    deviceName: null,
    pageOrigin: null,
    tamperedFieldNames: null,
    scriptFindings: null,
    honeypotCommand: null,
    score: 80,
    severity: "high",
    decision: "blocked",
    reasons: [{ ruleId: "suspicious-port", label: "Suspicious port", points: 40 }],
    explanation: null,
    aegisReport: null,
    remediation: null,
    defenderScanStatus: null,
    defenderThreatCount: null,
    ...overrides,
  };
}

test("maps supported events to current MITRE ATT&CK and OWASP categories", () => {
  const transaction = incident({
    category: "transaction_tampering",
    reasons: [{ ruleId: "transaction-field-tampering", label: "Transaction changed", points: 95 }],
  });
  const mappings = mapIncidentToFrameworks(transaction);
  assert.ok(mappings.some((mapping) => mapping.id === "T1565.002"));
  assert.ok(mappings.some((mapping) => mapping.id === "A08:2025"));

  const script = incident({ category: "suspicious_script", reasons: [] });
  assert.ok(mapIncidentToFrameworks(script).some((mapping) => mapping.id === "A05:2025"));
});

test("live risk score uses only incidents from the active 15-minute window", () => {
  const recent = incident({ id: "recent", score: 80, timestamp: new Date(NOW - 60_000).toISOString() });
  const old = incident({ id: "old", score: 100, timestamp: new Date(NOW - 20 * 60_000).toISOString() });
  const insights = buildSecurityInsights([recent, old], NOW);
  assert.equal(insights.liveRiskScore, 80);
  assert.equal(insights.liveRiskLevel, "critical");
});

test("correlates repeated events sharing an entity inside ten minutes", () => {
  const first = incident({ id: "first", timestamp: new Date(NOW - 5 * 60_000).toISOString() });
  const second = incident({ id: "second", timestamp: new Date(NOW - 60_000).toISOString(), remoteAddress: "198.51.100.8" });
  const insights = buildSecurityInsights([first, second], NOW);
  assert.equal(insights.correlations.length, 1);
  assert.deepEqual(insights.correlations[0]?.incidentIds, ["first", "second"]);
  assert.match(insights.correlations[0]?.signal ?? "", /powershell\.exe/);
});

test("builds active alerts, framework analytics, and attack history", () => {
  const high = incident({ id: "high" });
  const low = incident({ id: "low", score: 10, severity: "low", decision: "allow", reasons: [] });
  const insights = buildSecurityInsights([high, low], NOW);
  assert.equal(insights.activeAlertCount, 1);
  assert.equal(insights.history[0]?.total, 1);
  assert.ok(insights.analytics.mappings.some((mapping) => mapping.label.includes("T1571")));
});

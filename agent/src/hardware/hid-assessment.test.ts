import test from "node:test";
import assert from "node:assert/strict";
import { createHardwareAssessment, strongerHardwareAssessment } from "./hid-assessment.ts";

test("hardware assessment preserves an evidence-backed harmful verdict", () => {
  const assessment = createHardwareAssessment(
    "harmful",
    "Malicious command intent was detected and contained.",
    ["credential exfiltration", "new USB HID"],
    "high",
    new Date("2026-08-02T12:00:00.000Z")
  );

  assert.deepEqual(assessment, {
    verdict: "harmful",
    confidence: "high",
    reason: "Malicious command intent was detected and contained.",
    evidence: ["credential exfiltration", "new USB HID"],
    assessedAt: "2026-08-02T12:00:00.000Z",
  });
});

test("no-harm verdict is explicitly observational rather than a safety guarantee", () => {
  const assessment = createHardwareAssessment(
    "no_harmful_behavior_observed",
    "No harmful behavior was observed during the protected window.",
    ["observation window completed"],
    "medium"
  );

  assert.equal(assessment.verdict, "no_harmful_behavior_observed");
  assert.match(assessment.reason, /observed/i);
  assert.notEqual(assessment.reason.toLowerCase(), "safe");
});

test("a harmless observation cannot downgrade a suspicious verdict", () => {
  const suspicious = createHardwareAssessment("suspicious", "shell appeared", ["cmd.exe"], "medium");
  const harmless = createHardwareAssessment("no_harmful_behavior_observed", "nothing else observed", [], "medium");
  assert.equal(strongerHardwareAssessment(suspicious, harmless), suspicious);
});

test("harmful evidence upgrades every lower assessment", () => {
  const observing = createHardwareAssessment("observing", "watching", [], "low");
  const harmful = createHardwareAssessment("harmful", "malicious intent", ["credential theft"], "high");
  assert.equal(strongerHardwareAssessment(observing, harmful), harmful);
});

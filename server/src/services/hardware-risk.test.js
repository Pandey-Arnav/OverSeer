"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { evaluateHardwareRisk } = require("./hardware-risk");

function report(overrides = {}) {
  return {
    inventory: {
      totalFiles: 5,
      executableCount: 0,
      scriptCount: 0,
      shortcutCount: 0,
      archiveCount: 0,
      autorunPresent: false,
      truncated: false,
      ...(overrides.inventory || {}),
    },
    defender: {
      available: true,
      completed: true,
      threatCount: 0,
      ...(overrides.defender || {}),
    },
  };
}

test("allows a completed clean USB scan", () => {
  assert.deepEqual(evaluateHardwareRisk(report()), { score: 0, severity: "low", decision: "allow", reasons: [] });
});

test("warns when Microsoft Defender cannot complete the scan", () => {
  const result = evaluateHardwareRisk(report({ defender: { available: false, completed: false } }));
  assert.equal(result.score, 40);
  assert.equal(result.decision, "warn");
});

test("selects honest containment when Defender reports a threat", () => {
  const result = evaluateHardwareRisk(report({ defender: { threatCount: 1 } }));
  assert.equal(result.score, 100);
  assert.equal(result.severity, "high");
  assert.equal(result.decision, "detected_not_blocked");
});

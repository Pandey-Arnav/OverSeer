import test from "node:test";
import assert from "node:assert/strict";
import { calculateRisk, riskLevel } from "./RiskEngine.js";

test("protected transaction changes cross the freeze threshold", () => {
  const result = calculateRisk(["protectedFieldModified", "paymentFormModified"]);
  assert.equal(result.fraudRisk, 75);
  assert.equal(riskLevel(result.fraudRisk), "critical");
  assert.deepEqual(result.detectedRules.map((rule) => rule.id), [
    "protected-field-modified",
    "payment-form-modified",
  ]);
});

test("script and iframe findings accumulate without exceeding 100", () => {
  const result = calculateRisk(["dynamicScriptInjection", "hiddenIframe", "evalDetected", "unknownScriptSource"]);
  assert.equal(result.fraudRisk, 100);
});

test("unknown findings do not affect transaction risk", () => {
  assert.deepEqual(calculateRisk(["unrelated-monitor-signal"]), { fraudRisk: 0, detectedRules: [] });
});

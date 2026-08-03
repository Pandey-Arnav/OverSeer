import test from "node:test";
import assert from "node:assert/strict";
import { createIncident } from "./Incident.js";

test("incident output follows the browser-monitor to risk-engine contract", () => {
  const incident = createIncident({
    attackType: "transaction-tampering",
    page: "https://bank.example/transfer",
    fraudRisk: 75,
    modifiedFields: ["recipient"],
    detectedRules: [{ id: "protected-field-modified", label: "Protected transaction field modified", points: 50 }],
    actionTaken: "transaction-frozen-values-restored",
    originalTransaction: { recipient: "Alice" },
    modifiedTransaction: { recipient: "Mallory" },
  });

  assert.match(incident.id, /^[0-9a-f-]{36}$/i);
  assert.equal(incident.attackType, "transaction-tampering");
  assert.equal(incident.fraudRisk, 75);
  assert.deepEqual(incident.modifiedFields, ["recipient"]);
  assert.equal(incident.actionTaken, "transaction-frozen-values-restored");
});

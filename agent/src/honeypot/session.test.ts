import test from "node:test";
import assert from "node:assert/strict";
import { assessHoneypotBehavior } from "./session.ts";

const now = new Date("2026-08-02T12:00:00.000Z");

test("malicious command intent produces a harmful hardware verdict", () => {
  const assessment = assessHoneypotBehavior(false, { malicious: true, findings: ["credential theft"] }, false, now);
  assert.equal(assessment.verdict, "harmful");
  assert.equal(assessment.confidence, "high");
  assert.deepEqual(assessment.evidence, ["credential theft"]);
});

test("scripted timing with harmless intent is suspicious, not mislabeled harmful", () => {
  const assessment = assessHoneypotBehavior(true, { malicious: false, findings: [] }, false, now);
  assert.equal(assessment.verdict, "suspicious");
  assert.match(assessment.reason, /not classified as harmful/i);
});

test("human-like harmless input reports only that no harm was observed", () => {
  const assessment = assessHoneypotBehavior(false, { malicious: false, findings: [] }, false, now);
  assert.equal(assessment.verdict, "no_harmful_behavior_observed");
  assert.match(assessment.reason, /observed input/i);
});

test("catastrophic safety pattern always produces a harmful verdict", () => {
  const assessment = assessHoneypotBehavior(true, { malicious: false, findings: [] }, true, now);
  assert.equal(assessment.verdict, "harmful");
  assert.ok(assessment.evidence.length > 0);
});

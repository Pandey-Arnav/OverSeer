"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { validateForkGuardRequest, sanitizedPayload } = require("./forkguard");

function validBody() {
  return {
    incidentId: "incident-1",
    eventType: "form_submission",
    pageOrigin: "https://safe.example",
    destinationOrigin: "https://unknown.example",
    score: 95,
    decision: "blocked",
    reasons: [
      {
        ruleId: "cross-origin-password-form",
        label: "Password form targeted another origin",
        points: 50,
      },
    ],
  };
}

test("accepts sanitized Sentinel incident metadata", () => {
  assert.equal(validateForkGuardRequest(validBody()), null);
});

test("rejects sensitive fields", () => {
  const body = { ...validBody(), password: "must-never-leave-extension" };
  assert.match(validateForkGuardRequest(body), /must not include/);
});

test("derives technical blockability on the server", () => {
  const formPayload = sanitizedPayload(validBody());
  assert.equal(formPayload.blockable, true);

  const redirectPayload = sanitizedPayload({
    ...validBody(),
    eventType: "redirect",
    decision: "detected_not_blocked",
  });
  assert.equal(redirectPayload.blockable, false);
});

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

// Order matters: each file attaches to the same globalThis.Sentinel object.
require("../shared/constants.js");
require("../shared/utils.js");
require("../risk/rules.js");
const { evaluateRisk, buildIncident, decideAction } = require("./engine.js");

const BASE_EVENT = {
  type: "fetch_request",
  pageUrl: "https://example.com/account",
  pageOrigin: "https://example.com",
  timestamp: Date.now(),
};

test("safe same-origin GET is allowed with score 0", () => {
  const result = evaluateRisk({
    ...BASE_EVENT,
    destinationUrl: "https://example.com/api/profile",
    method: "GET",
    payloadSize: 200,
  });
  assert.equal(result.score, 0);
  assert.equal(result.decision, "allow");
  assert.equal(result.reasons.length, 0);
});

test("cross-origin POST scores the cross-origin-request rule", () => {
  const result = evaluateRisk({
    ...BASE_EVENT,
    type: "fetch_request",
    destinationUrl: "https://tracker.test/collect",
    method: "POST",
    payloadSize: 200,
  });
  assert.ok(result.score >= 45);
  assert.ok(result.reasons.some((r) => r.ruleId === "cross-origin-request"));
});

test("large payload triggers the large-payload rule", () => {
  const result = evaluateRisk({
    ...BASE_EVENT,
    destinationUrl: "https://example.com/api/upload",
    payloadSize: 50000,
  });
  assert.ok(result.reasons.some((r) => r.ruleId === "large-payload"));
});

test("password form posting to another origin is high severity and blockable", () => {
  const result = evaluateRisk({
    type: "form_submission",
    pageUrl: "https://example.com/login",
    pageOrigin: "https://example.com",
    destinationUrl: "https://evil.test/harvest",
    hasPasswordField: true,
    timestamp: Date.now(),
  });
  assert.ok(result.score >= 70, `expected block-range score, got ${result.score}`);
  assert.equal(result.severity, "high");
  assert.equal(result.decision, "blocked");
  assert.ok(result.reasons.some((r) => r.ruleId === "cross-origin-password-form"));
});

test("raw IP destination triggers the raw-ip-destination rule", () => {
  const result = evaluateRisk({
    ...BASE_EVENT,
    destinationUrl: "http://203.0.113.42/collect",
  });
  assert.ok(result.reasons.some((r) => r.ruleId === "raw-ip-destination"));
});

test("multiple rules accumulate additively", () => {
  const result = evaluateRisk({
    ...BASE_EVENT,
    destinationUrl: "http://203.0.113.42/api/data",
    payloadSize: 50000,
  });
  const ruleIds = result.reasons.map((r) => r.ruleId).sort();
  assert.deepEqual(ruleIds, ["cross-origin-request", "large-payload", "raw-ip-destination"].sort());
  // 45 + 40 + 40 = 125, clamped to 100
  assert.equal(result.score, 100);
});

test("score clamps at 100 even with many stacked rules", () => {
  const result = evaluateRisk(
    {
      type: "form_submission",
      pageUrl: "https://example.com/login",
      pageOrigin: "https://example.com",
      destinationUrl: "http://203.0.113.42/collect",
      hasPasswordField: true,
      payloadSize: 50000,
      timestamp: 10_000,
    },
    { lastClickTimestamp: 9500 }
  );
  assert.equal(result.score, 100);
});

test("threshold boundaries map to the correct decision (allow/warn/block)", () => {
  assert.equal(decideAction("fetch_request", 0), "allow");
  assert.equal(decideAction("fetch_request", 39), "allow");
  assert.equal(decideAction("fetch_request", 40), "warn");
  assert.equal(decideAction("fetch_request", 69), "warn");
  assert.equal(decideAction("fetch_request", 70), "blocked");
  assert.equal(decideAction("fetch_request", 100), "blocked");
});

test("non-blockable event types are marked detected_not_blocked at block-level score", () => {
  // send_beacon alone can't reach 70 from rules (only +20), so combine with
  // cross-origin + raw IP to push it into block range while keeping the
  // event type itself non-blockable.
  const result = evaluateRisk({
    type: "send_beacon",
    pageUrl: "https://example.com/",
    pageOrigin: "https://example.com",
    destinationUrl: "http://203.0.113.42/collect",
    timestamp: Date.now(),
  });
  assert.ok(result.score >= 70, `expected block-range score, got ${result.score}`);
  assert.equal(result.decision, "detected_not_blocked");
});

test("redirect shortly after a click triggers redirect-after-click only with context", () => {
  const event = {
    type: "redirect",
    pageUrl: "https://example.com/",
    pageOrigin: "https://example.com",
    timestamp: 10_000,
  };
  const withoutContext = evaluateRisk(event);
  assert.equal(withoutContext.reasons.length, 0);

  const withContext = evaluateRisk(event, { lastClickTimestamp: 9800 });
  assert.ok(withContext.reasons.some((r) => r.ruleId === "redirect-after-click"));
});

test("unseen destination only fires when a seenDestinations set is provided", () => {
  const event = {
    ...BASE_EVENT,
    destinationUrl: "https://newhost.test/api",
  };
  const withoutContext = evaluateRisk(event);
  assert.equal(withoutContext.reasons.some((r) => r.ruleId === "unseen-destination"), false);

  const seen = new Set(["https://oldhost.test"]);
  const withContext = evaluateRisk(event, { seenDestinations: seen });
  assert.ok(withContext.reasons.some((r) => r.ruleId === "unseen-destination"));

  seen.add("https://newhost.test");
  const secondTime = evaluateRisk(event, { seenDestinations: seen });
  assert.equal(secondTime.reasons.some((r) => r.ruleId === "unseen-destination"), false);
});

test("missing optional fields do not throw and produce a low/zero score", () => {
  const result = evaluateRisk({
    type: "hidden_iframe",
    pageOrigin: "https://example.com",
    timestamp: Date.now(),
    // no pageUrl, no destinationUrl, no isHidden
  });
  assert.equal(result.score, 0);
  assert.equal(result.decision, "allow");
});

test("invalid event type throws instead of silently failing", () => {
  assert.throws(
    () =>
      evaluateRisk({
        type: "not_a_real_event_type",
        pageOrigin: "https://example.com",
      }),
    /unknown event type/i
  );
});

test("missing required pageOrigin throws instead of silently failing", () => {
  assert.throws(() => evaluateRisk({ type: "fetch_request" }), /pageOrigin/i);
});

test("buildIncident produces the documented data model and never carries sensitive fields", () => {
  const event = {
    type: "form_submission",
    pageUrl: "https://example.com/login",
    pageOrigin: "https://example.com",
    destinationUrl: "https://evil.test/harvest",
    hasPasswordField: true,
    method: "POST",
    payloadSize: 8200,
    tabId: 123,
    timestamp: Date.now(),
  };
  const evaluation = evaluateRisk(event);
  const incident = buildIncident(event, evaluation);

  assert.ok(incident.id);
  assert.ok(incident.timestamp);
  assert.equal(incident.tabId, 123);
  assert.equal(incident.pageOrigin, "https://example.com");
  assert.equal(incident.destinationOrigin, "https://evil.test");
  assert.equal(incident.decision, "blocked");
  assert.equal(incident.explanation, null);

  // Rule labels are allowed to *describe* a password field ("Password form
  // targeted another origin") — what must never appear is the sensitive
  // *value* itself, as a field on the incident. Check the actual key set,
  // not a naive substring match (which would false-positive on labels).
  const forbiddenKeys = ["password", "cookie", "cookies", "token", "authorization", "formData", "rawBody", "value"];
  for (const key of forbiddenKeys) {
    assert.equal(Object.prototype.hasOwnProperty.call(incident, key), false, `incident must not have a "${key}" key`);
  }
});

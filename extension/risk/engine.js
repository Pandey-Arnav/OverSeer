/**
 * Sentinel — risk engine.
 *
 * Combines every rule in risk/rules.js into a single score + decision, and
 * builds the normalized incident object (see the data model documented in
 * the project README). This file is intentionally side-effect-free and
 * synchronous so it can run identically in the MAIN-world page monitor
 * (fast, context-free pre-check) and the background service worker (full
 * context-aware evaluation for logging).
 */
(function (global) {
  function assertValidEvent(event) {
    if (!event || typeof event !== "object") {
      throw new TypeError("Sentinel.evaluateRisk: event must be an object");
    }
    const validTypes = Object.values(global.Sentinel.EVENT_TYPES);
    if (!validTypes.includes(event.type)) {
      throw new TypeError(`Sentinel.evaluateRisk: unknown event type "${event.type}"`);
    }
    if (!event.pageOrigin || typeof event.pageOrigin !== "string") {
      throw new TypeError("Sentinel.evaluateRisk: event.pageOrigin is required");
    }
  }

  /** Decides allow/warn/blocked/detected_not_blocked given a score + event type. */
  function decideAction(eventType, score) {
    const { WARN, BLOCK } = global.Sentinel.THRESHOLDS;
    const { ALLOW, WARN: WARN_DECISION, BLOCKED, DETECTED_NOT_BLOCKED } = global.Sentinel.DECISION;

    if (score >= BLOCK) {
      return global.Sentinel.BLOCKABLE_EVENT_TYPES.has(eventType) ? BLOCKED : DETECTED_NOT_BLOCKED;
    }
    if (score >= WARN) return WARN_DECISION;
    return ALLOW;
  }

  /**
   * Runs every rule against `event`/`context` and returns
   * { score, severity, decision, reasons }. Throws on structurally invalid
   * input (unknown event type, missing pageOrigin) — callers are expected
   * to validate/sanitize before this point and to catch+log, per the
   * "never silently ignore errors" project rule.
   */
  function evaluateRisk(event, context = {}) {
    assertValidEvent(event);

    const normalizedEvent = { ...event, timestamp: event.timestamp ?? Date.now() };

    const reasons = [];
    for (const rule of global.Sentinel.RULES) {
      const finding = rule(normalizedEvent, context);
      if (finding) reasons.push(finding);
    }

    const rawScore = reasons.reduce((sum, r) => sum + r.points, 0);
    const score = global.Sentinel.clampScore(rawScore);
    const severity = global.Sentinel.severityForScore(score);
    const decision = decideAction(normalizedEvent.type, score);

    return { score, severity, decision, reasons };
  }

  /** Builds the normalized incident object from an event + its evaluation. */
  function buildIncident(event, evaluation) {
    const destination = event.destinationUrl ? global.Sentinel.safeParseUrl(event.destinationUrl) : null;
    return {
      id: global.Sentinel.generateId(),
      timestamp: global.Sentinel.nowIso(),
      tabId: typeof event.tabId === "number" ? event.tabId : null,
      pageUrl: event.pageUrl ?? null,
      pageOrigin: event.pageOrigin,
      eventType: event.type,
      destinationUrl: event.destinationUrl ?? null,
      destinationOrigin: destination ? destination.origin : null,
      method: event.method ?? null,
      payloadSize: typeof event.payloadSize === "number" ? event.payloadSize : null,
      score: evaluation.score,
      severity: evaluation.severity,
      decision: evaluation.decision,
      reasons: evaluation.reasons,
      explanation: null,
    };
  }

  global.Sentinel = global.Sentinel || {};
  Object.assign(global.Sentinel, { evaluateRisk, buildIncident, decideAction });

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { evaluateRisk, buildIncident, decideAction };
  }
})(typeof self !== "undefined" ? self : globalThis);

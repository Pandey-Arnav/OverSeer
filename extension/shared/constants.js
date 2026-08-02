/**
 * Sentinel — shared constants.
 *
 * Single source of truth for rule weights, thresholds, event/decision enums,
 * and detection tuning knobs. Change thresholds here, nowhere else.
 *
 * Loaded as a classic (non-module) script in every extension context
 * (background, content script, popup, dashboard) via <script>/manifest
 * "js" arrays, so it must not use `export`/`import` — everything is
 * attached to a single global, `Sentinel`, to avoid polluting the page's
 * own globals when injected into the MAIN world.
 */
(function (global) {
  const RULE_WEIGHTS = {
    CROSS_ORIGIN_REQUEST: 45,
    LARGE_PAYLOAD: 40,
    SEND_BEACON: 20,
    REDIRECT_AFTER_CLICK: 15,
    UNSEEN_DESTINATION: 10,
    RAW_IP_DESTINATION: 40,
    PASSWORD_FORM_CROSS_ORIGIN: 50,
    HIDDEN_IFRAME: 25,
    MULTIPLE_REDIRECTS: 20,
    CLIPBOARD_ACCESS: 15,
    SUSPICIOUS_PATH: 15,
  };

  // 0-39 allow | 40-69 allow-and-warn | 70-100 block-if-possible-else-warn
  const THRESHOLDS = {
    WARN: 40,
    BLOCK: 70,
    MAX_SCORE: 100,
  };

  const SEVERITY = {
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
  };

  const DECISION = {
    ALLOW: "allow",
    WARN: "warn",
    BLOCKED: "blocked",
    DETECTED_NOT_BLOCKED: "detected_not_blocked",
  };

  const EVENT_TYPES = {
    FETCH_REQUEST: "fetch_request",
    XHR_REQUEST: "xhr_request",
    SEND_BEACON: "send_beacon",
    FORM_SUBMISSION: "form_submission",
    REDIRECT: "redirect",
    HISTORY_CHANGE: "history_change",
    CLIPBOARD_ACCESS: "clipboard_access",
    HIDDEN_IFRAME: "hidden_iframe",
  };

  // Which event types can *actually* be prevented given real MV3/browser
  // constraints, vs. ones we can only ever detect-and-log honestly:
  //   - form_submission: preventDefault() holds it; form.submit() (not
  //     requestSubmit()) resumes without re-firing the listener. Reliable.
  //   - fetch_request / xhr_request (async): both already return a
  //     promise/use callbacks, so gating the real call behind an async
  //     decision doesn't break the page's expected control flow. Reliable
  //     for async XHR only — synchronous XHR (`async: false`) cannot be
  //     delayed without breaking the page, so it is never blocked even if
  //     flagged (see page-monitor.js).
  //   - clipboard_access: Clipboard API methods are promise-based, same
  //     reasoning as fetch.
  //   - send_beacon: the whole point of the Beacon API is a synchronous,
  //     fire-and-forget call with no way to defer or cancel it after
  //     invocation — genuinely not blockable.
  //   - redirect / history_change: MV3 has no reliable way to cancel an
  //     in-progress top-level navigation from an extension. Always
  //     detect-and-log.
  //   - hidden_iframe: by the time a MutationObserver callback sees the
  //     inserted node, the browser may have already started loading its
  //     src. Best-effort removal is attempted, but never promised.
  const BLOCKABLE_EVENT_TYPES = new Set([
    "form_submission",
    "fetch_request",
    "xhr_request",
    "clipboard_access",
  ]);

  // Detection tuning — deliberately conservative defaults for a demo.
  const TUNING = {
    LARGE_PAYLOAD_BYTES: 5000,
    REDIRECT_AFTER_CLICK_WINDOW_MS: 1500,
    MULTIPLE_REDIRECTS_COUNT: 3,
    MULTIPLE_REDIRECTS_WINDOW_MS: 4000,
    SUSPICIOUS_PATH_PATTERNS: [
      /\/(collect|beacon|track|log|gather|exfil|analytics)(\/|$|\?)/i,
      /\.(php|cgi)(\?|$)/i,
    ],
    RAW_IP_REGEX:
      /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[?[0-9a-f:]+:[0-9a-f:]+\]?)$/i,
  };

  const STORAGE_KEYS = {
    INCIDENTS: "sentinelIncidents",
    SETTINGS: "sentinelSettings",
  };

  const DEFAULT_SETTINGS = {
    protectionEnabled: true,
    aiExplanationsEnabled: true,
  };

  const MAX_STORED_INCIDENTS = 500;

  const BACKEND_URL = "http://localhost:4000";

  global.Sentinel = global.Sentinel || {};
  global.Sentinel.RULE_WEIGHTS = RULE_WEIGHTS;
  global.Sentinel.THRESHOLDS = THRESHOLDS;
  global.Sentinel.SEVERITY = SEVERITY;
  global.Sentinel.DECISION = DECISION;
  global.Sentinel.EVENT_TYPES = EVENT_TYPES;
  global.Sentinel.BLOCKABLE_EVENT_TYPES = BLOCKABLE_EVENT_TYPES;
  global.Sentinel.TUNING = TUNING;
  global.Sentinel.STORAGE_KEYS = STORAGE_KEYS;
  global.Sentinel.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
  global.Sentinel.MAX_STORED_INCIDENTS = MAX_STORED_INCIDENTS;
  global.Sentinel.BACKEND_URL = BACKEND_URL;

  // CommonJS export so the same file can be `require()`d unmodified from
  // the Node test runner (Phase 1 tests) without a build step.
  if (typeof module !== "undefined" && module.exports) {
    module.exports = global.Sentinel;
  }
})(typeof self !== "undefined" ? self : globalThis);

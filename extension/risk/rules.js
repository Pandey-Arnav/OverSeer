/**
 * Sentinel — risk rules.
 *
 * Each rule is a pure function: (event, context) => finding|null.
 * `event` is the sanitized, already-collected metadata for one observed
 * action (see shared/constants.js EVENT_TYPES and the incident model in
 * risk/engine.js). `context` carries cross-event state the caller may or
 * may not have available:
 *   - seenDestinations: Set<string> of previously-seen destination origins
 *     (undefined when called from a context-free/synchronous check)
 *   - lastClickTimestamp: number|null, ms epoch of the most recent user click
 *   - recentRedirectCount: number, redirects within the tuning window
 *
 * Rules that need a context field simply return null if it's missing,
 * rather than throwing — this lets the exact same rule set run either as
 * a fast context-free pre-check (in the page's MAIN world, before a
 * network call is allowed to proceed) or as the full context-aware
 * evaluation (in the background service worker, for accurate logging).
 */
(function (global) {
  const { RULE_WEIGHTS, TUNING, EVENT_TYPES } = global.Sentinel;
  const { safeParseUrl, isCrossOrigin, isRawIpDestination, hasSuspiciousPath } = global.Sentinel;

  const NETWORKY_EVENTS = new Set([
    EVENT_TYPES.FETCH_REQUEST,
    EVENT_TYPES.XHR_REQUEST,
    EVENT_TYPES.SEND_BEACON,
    EVENT_TYPES.FORM_SUBMISSION,
  ]);

  function crossOriginRequest(event) {
    if (!NETWORKY_EVENTS.has(event.type) || !event.destinationUrl) return null;
    if (!isCrossOrigin(event.pageOrigin, event.destinationUrl)) return null;
    return {
      ruleId: "cross-origin-request",
      label: "Request sent to a different origin than the page",
      points: RULE_WEIGHTS.CROSS_ORIGIN_REQUEST,
    };
  }

  function largePayload(event) {
    if (typeof event.payloadSize !== "number") return null;
    if (event.payloadSize <= TUNING.LARGE_PAYLOAD_BYTES) return null;
    return {
      ruleId: "large-payload",
      label: `Unusually large request payload (~${Math.round(event.payloadSize / 1024)}KB)`,
      points: RULE_WEIGHTS.LARGE_PAYLOAD,
    };
  }

  function sendBeaconUsage(event) {
    if (event.type !== EVENT_TYPES.SEND_BEACON) return null;
    return {
      ruleId: "send-beacon-usage",
      label: "Page used navigator.sendBeacon (fire-and-forget background request)",
      points: RULE_WEIGHTS.SEND_BEACON,
    };
  }

  function redirectAfterClick(event, context) {
    const isNav = event.type === EVENT_TYPES.REDIRECT || event.type === EVENT_TYPES.HISTORY_CHANGE;
    if (!isNav || !context || !context.lastClickTimestamp) return null;
    const delta = event.timestamp - context.lastClickTimestamp;
    if (delta < 0 || delta > TUNING.REDIRECT_AFTER_CLICK_WINDOW_MS) return null;
    return {
      ruleId: "redirect-after-click",
      label: "Page redirected within a second of a user click",
      points: RULE_WEIGHTS.REDIRECT_AFTER_CLICK,
    };
  }

  function unseenDestination(event, context) {
    if (!NETWORKY_EVENTS.has(event.type) || !event.destinationUrl) return null;
    if (!context || !(context.seenDestinations instanceof Set)) return null;
    const parsed = safeParseUrl(event.destinationUrl);
    if (!parsed) return null;
    if (context.seenDestinations.has(parsed.origin)) return null;
    return {
      ruleId: "unseen-destination",
      label: "First time this page has contacted this destination",
      points: RULE_WEIGHTS.UNSEEN_DESTINATION,
    };
  }

  function rawIpDestination(event) {
    if (!event.destinationUrl || !isRawIpDestination(event.destinationUrl)) return null;
    return {
      ruleId: "raw-ip-destination",
      label: "Destination is a raw IP address rather than a domain name",
      points: RULE_WEIGHTS.RAW_IP_DESTINATION,
    };
  }

  function passwordFormCrossOrigin(event) {
    if (event.type !== EVENT_TYPES.FORM_SUBMISSION || !event.hasPasswordField) return null;
    if (!event.destinationUrl || !isCrossOrigin(event.pageOrigin, event.destinationUrl)) return null;
    return {
      ruleId: "cross-origin-password-form",
      label: "Password form targeted another origin",
      points: RULE_WEIGHTS.PASSWORD_FORM_CROSS_ORIGIN,
    };
  }

  function hiddenIframe(event) {
    if (event.type !== EVENT_TYPES.HIDDEN_IFRAME || !event.isHidden) return null;
    return {
      ruleId: "hidden-iframe",
      label: "A hidden (zero-size or off-screen) iframe was inserted into the page",
      points: RULE_WEIGHTS.HIDDEN_IFRAME,
    };
  }

  function multipleRedirects(event, context) {
    const isNav = event.type === EVENT_TYPES.REDIRECT || event.type === EVENT_TYPES.HISTORY_CHANGE;
    if (!isNav || !context || typeof context.recentRedirectCount !== "number") return null;
    if (context.recentRedirectCount < TUNING.MULTIPLE_REDIRECTS_COUNT) return null;
    return {
      ruleId: "multiple-redirects",
      label: `${context.recentRedirectCount} redirects happened in quick succession`,
      points: RULE_WEIGHTS.MULTIPLE_REDIRECTS,
    };
  }

  function clipboardAccess(event) {
    if (event.type !== EVENT_TYPES.CLIPBOARD_ACCESS) return null;
    return {
      ruleId: "clipboard-access",
      label: `Page attempted a clipboard ${event.clipboardAction || "access"} operation`,
      points: RULE_WEIGHTS.CLIPBOARD_ACCESS,
    };
  }

  function suspiciousPath(event) {
    if (!event.destinationUrl || !hasSuspiciousPath(event.destinationUrl)) return null;
    return {
      ruleId: "suspicious-path",
      label: "Destination URL path looks like a tracking/collection endpoint",
      points: RULE_WEIGHTS.SUSPICIOUS_PATH,
    };
  }

  const RULES = [
    crossOriginRequest,
    largePayload,
    sendBeaconUsage,
    redirectAfterClick,
    unseenDestination,
    rawIpDestination,
    passwordFormCrossOrigin,
    hiddenIframe,
    multipleRedirects,
    clipboardAccess,
    suspiciousPath,
  ];

  global.Sentinel = global.Sentinel || {};
  global.Sentinel.RULES = RULES;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { RULES };
  }
})(typeof self !== "undefined" ? self : globalThis);

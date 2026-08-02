/**
 * Sentinel — shared utility helpers.
 * Classic script (see constants.js header for why); attaches to the
 * `Sentinel` global and also CommonJS-exports for the Node test runner.
 */
(function (global) {
  /** Parses a URL string into {origin, hostname, pathname}, or null if invalid. */
  function safeParseUrl(urlString) {
    try {
      const u = new URL(urlString);
      return { origin: u.origin, hostname: u.hostname, pathname: u.pathname + u.search };
    } catch {
      return null;
    }
  }

  function isCrossOrigin(pageOrigin, destinationUrl) {
    const parsed = safeParseUrl(destinationUrl);
    if (!parsed) return false;
    return parsed.origin !== pageOrigin;
  }

  function isRawIpDestination(destinationUrl) {
    const parsed = safeParseUrl(destinationUrl);
    if (!parsed) return false;
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    return global.Sentinel.TUNING.RAW_IP_REGEX.test(host);
  }

  function hasSuspiciousPath(destinationUrl) {
    const parsed = safeParseUrl(destinationUrl);
    if (!parsed) return false;
    return global.Sentinel.TUNING.SUSPICIOUS_PATH_PATTERNS.some((re) => re.test(parsed.pathname));
  }

  function clampScore(score) {
    return Math.max(0, Math.min(global.Sentinel.THRESHOLDS.MAX_SCORE, Math.round(score)));
  }

  function severityForScore(score) {
    const { WARN, BLOCK } = global.Sentinel.THRESHOLDS;
    const { LOW, MEDIUM, HIGH } = global.Sentinel.SEVERITY;
    if (score >= BLOCK) return HIGH;
    if (score >= WARN) return MEDIUM;
    return LOW;
  }

  function generateId() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
    return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  function nowIso() {
    return new Date().toISOString();
  }

  global.Sentinel = global.Sentinel || {};
  Object.assign(global.Sentinel, {
    safeParseUrl,
    isCrossOrigin,
    isRawIpDestination,
    hasSuspiciousPath,
    clampScore,
    severityForScore,
    generateId,
    nowIso,
  });

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      safeParseUrl,
      isCrossOrigin,
      isRawIpDestination,
      hasSuspiciousPath,
      clampScore,
      severityForScore,
      generateId,
      nowIso,
    };
  }
})(typeof self !== "undefined" ? self : globalThis);

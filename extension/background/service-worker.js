/**
 * Sentinel — background service worker.
 *
 * The single canonical place the risk engine runs (per the project's
 * decision pipeline: page → content script → HERE → decision → page).
 * Owns per-tab behavior context (seen destinations, last click, recent
 * redirects), persists incidents, updates the toolbar badge, and
 * maintains the one declarativeNetRequest rule that's actually a good
 * fit for DNR (see comment below).
 *
 * Classic (non-module) service worker — importScripts() loads the shared
 * IIFE-style files that also run unmodified in the browser and under
 * Node's test runner.
 */
importScripts(
  "../shared/constants.js",
  "../shared/utils.js",
  "../risk/rules.js",
  "../risk/engine.js",
  "../storage/incidents.js"
);

const BADGE_COLORS = { low: "#16a34a", medium: "#f59e0b", high: "#dc2626" };
const RAW_IP_BLOCK_RULE_ID = 1;

/**
 * Per-tab in-memory behavior state. Deliberately NOT persisted — an MV3
 * service worker can be killed and restarted between events, which would
 * reset this anyway. Incidents themselves are safely persisted via
 * chrome.storage.local regardless (see storage/incidents.js); only the
 * live "context" used to enrich scoring (unseen destinations, redirect
 * timing) is best-effort in-memory. See README known limitations.
 */
const tabContext = new Map();
const lastUrlByTab = new Map();

function getContext(tabId) {
  if (!tabContext.has(tabId)) {
    tabContext.set(tabId, {
      seenDestinations: new Set(),
      lastClickTimestamp: null,
      redirectTimestamps: [],
      incidentCount: 0,
      maxSeverity: "low",
    });
  }
  return tabContext.get(tabId);
}

function resetContext(tabId) {
  tabContext.set(tabId, {
    seenDestinations: new Set(),
    lastClickTimestamp: null,
    redirectTimestamps: [],
    incidentCount: 0,
    maxSeverity: "low",
  });
}

function recordRedirect(tabId, ts) {
  const ctx = getContext(tabId);
  ctx.redirectTimestamps.push(ts);
  const cutoff = ts - self.Sentinel.TUNING.MULTIPLE_REDIRECTS_WINDOW_MS;
  ctx.redirectTimestamps = ctx.redirectTimestamps.filter((t) => t >= cutoff);
}

function updateBadge(tabId) {
  const ctx = tabContext.get(tabId);
  if (!ctx || ctx.incidentCount === 0) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  chrome.action.setBadgeText({ tabId, text: String(ctx.incidentCount) });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[ctx.maxSeverity] || BADGE_COLORS.low });
}

const SEVERITY_RANK = { low: 0, medium: 1, high: 2 };

/**
 * The single canonical evaluate → log → (optionally) block decision.
 * Used both for events relayed from content scripts and for redirects
 * detected directly here via webNavigation.
 */
async function evaluateAndLog(event) {
  const settings = await self.Sentinel.getSettings();
  if (!settings.protectionEnabled) {
    return { score: 0, severity: "low", decision: "allow", reasons: [], incidentId: null, protectionDisabled: true };
  }

  const ctx = getContext(event.tabId);

  // Both real browser redirects (webNavigation) and SPA-style
  // history.pushState/replaceState calls count toward "multiple
  // redirects" — record here, in the one place risk actually gets
  // evaluated, so the rule sees a consistent count regardless of source.
  const isNavEvent = event.type === self.Sentinel.EVENT_TYPES.REDIRECT || event.type === self.Sentinel.EVENT_TYPES.HISTORY_CHANGE;
  if (isNavEvent) recordRedirect(event.tabId, event.timestamp || Date.now());

  const context = {
    seenDestinations: ctx.seenDestinations,
    lastClickTimestamp: ctx.lastClickTimestamp,
    recentRedirectCount: ctx.redirectTimestamps.length,
  };

  let evaluation;
  try {
    evaluation = self.Sentinel.evaluateRisk(event, context);
  } catch (err) {
    // Never let a bug in evaluation break the page — fail open, but log
    // loudly for development (no sensitive data in `err.message`, since
    // it only ever describes shape problems like an unknown event type).
    console.error("[Sentinel] evaluateRisk failed:", err.message);
    return { score: 0, severity: "low", decision: "allow", reasons: [], incidentId: null, evaluationError: true };
  }

  if (event.destinationUrl) {
    const parsed = self.Sentinel.safeParseUrl(event.destinationUrl);
    if (parsed) ctx.seenDestinations.add(parsed.origin);
  }

  const incident = self.Sentinel.buildIncident(event, evaluation);
  await self.Sentinel.addIncident(incident);

  ctx.incidentCount += 1;
  if (SEVERITY_RANK[evaluation.severity] > SEVERITY_RANK[ctx.maxSeverity]) {
    ctx.maxSeverity = evaluation.severity;
  }
  updateBadge(event.tabId);

  return { ...evaluation, incidentId: incident.id };
}

// --- Messages from content scripts --------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "sentinel-event" && sender.tab?.id != null) {
    const event = { ...message.event, tabId: sender.tab.id };
    evaluateAndLog(event)
      .then(sendResponse)
      .catch((err) => {
        console.error("[Sentinel] unexpected error handling event:", err.message);
        sendResponse({ score: 0, severity: "low", decision: "allow", reasons: [], incidentId: null });
      });
    return true; // keep the message channel open for the async response
  }

  if (message?.type === "sentinel-click" && sender.tab?.id != null) {
    getContext(sender.tab.id).lastClickTimestamp = Date.now();
  }

  return false;
});

// --- Redirect tracking via webNavigation --------------------------------
//
// MV3 gives no reliable way to *cancel* an in-progress top-level
// navigation, so this is detection/logging only — matches
// BLOCKABLE_EVENT_TYPES not including "redirect".

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const isRedirect =
    details.transitionQualifiers.includes("client_redirect") ||
    details.transitionQualifiers.includes("server_redirect");
  const previousUrl = lastUrlByTab.get(details.tabId);

  if (isRedirect && previousUrl) {
    const ts = Date.now();
    const parsed = self.Sentinel.safeParseUrl(previousUrl);
    if (parsed) {
      await evaluateAndLog({
        tabId: details.tabId,
        type: self.Sentinel.EVENT_TYPES.REDIRECT,
        pageUrl: previousUrl,
        pageOrigin: parsed.origin,
        destinationUrl: details.url,
        timestamp: ts,
      });
    }
  } else {
    // Fresh top-level navigation: new page, new behavior window.
    resetContext(details.tabId);
    chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
  }

  lastUrlByTab.set(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabContext.delete(tabId);
  lastUrlByTab.delete(tabId);
});

// --- declarativeNetRequest: the one rule DNR is actually right for ------
//
// DNR only matches static URL patterns — it can't react to a JS-computed
// score, so it's not a fit for most of this extension's rules. Raw-IP
// destinations are the exception: "is this hostname a literal IP" is a
// purely static, regex-matchable property of the URL, so a real network-
// level block is both possible and appropriate here. Scoped to
// sub-resource request types only (NOT main_frame) — a user directly
// navigating to an IP address (e.g. a home router at 192.168.1.1) is
// normal and should not be blocked; a page's *background* request to a
// raw IP is the actual suspicious pattern this extension targets.
async function syncRawIpBlockRule(enabled) {
  const addRules = enabled
    ? [
        {
          id: RAW_IP_BLOCK_RULE_ID,
          priority: 1,
          action: { type: "block" },
          condition: {
            regexFilter: "^https?://(\\d{1,3}\\.){3}\\d{1,3}([:/]|$)",
            resourceTypes: [
              "xmlhttprequest",
              "sub_frame",
              "script",
              "image",
              "media",
              "font",
              "object",
              "ping",
              "csp_report",
              "other",
            ],
          },
        },
      ]
    : [];

  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [RAW_IP_BLOCK_RULE_ID],
      addRules,
    });
  } catch (err) {
    console.error("[Sentinel] failed to sync declarativeNetRequest rule:", err.message);
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await self.Sentinel.getSettings();
  await syncRawIpBlockRule(settings.protectionEnabled);
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || !changes[self.Sentinel.STORAGE_KEYS.SETTINGS]) return;
  const next = changes[self.Sentinel.STORAGE_KEYS.SETTINGS].newValue || {};
  syncRawIpBlockRule(next.protectionEnabled !== false);
});

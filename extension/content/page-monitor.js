/**
 * Sentinel — page monitor (runs in the MAIN world; see manifest.json).
 *
 * Content scripts normally run in an ISOLATED world: they share the DOM
 * with the page but have their own separate JS globals, so patching
 * window.fetch/XMLHttpRequest/etc. from there would NOT intercept calls
 * the page's own script makes — each world has its own copy of the
 * mutable global object. This file has to run in the MAIN world instead.
 *
 * MAIN-world scripts have no chrome.* API access, so decisions come from
 * a window.postMessage round trip to content-script.js (ISOLATED world,
 * which does have chrome.* access) and on to the background service
 * worker, which is the single canonical place risk is evaluated.
 *
 * Only fetch, async XHR, and the Clipboard API are gated on that
 * decision before proceeding — they're all promise/callback-based, so an
 * async round trip doesn't break the page's expected control flow.
 * navigator.sendBeacon and history.pushState/replaceState are reported
 * but never gated: sendBeacon is a synchronous fire-and-forget call by
 * design (nothing to delay), and reliably intercepting SPA navigation
 * without breaking the page isn't feasible either — see
 * BLOCKABLE_EVENT_TYPES in shared/constants.js for the full reasoning.
 */
(function () {
  const REQUEST_TIMEOUT_MS = 3000;

  function estimateBodySize(body) {
    if (body == null) return 0;
    if (typeof body === "string") return body.length;
    if (typeof Blob !== "undefined" && body instanceof Blob) return body.size;
    if (body instanceof ArrayBuffer) return body.byteLength;
    if (ArrayBuffer.isView(body)) return body.byteLength;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
      return body.toString().length;
    }
    if (typeof FormData !== "undefined" && body instanceof FormData) {
      let total = 0;
      for (const [key, value] of body.entries()) {
        total += key.length;
        total += typeof value === "string" ? value.length : value.size || 0;
      }
      return total;
    }
    return undefined;
  }

  function resolveUrl(url) {
    try {
      return new URL(url, location.href).href;
    } catch {
      return typeof url === "string" ? url : null;
    }
  }

  /**
   * Sends a sanitized event to the isolated-world content script and,
   * when `wait` is true, awaits its decision (fail-open on timeout so a
   * bridge hiccup never hangs the page). When `wait` is false this is a
   * pure fire-and-forget notification for logging.
   */
  function requestEvaluation(event, { wait }) {
    const correlationId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    window.postMessage(
      { source: "sentinel-page-monitor", type: "sentinel-evaluate-request", correlationId, event },
      location.origin
    );
    if (!wait) return Promise.resolve(null);

    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        window.removeEventListener("message", handler);
        resolve(null); // fail-open: never hang page behavior on our own plumbing
      }, REQUEST_TIMEOUT_MS);

      function handler(e) {
        if (e.source !== window || e.origin !== location.origin) return;
        const data = e.data;
        if (
          !data ||
          data.source !== "sentinel-content-script" ||
          data.type !== "sentinel-evaluate-response" ||
          data.correlationId !== correlationId
        ) {
          return;
        }
        clearTimeout(timeoutId);
        window.removeEventListener("message", handler);
        resolve(data.result);
      }
      window.addEventListener("message", handler);
    });
  }

  // --- fetch ---------------------------------------------------------

  const originalFetch = window.fetch;
  if (originalFetch) {
    window.fetch = async function (input, init) {
      const url = typeof input === "string" || input instanceof URL ? String(input) : input.url;
      const method = (init && init.method) || "GET";
      const event = {
        type: "fetch_request",
        pageUrl: location.href,
        pageOrigin: location.origin,
        destinationUrl: resolveUrl(url),
        method: String(method).toUpperCase(),
        payloadSize: estimateBodySize(init && init.body),
        timestamp: Date.now(),
      };
      const result = await requestEvaluation(event, { wait: true });
      if (result && result.decision === "blocked") {
        return Promise.reject(new TypeError(`Sentinel blocked this request (risk score ${result.score}/100)`));
      }
      return originalFetch.call(window, input, init);
    };
  }

  // --- XMLHttpRequest --------------------------------------------------

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, async) {
    this.__sentinelMeta = {
      method: String(method || "GET").toUpperCase(),
      url: String(url),
      async: async !== false,
    };
    return originalOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const meta = this.__sentinelMeta || { method: "GET", url: location.href, async: true };
    const event = {
      type: "xhr_request",
      pageUrl: location.href,
      pageOrigin: location.origin,
      destinationUrl: resolveUrl(meta.url),
      method: meta.method,
      payloadSize: estimateBodySize(body),
      timestamp: Date.now(),
    };

    if (meta.async === false) {
      // Synchronous XHR blocks the calling thread until it completes —
      // delaying it to await a decision would hang the page. Detect and
      // log only; never claim this was blocked.
      requestEvaluation(event, { wait: false });
      return originalSend.call(this, body);
    }

    const xhr = this;
    requestEvaluation(event, { wait: true }).then((result) => {
      if (result && result.decision === "blocked") {
        // Best-effort: surface a network-error-shaped failure rather than
        // leaving the caller's onload/onerror handlers waiting forever.
        queueMicrotask(() => xhr.dispatchEvent(new Event("error")));
        return;
      }
      originalSend.call(xhr, body);
    });
  };

  // --- navigator.sendBeacon --------------------------------------------
  //
  // Fire-and-forget by design — there's no way to delay or cancel it
  // after invocation, so this is detection/logging only.

  if (navigator.sendBeacon) {
    const originalSendBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      requestEvaluation(
        {
          type: "send_beacon",
          pageUrl: location.href,
          pageOrigin: location.origin,
          destinationUrl: resolveUrl(url),
          method: "POST",
          payloadSize: estimateBodySize(data),
          timestamp: Date.now(),
        },
        { wait: false }
      );
      return originalSendBeacon(url, data);
    };
  }

  // --- Clipboard API -----------------------------------------------------

  if (navigator.clipboard) {
    if (navigator.clipboard.writeText) {
      const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = async function (text) {
        const result = await requestEvaluation(
          {
            type: "clipboard_access",
            pageUrl: location.href,
            pageOrigin: location.origin,
            clipboardAction: "write",
            timestamp: Date.now(),
          },
          { wait: true }
        );
        if (result && result.decision === "blocked") {
          throw new DOMException(`Sentinel blocked this clipboard write (risk score ${result.score}/100)`, "NotAllowedError");
        }
        return originalWriteText(text);
      };
    }

    if (navigator.clipboard.readText) {
      const originalReadText = navigator.clipboard.readText.bind(navigator.clipboard);
      navigator.clipboard.readText = async function () {
        const result = await requestEvaluation(
          {
            type: "clipboard_access",
            pageUrl: location.href,
            pageOrigin: location.origin,
            clipboardAction: "read",
            timestamp: Date.now(),
          },
          { wait: true }
        );
        if (result && result.decision === "blocked") {
          throw new DOMException(`Sentinel blocked this clipboard read (risk score ${result.score}/100)`, "NotAllowedError");
        }
        return originalReadText();
      };
    }
  }

  // --- history.pushState / replaceState ---------------------------------
  //
  // SPA-style navigation the page triggers itself. Not reliably
  // interceptable/reversible without risking breaking the page, so this
  // is detection/logging only (feeds the "multiple redirects" and
  // "redirect after click" rules the same way full navigations do).

  ["pushState", "replaceState"].forEach((fnName) => {
    const original = history[fnName];
    history[fnName] = function (...args) {
      requestEvaluation(
        {
          type: "history_change",
          pageUrl: location.href,
          pageOrigin: location.origin,
          destinationUrl: resolveUrl(args[2] ?? location.href),
          timestamp: Date.now(),
        },
        { wait: false }
      );
      return original.apply(history, args);
    };
  });
})();

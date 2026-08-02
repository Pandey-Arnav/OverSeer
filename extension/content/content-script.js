/**
 * Sentinel — content script (ISOLATED world; see manifest.json).
 *
 * Responsibilities:
 *   1. Bridge: validate + relay MAIN-world events (from page-monitor.js)
 *      to the background service worker, and post the decision back.
 *   2. Native DOM observation that doesn't need MAIN-world access: form
 *      submissions (including password-field detection), click timing,
 *      and hidden-iframe insertion.
 *
 * Loaded after shared/constants.js + shared/utils.js (see manifest.json),
 * so `Sentinel.*` is already populated in this world.
 */
(function () {
  const { EVENT_TYPES } = Sentinel;

  function sendToBackground(event) {
    return chrome.runtime.sendMessage({ type: "sentinel-event", event }).catch((err) => {
      console.error("[Sentinel] failed to reach background service worker:", err.message);
      return { score: 0, severity: "low", decision: "allow", reasons: [], incidentId: null };
    });
  }

  // --- Bridge: MAIN world (page-monitor.js) <-> background --------------
  //
  // Validate every postMessage before trusting it: same window, same
  // origin, and a recognizable Sentinel envelope shape. Untrusted pages
  // can post arbitrary messages, so none of this is assumed safe by
  // default.
  window.addEventListener("message", (e) => {
    if (e.source !== window || e.origin !== location.origin) return;
    const data = e.data;
    if (!data || data.source !== "sentinel-page-monitor" || data.type !== "sentinel-evaluate-request") return;
    if (!data.correlationId || !data.event || typeof data.event !== "object") return;

    sendToBackground(data.event).then((result) => {
      window.postMessage(
        {
          source: "sentinel-content-script",
          type: "sentinel-evaluate-response",
          correlationId: data.correlationId,
          result,
        },
        location.origin
      );
    });
  });

  // --- Click timing (feeds the redirect-after-click rule) ---------------

  document.addEventListener(
    "click",
    () => {
      chrome.runtime.sendMessage({ type: "sentinel-click" }).catch(() => {});
    },
    { capture: true, passive: true }
  );

  // --- Form submission: hold, evaluate, then resume or keep blocked -----
  //
  // e.preventDefault() holds the submission synchronously while we await
  // the background's decision. To resume, we call form.submit() rather
  // than form.requestSubmit() — per the HTML spec, .submit() does NOT
  // re-fire the "submit" event, so this can't loop back into this same
  // handler.

  function approximateFormPayloadSize(form) {
    let total = 0;
    for (const el of form.elements) {
      if (!el.name || el.disabled) continue;
      if (el.type === "password") {
        // Count only the length toward payload size — never the value.
        total += el.name.length + (el.value ? el.value.length : 0);
        continue;
      }
      if (el.type === "file") {
        total += el.name.length + Array.from(el.files || []).reduce((sum, f) => sum + f.size, 0);
        continue;
      }
      if (el.type === "checkbox" || el.type === "radio") {
        if (!el.checked) continue;
      }
      total += el.name.length + (el.value ? String(el.value).length : 0);
    }
    return total;
  }

  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;

      e.preventDefault();

      const destinationUrl = (() => {
        try {
          return new URL(form.action || location.href, location.href).href;
        } catch {
          return location.href;
        }
      })();
      const hasPasswordField = !!form.querySelector('input[type="password"]');
      const payloadSize = approximateFormPayloadSize(form);

      const event = {
        type: EVENT_TYPES.FORM_SUBMISSION,
        pageUrl: location.href,
        pageOrigin: location.origin,
        destinationUrl,
        method: (form.method || "GET").toUpperCase(),
        hasPasswordField,
        payloadSize,
        timestamp: Date.now(),
      };

      sendToBackground(event).then((result) => {
        if (result && result.decision === "blocked") {
          showBlockedFormNotice(form, result, () => {
            form.submit(); // user override — does not re-fire "submit"
          });
          return;
        }
        form.submit();
      });
    },
    { capture: true }
  );

  /** Minimal, dependency-free interstitial for a blocked form submission. */
  function showBlockedFormNotice(form, result, onContinueAnyway) {
    const existing = document.getElementById("sentinel-block-notice");
    if (existing) existing.remove();

    const topReason = result.reasons && result.reasons[0] ? result.reasons[0].label : "Suspicious behavior detected";

    const notice = document.createElement("div");
    notice.id = "sentinel-block-notice";
    notice.setAttribute(
      "style",
      "position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;" +
        "background:rgba(15,23,32,0.92);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
    );
    notice.innerHTML = `
      <div style="max-width:420px;background:#fff;border-radius:12px;padding:28px;box-shadow:0 20px 50px rgba(0,0,0,0.35);">
        <div style="font-size:28px;margin-bottom:8px;">🛡️</div>
        <h2 style="margin:0 0 8px;font-size:18px;color:#0f1720;">Sentinel blocked this form submission</h2>
        <p style="margin:0 0 4px;color:#374151;font-size:14px;">Risk score: <strong>${result.score}/100</strong></p>
        <p style="margin:0 0 16px;color:#374151;font-size:14px;">${topReason}</p>
        <div style="display:flex;gap:8px;">
          <button id="sentinel-block-leave" style="flex:1;padding:10px;border:none;border-radius:8px;background:#0f1720;color:#fff;font-weight:600;cursor:pointer;">Cancel</button>
          <button id="sentinel-block-continue" style="flex:1;padding:10px;border:1px solid #d1d5db;border-radius:8px;background:#fff;color:#374151;font-size:13px;cursor:pointer;">Continue anyway</button>
        </div>
      </div>
    `;
    document.documentElement.appendChild(notice);

    notice.querySelector("#sentinel-block-leave").addEventListener("click", () => notice.remove());
    notice.querySelector("#sentinel-block-continue").addEventListener("click", () => {
      notice.remove();
      onContinueAnyway();
    });
  }

  // --- Hidden iframe detection --------------------------------------------

  function isHidden(el) {
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return true;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return true;
    if (rect.left < -1000 || rect.top < -1000) return true;
    return false;
  }

  function reportIframe(iframe) {
    sendToBackground({
      type: EVENT_TYPES.HIDDEN_IFRAME,
      pageUrl: location.href,
      pageOrigin: location.origin,
      destinationUrl: iframe.src || null,
      isHidden: isHidden(iframe),
      timestamp: Date.now(),
    });
  }

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;
        if (node.tagName === "IFRAME") reportIframe(node);
        else node.querySelectorAll?.("iframe").forEach(reportIframe);
      }
    }
  });
  observer.observe(document.documentElement || document, { childList: true, subtree: true });
})();

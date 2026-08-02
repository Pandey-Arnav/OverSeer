/**
 * Sentinel Transaction Guardian — content script.
 *
 * Watches forms containing payment-like fields (recipient/account/
 * amount) for the classic banking-trojan / man-in-the-browser pattern:
 * a script silently rewriting a field's value after the user has
 * already typed it, right before submission — swapping the real
 * destination for an attacker-controlled one without changing anything
 * visible on screen.
 *
 * Detection mechanism: track each payment-like field's value as of its
 * most recent genuine `input` event (real user typing/pasting). A
 * direct property assignment (`el.value = "..."`, the mechanism an
 * injected/malicious script would use) does NOT fire `input` — so a
 * mismatch between the tracked value and the value at submit time is a
 * reliable tampering signal. This needs only native DOM event listening
 * (no JS-method-overriding), so — unlike the earlier browser-extension
 * prototype's fetch/XHR/clipboard hooks — no MAIN-world injection is
 * needed at all; everything here runs in the default isolated content-
 * script world.
 */
import { PAYMENT_FIELD_PATTERN } from "../shared/constants.ts";

interface AgentDecision {
  score: number;
  severity: "low" | "medium" | "high";
  decision: "allow" | "warn" | "blocked" | "detected_not_blocked";
  reasons: { ruleId: string; label: string; points: number }[];
  incidentId: string | null;
}

function isPaymentField(el: HTMLInputElement | HTMLTextAreaElement): boolean {
  const haystack = [el.name, el.id, el.autocomplete, el.placeholder].filter(Boolean).join(" ");
  return PAYMENT_FIELD_PATTERN.test(haystack);
}

function reportEvent(event: Record<string, unknown>): Promise<AgentDecision> {
  return chrome.runtime
    .sendMessage({ type: "sentinel-report-event", event })
    .catch(() => ({ score: 0, severity: "low", decision: "allow", reasons: [], incidentId: null }) as AgentDecision);
}

// Records each payment-like field's value as of its last genuine `input`
// event. WeakMap so nothing leaks if the field is removed from the DOM,
// and no value ever touches storage or the network except as a diff.
const lastUserValues = new WeakMap<Element, string>();

document.addEventListener(
  "input",
  (e: Event) => {
    const el = e.target;
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      if (isPaymentField(el)) lastUserValues.set(el, el.value);
    }
  },
  { capture: true, passive: true }
);

function findTamperedFields(form: HTMLFormElement): string[] {
  const tampered: string[] = [];
  for (const el of form.elements) {
    if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) continue;
    if (!isPaymentField(el)) continue;
    const lastSeen = lastUserValues.get(el);
    if (lastSeen !== undefined && lastSeen !== el.value) {
      tampered.push(el.name || el.id || "(unnamed field)");
    }
  }
  return tampered;
}

function formHasPaymentField(form: HTMLFormElement): boolean {
  for (const el of form.elements) {
    if ((el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) && isPaymentField(el)) return true;
  }
  return false;
}

document.addEventListener(
  "submit",
  (e: SubmitEvent) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (!formHasPaymentField(form)) return; // out of scope: not a transaction-like form

    e.preventDefault();

    const destinationUrl = (() => {
      try {
        return new URL(form.action || location.href, location.href).href;
      } catch {
        return location.href;
      }
    })();
    const tamperedFieldNames = findTamperedFields(form);

    reportEvent({
      category: "transaction_tampering",
      pageOrigin: location.origin,
      pageUrl: location.href,
      destinationUrl,
      tamperedFieldNames,
    }).then((decision) => {
      if (decision.decision === "blocked") {
        showFrozenNotice(decision, () => {
          form.submit(); // explicit user override — does not re-fire "submit"
        });
        return;
      }
      form.submit();
    });
  },
  { capture: true }
);

/** The core promised UX: freeze the transaction and clearly alert the user. */
function showFrozenNotice(decision: AgentDecision, onContinueAnyway: () => void): void {
  const existing = document.getElementById("sentinel-freeze-notice");
  if (existing) existing.remove();

  const topReason = decision.reasons[0]?.label ?? "A protected field was modified without your input.";

  const notice = document.createElement("div");
  notice.id = "sentinel-freeze-notice";
  notice.setAttribute(
    "style",
    "position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;" +
      "background:rgba(15,23,32,0.94);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
  );
  notice.innerHTML = `
    <div style="max-width:440px;background:#fff;border-radius:14px;padding:30px;box-shadow:0 20px 60px rgba(0,0,0,0.4);">
      <div style="font-size:30px;margin-bottom:8px;">🧊</div>
      <h2 style="margin:0 0 8px;font-size:19px;color:#0f1720;">Transaction frozen</h2>
      <p style="margin:0 0 4px;color:#374151;font-size:14px;">Sentinel detected an unauthorized change to this transaction before it was sent.</p>
      <p style="margin:0 0 16px;color:#dc2626;font-size:13px;font-weight:600;">${topReason}</p>
      <button id="sentinel-freeze-cancel" style="width:100%;padding:12px;border:none;border-radius:8px;background:#0f1720;color:#fff;font-weight:600;cursor:pointer;margin-bottom:8px;">
        Keep this transaction frozen (recommended)
      </button>
      <button id="sentinel-freeze-override" style="width:100%;padding:9px;border:1px solid #d1d5db;border-radius:8px;background:#fff;color:#6b7280;font-size:12px;cursor:pointer;">
        I've verified this myself — send anyway
      </button>
    </div>
  `;
  document.documentElement.appendChild(notice);

  notice.querySelector("#sentinel-freeze-cancel")!.addEventListener("click", () => notice.remove());
  notice.querySelector("#sentinel-freeze-override")!.addEventListener("click", () => {
    notice.remove();
    onContinueAnyway();
  });
}

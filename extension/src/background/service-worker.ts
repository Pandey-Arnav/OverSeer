/**
 * Sentinel Transaction Guardian — background service worker.
 *
 * The only job here: relay a "report event" message from the content
 * script to the local agent's REST API. A content script's own `fetch`
 * can be subject to the visited page's CSP `connect-src` in some Chrome
 * versions; routing through the background service worker (governed by
 * this extension's own host_permissions, not the page's CSP) sidesteps
 * that entirely — the same reason the original browser-extension
 * prototype used a background relay.
 */
import { AGENT_URL } from "../shared/constants.ts";

interface ReportEventMessage {
  type: "sentinel-report-event";
  event: Record<string, unknown>;
}

interface AgentDecision {
  score: number;
  severity: "low" | "medium" | "high";
  decision: "allow" | "warn" | "blocked" | "detected_not_blocked";
  reasons: { ruleId: string; label: string; points: number }[];
  incidentId: string | null;
}

const FAIL_OPEN_DECISION: AgentDecision = { score: 0, severity: "low", decision: "allow", reasons: [], incidentId: null };

async function reportToAgent(event: Record<string, unknown>): Promise<AgentDecision> {
  try {
    const response = await fetch(`${AGENT_URL}/api/report-event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
    });
    if (!response.ok) throw new Error(`agent responded ${response.status}`);
    return (await response.json()) as AgentDecision;
  } catch (err) {
    // Fail open: the Sentinel Agent not running must never block a
    // legitimate transaction. This does mean transaction-integrity
    // protection is inert if the agent isn't running — documented
    // clearly in the README as a real dependency, not hidden.
    console.error("[Sentinel] could not reach local agent (is it running on :4100?):", (err as Error).message);
    return FAIL_OPEN_DECISION;
  }
}

chrome.runtime.onMessage.addListener((message: ReportEventMessage, _sender, sendResponse) => {
  if (message?.type !== "sentinel-report-event") return false;
  reportToAgent(message.event).then(sendResponse);
  return true; // keep the message channel open for the async response
});

chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: AGENT_URL });
});

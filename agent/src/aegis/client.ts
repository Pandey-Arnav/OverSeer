import type { AegisReport, Incident } from "../shared/types.ts";

const AEGIS_URL = process.env["AEGIS_URL"] || "http://127.0.0.1:8012";

export interface AegisPayload {
  incidentId: string;
  eventType: string;
  pageOrigin: string;
  destinationOrigin: string;
  score: number;
  decision: string;
  blockable: boolean;
  reasons: Array<{ ruleId: string; label: string; points: number }>;
}

export function incidentToAegisPayload(incident: Incident): AegisPayload {
  const isUsb = incident.category.startsWith("usb_");
  const destination = incident.remoteAddress
    ? `network://${incident.remoteAddress}${incident.remotePort ? `:${incident.remotePort}` : ""}`
    : isUsb
      ? `hardware://${incident.category}`
      : "local://ghostshield";

  return {
    incidentId: incident.id.slice(0, 200),
    eventType: isUsb ? "usb_scan_result" : incident.category,
    pageOrigin: incident.pageOrigin || "local://ghostshield-agent",
    destinationOrigin: destination,
    score: Math.max(0, Math.min(100, Math.round(incident.score))),
    decision: incident.decision,
    // User-mode USB monitoring observes a mounted volume; it must not claim
    // kernel-level pre-mount blocking even when an eject action is available.
    blockable: !isUsb && incident.remediation?.available === true,
    reasons: incident.reasons.slice(0, 32).map((reason) => ({
      ruleId: reason.ruleId.slice(0, 200),
      label: reason.label.slice(0, 500),
      points: Math.round(reason.points),
    })),
  };
}

export async function evaluateIncidentWithAegis(incident: Incident): Promise<AegisReport> {
  const response = await fetch(`${AEGIS_URL}/walker/evaluate_sentinel_api`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ payload: incidentToAegisPayload(incident) }),
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) throw new Error(`AEGIS responded with HTTP ${response.status}`);

  const envelope = (await response.json()) as { data?: { reports?: AegisReport[] } };
  const report = envelope.data?.reports?.[0];
  if (!report || report.engine !== "AEGIS_FORKGUARD") throw new Error("AEGIS returned an invalid report");
  return report;
}

export async function getAegisHealth(): Promise<{ status: "ok" | "offline"; engine: "AEGIS_FORKGUARD"; url: string }> {
  try {
    const response = await fetch(`${AEGIS_URL}/healthz`, { signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return { status: "ok", engine: "AEGIS_FORKGUARD", url: AEGIS_URL };
  } catch {
    return { status: "offline", engine: "AEGIS_FORKGUARD", url: AEGIS_URL };
  }
}

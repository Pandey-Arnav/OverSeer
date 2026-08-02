import { getIncidents, updateIncident } from "../storage/store.ts";
import type { HardwareAssessment, HardwareVerdict, HidDeviceContext } from "../shared/types.ts";

const CORRELATION_WINDOW_MS = 2 * 60 * 1000;
const currentAssessments = new Map<string, HardwareAssessment>();
const VERDICT_PRIORITY: Record<HardwareVerdict, number> = {
  observing: 0,
  no_harmful_behavior_observed: 1,
  suspicious: 2,
  harmful: 3,
};

export function createHardwareAssessment(
  verdict: HardwareVerdict,
  reason: string,
  evidence: string[],
  confidence: HardwareAssessment["confidence"],
  now = new Date()
): HardwareAssessment {
  return { verdict, confidence, reason, evidence, assessedAt: now.toISOString() };
}

export function getCurrentHardwareAssessment(deviceKey: string): HardwareAssessment | null {
  return currentAssessments.get(deviceKey) ?? null;
}

export function strongerHardwareAssessment(
  current: HardwareAssessment | null,
  candidate: HardwareAssessment
): HardwareAssessment {
  if (!current) return candidate;
  return VERDICT_PRIORITY[current.verdict] > VERDICT_PRIORITY[candidate.verdict] ? current : candidate;
}

async function persistRecentAssessment(context: HidDeviceContext, assessment: HardwareAssessment): Promise<void> {
  const cutoff = Date.now() - CORRELATION_WINDOW_MS;
  const incident = (await getIncidents()).find(
    (candidate) =>
      candidate.category === "usb_hid_device" &&
      candidate.deviceKey === context.deviceKey &&
      new Date(candidate.timestamp).getTime() >= cutoff
  );
  if (incident) await updateIncident(incident.id, { hardwareAssessment: assessment });
}

/** Starts a fresh assessment window for a newly attached instance of the device. */
export async function beginHardwareObservation(context: HidDeviceContext, assessment: HardwareAssessment): Promise<void> {
  currentAssessments.set(context.deviceKey, assessment);
  await persistRecentAssessment(context, assessment);
}

/**
 * Stores the latest assessment in memory and updates the matching recent HID
 * attachment incident when it already exists. If the faster watcher wins the
 * race, usb-monitor.ts consumes the in-memory value when it logs the device.
 */
export async function recordHardwareAssessment(context: HidDeviceContext, assessment: HardwareAssessment): Promise<void> {
  const strongest = strongerHardwareAssessment(currentAssessments.get(context.deviceKey) ?? null, assessment);
  currentAssessments.set(context.deviceKey, strongest);
  await persistRecentAssessment(context, strongest);
}

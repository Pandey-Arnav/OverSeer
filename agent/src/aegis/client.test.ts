import test from "node:test";
import assert from "node:assert/strict";
import { incidentToAegisPayload } from "./client.ts";
import type { Incident } from "../shared/types.ts";

function usbIncident(): Incident {
  return {
    id: "usb-test-1",
    timestamp: new Date().toISOString(),
    category: "usb_storage_device",
    summary: "Private USB label — Microsoft Defender detected 1 threat",
    processName: null,
    processPath: "E:\\private\\never-forward.txt",
    remoteAddress: null,
    remotePort: null,
    deviceName: "Private USB label",
    pageOrigin: null,
    tamperedFieldNames: null,
    scriptFindings: null,
    score: 100,
    severity: "high",
    decision: "blocked",
    reasons: [{ ruleId: "defender-usb-threat", label: "Microsoft Defender reported a threat", points: 100 }],
    explanation: null,
    aegisReport: null,
    remediation: {
      available: true,
      action: "eject_device",
      reason: "Storage volume can be ejected",
      bsdName: "E:",
      applied: false,
      appliedAt: null,
    },
    defenderScanStatus: "threat_found",
    defenderThreatCount: 1,
  };
}

test("AEGIS receives bounded incident metadata and honest USB blockability", () => {
  const payload = incidentToAegisPayload(usbIncident());
  assert.equal(payload.eventType, "usb_scan_result");
  assert.equal(payload.blockable, false);
  assert.equal(payload.score, 100);
  assert.equal(payload.destinationOrigin, "hardware://usb_storage_device");
  const serialized = JSON.stringify(payload);
  assert.equal(serialized.includes("Private USB label"), false);
  assert.equal(serialized.includes("never-forward"), false);
  assert.equal(serialized.includes("E:"), false);
});

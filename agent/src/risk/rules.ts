/**
 * Sentinel Agent — risk rules.
 *
 * Each rule is a pure function: (event, context) => finding|null. Same
 * philosophy as the original browser-extension prototype: transparent,
 * additive, independently testable — no black-box scoring.
 */
import { RULE_WEIGHTS, SUSPICIOUS_PORTS, EVENT_CATEGORIES, TUNING } from "../shared/constants.ts";
import type { EvalContext, Rule, RuleFinding, SentinelEvent } from "../shared/types.ts";

function suspiciousPort(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.NETWORK_CONNECTION) return null;

  // A process *listening* on a known-bad port (a backdoor waiting for a
  // handler to connect in) is at least as strong a signal as an outbound
  // connection to one — check whichever port is actually relevant for
  // this connection's direction.
  const port = event.connectionState === "LISTEN" ? event.localPort : event.remotePort;
  if (port == null || !SUSPICIOUS_PORTS.has(port)) return null;

  const label =
    event.connectionState === "LISTEN"
      ? `Listening on a port historically associated with malware/backdoors (port ${port})`
      : `Connected to a port historically associated with malware/backdoors (port ${port})`;
  return { ruleId: "suspicious-port", label, points: RULE_WEIGHTS.SUSPICIOUS_PORT };
}

function unsignedProcess(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.NETWORK_CONNECTION || !event.process) return null;
  if (event.process.signed !== false) return null; // null (unknown) is not treated as a signal
  return {
    ruleId: "unsigned-process",
    label: `"${event.process.name}" is not code-signed at all`,
    points: RULE_WEIGHTS.UNSIGNED_PROCESS,
  };
}

function suspiciousProcessPath(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.NETWORK_CONNECTION || !event.process) return null;
  if (!event.process.suspiciousPath) return null;
  let points: number = RULE_WEIGHTS.SUSPICIOUS_PROCESS_PATH;
  let label = `"${event.process.name}" is running from a commonly-abused location (${event.process.execPath})`;
  if (event.process.signedAdhoc) {
    points += RULE_WEIGHTS.ADHOC_SIGNED_FROM_SUSPICIOUS_PATH;
    label += " and is only ad-hoc signed";
  }
  return { ruleId: "suspicious-process-path", label, points };
}

function unseenRemoteHost(event: SentinelEvent, context: EvalContext): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.NETWORK_CONNECTION || event.connectionState !== "ESTABLISHED") return null;
  if (!event.remoteAddress || !(context.seenRemoteHosts instanceof Set)) return null;
  const key = `${event.remoteAddress}:${event.remotePort ?? ""}`;
  if (context.seenRemoteHosts.has(key)) return null;
  return {
    ruleId: "unseen-remote-host",
    label: `First time this process has contacted ${event.remoteAddress}${event.remotePort ? `:${event.remotePort}` : ""}`,
    points: RULE_WEIGHTS.UNSEEN_REMOTE_HOST,
  };
}

function newListeningPort(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.NETWORK_CONNECTION || event.connectionState !== "LISTEN") return null;
  if (!event.isNewListeningPort) return null;
  return {
    ruleId: "new-listening-port",
    label: `"${event.process?.name ?? "A process"}" started listening on port ${event.localPort} — could be a backdoor/reverse-shell listener`,
    points: RULE_WEIGHTS.NEW_LISTENING_PORT,
  };
}

function multipleNewRemoteHosts(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.NETWORK_CONNECTION) return null;
  if (typeof event.distinctRemoteHostsInWindow !== "number") return null;
  if (event.distinctRemoteHostsInWindow < TUNING.MULTIPLE_NEW_HOSTS_COUNT) return null;
  return {
    ruleId: "multiple-new-remote-hosts",
    label: `"${event.process?.name ?? "A process"}" contacted ${event.distinctRemoteHostsInWindow} new destinations in quick succession — a beaconing/scanning pattern`,
    points: RULE_WEIGHTS.MULTIPLE_NEW_REMOTE_HOSTS,
  };
}

function newUsbDevice(event: SentinelEvent): RuleFinding | null {
  const weights: Partial<Record<string, number>> = {
    usb_storage_device: RULE_WEIGHTS.NEW_USB_STORAGE_DEVICE,
    usb_hid_device: RULE_WEIGHTS.NEW_USB_HID_DEVICE,
    usb_network_device: RULE_WEIGHTS.NEW_USB_NETWORK_DEVICE,
    usb_other_device: RULE_WEIGHTS.NEW_USB_OTHER_DEVICE,
  };
  const points = weights[event.category];
  if (points == null) return null;

  const kindLabel: Record<string, string> = {
    usb_storage_device: "storage device",
    usb_hid_device: "keyboard/mouse-class (HID) device",
    usb_network_device: "network-adapter device (possible MITM implant)",
    usb_other_device: "device",
  };

  return {
    ruleId: `new-${event.category}`,
    label: `New USB ${kindLabel[event.category]} connected: ${event.deviceName ?? "unknown device"}`,
    points,
  };
}

function defenderUsbFinding(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.USB_STORAGE_DEVICE) return null;
  if (event.defenderScanStatus === "threat_found") {
    const count = Math.max(1, event.defenderThreatCount ?? 1);
    return {
      ruleId: "defender-usb-threat",
      label: `Microsoft Defender reported ${count} threat${count === 1 ? "" : "s"} on the newly mounted USB volume`,
      points: RULE_WEIGHTS.DEFENDER_THREAT_FOUND,
    };
  }
  if (event.defenderScanStatus === "unavailable") {
    return {
      ruleId: "defender-usb-scan-unavailable",
      label: "Microsoft Defender could not complete the USB scan; treat the volume cautiously until it is scanned",
      points: RULE_WEIGHTS.DEFENDER_SCAN_UNAVAILABLE,
    };
  }
  return null;
}

// PAYMENT DETECTION: catches the classic banking-trojan / man-in-the-
// browser pattern where a script silently rewrites a payment field
// (recipient account, IBAN, wallet address, amount) after the user has
// already filled it in, right before submission — swapping the real
// destination for an attacker-controlled one without changing anything
// visible on screen. The browser extension tracks each payment-like
// field's last genuine `input`-event value; if the value at submit time
// differs from that with no intervening input event, the change happened
// via direct property assignment (`el.value = ...`), which doesn't fire
// `input` — a strong, low-ambiguity tampering signal reported here
// already-detected (see extension/src/content-script.ts), not
// re-derived from raw form data (the agent never sees actual field
// values, only which field names were flagged).
function transactionFieldTampering(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.TRANSACTION_TAMPERING) return null;
  if (!event.tamperedFieldNames || event.tamperedFieldNames.length === 0) return null;
  return {
    ruleId: "transaction-field-tampering",
    label: `Payment field(s) changed programmatically after the user filled them in: ${event.tamperedFieldNames.join(", ")}`,
    points: RULE_WEIGHTS.TRANSACTION_FIELD_TAMPERING,
  };
}

function badUsbKeystrokeTiming(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.USB_BADUSB_KEYSTROKE || !event.keystrokeStats) return null;
  return {
    ruleId: "badusb-keystroke-timing",
    label: `Honeypot input arrived at ${event.keystrokeStats.meanIntervalMs.toFixed(1)}ms/key with only ${event.keystrokeStats.stdDevMs.toFixed(1)}ms jitter — far more uniform than human typing, consistent with scripted HID injection (BadUSB)`,
    points: RULE_WEIGHTS.BADUSB_KEYSTROKE_TIMING,
  };
}

function suspiciousScript(event: SentinelEvent): RuleFinding | null {
  if (event.category !== EVENT_CATEGORIES.SUSPICIOUS_SCRIPT) return null;
  if (!event.scriptFindings || event.scriptFindings.length === 0) return null;
  return {
    ruleId: "suspicious-script-pattern",
    label: `Static analysis flagged: ${event.scriptFindings.join(", ")}`,
    points: RULE_WEIGHTS.SUSPICIOUS_SCRIPT_PATTERN * event.scriptFindings.length,
  };
}

export const RULES: Rule[] = [
  suspiciousPort,
  unsignedProcess,
  suspiciousProcessPath,
  unseenRemoteHost,
  newListeningPort,
  multipleNewRemoteHosts,
  newUsbDevice,
  defenderUsbFinding,
  transactionFieldTampering,
  badUsbKeystrokeTiming,
  suspiciousScript,
];

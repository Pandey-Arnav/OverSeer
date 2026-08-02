import type { Settings, EventCategory } from "./types.ts";

export const RULE_WEIGHTS = {
  SUSPICIOUS_PORT: 40,
  UNSIGNED_PROCESS: 45,
  SUSPICIOUS_PROCESS_PATH: 30,
  ADHOC_SIGNED_FROM_SUSPICIOUS_PATH: 15, // additive on top of SUSPICIOUS_PROCESS_PATH, not a replacement
  UNSEEN_REMOTE_HOST: 10,
  NEW_LISTENING_PORT: 35,
  MULTIPLE_NEW_REMOTE_HOSTS: 20,
  NEW_USB_STORAGE_DEVICE: 20,
  NEW_USB_HID_DEVICE: 25,
  NEW_USB_NETWORK_DEVICE: 35,
  NEW_USB_OTHER_DEVICE: 15,
  DEFENDER_THREAT_FOUND: 100,
  DEFENDER_SCAN_UNAVAILABLE: 25,
  // Deliberately alone enough to cross BLOCK (70) — a script-driven
  // rewrite of a recipient/amount/account field after the user has
  // already started editing it is a strong, low-ambiguity signal of
  // transaction manipulation, not a "maybe" like the additive rules
  // above.
  TRANSACTION_FIELD_TAMPERING: 95,
  BADUSB_KEYSTROKE_TIMING: 80,
  SUSPICIOUS_SCRIPT_PATTERN: 25, // per matched heuristic; additive across findings
} as const;

// 0-39 allow | 40-69 allow-and-warn | 70-100 action-recommended
export const THRESHOLDS = {
  WARN: 40,
  BLOCK: 70,
  MAX_SCORE: 100,
} as const;

export const SEVERITY = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
} as const;

export const DECISION = {
  ALLOW: "allow",
  WARN: "warn",
  BLOCKED: "blocked",
  DETECTED_NOT_BLOCKED: "detected_not_blocked",
} as const;

export const EVENT_CATEGORIES = {
  NETWORK_CONNECTION: "network_connection",
  USB_STORAGE_DEVICE: "usb_storage_device",
  USB_HID_DEVICE: "usb_hid_device",
  USB_NETWORK_DEVICE: "usb_network_device",
  USB_OTHER_DEVICE: "usb_other_device",
  USB_BADUSB_KEYSTROKE: "usb_badusb_keystroke",
  TRANSACTION_TAMPERING: "transaction_tampering",
  SUSPICIOUS_SCRIPT: "suspicious_script",
} as const satisfies Record<string, EventCategory>;

// Which categories have a *safe* remediation action at all. Whether it's
// actually offered for a specific incident also depends on
// isSafeToTerminate() (never offer to kill a root-owned or critical
// system process) — see remediation/actions.ts.
//
// transaction_tampering is included here too, but for a different
// reason than the other two: there's no *further* remediation to offer
// (the extension already froze the transaction client-side by the time
// this incident exists) — including it just makes decideAction() map a
// high score to "blocked" (meaning "already frozen") rather than
// "detected_not_blocked" (which would incorrectly imply nothing was done
// about it). See the Decision type doc comment in shared/types.ts.
export const REMEDIABLE_CATEGORIES: ReadonlySet<EventCategory> = new Set<EventCategory>([
  "network_connection",
  "usb_storage_device",
  "transaction_tampering",
]);

// Ports historically associated with malware C2/backdoors/remote-access
// tools. Not exhaustive — a known-bad-port hit is a strong but not
// infallible signal (legitimate services occasionally reuse these).
export const SUSPICIOUS_PORTS = new Set([
  1337, 31337, 4444, 5555, 6666, 6667, 6668, 6669, 12345, 12346, 20034, 27374, 54321, 1080, 9001, 9030,
]);

// Processes it is never safe to offer "terminate" for, even if owned by
// the current user — killing these can crash the session or the machine.
export const CRITICAL_PROCESS_NAMES = new Set([
  "launchd",
  "kernel_task",
  "WindowServer",
  "loginwindow",
  "syslogd",
  "coreaudiod",
  "SystemUIServer",
  "Finder",
  "cfprefsd",
  "logind",
  "securityd",
]);

export const TUNING = {
  NETWORK_POLL_INTERVAL_MS: 5000,
  USB_POLL_INTERVAL_MS: 3000,
  MULTIPLE_NEW_HOSTS_WINDOW_MS: 10_000,
  MULTIPLE_NEW_HOSTS_COUNT: 4,
  // Deliberately narrow: transient/world-writable staging locations and
  // running an executable straight out of Downloads without installing
  // it. An earlier version also flagged "any path containing a
  // dot-prefixed directory" to catch hidden-folder persistence — live
  // testing against this machine's real traffic immediately false-
  // positived on a legitimate Cloudflare `workerd` binary living under
  // `~/.superset/...`. Dot-directories (.npm, .cargo, .vscode, and any
  // number of tool-specific config/cache dirs) are completely ordinary
  // on real developer machines, so that pattern is not included here.
  SUSPICIOUS_PATH_PATTERNS: [/^\/tmp\//, /^\/var\/tmp\//, /^\/private\/tmp\//, /\/Downloads\//],
  // Matches common payment/transfer field identifiers (name/id/autocomplete/
  // placeholder) on a web page — used by the browser extension to scope
  // transaction-field-tampering tracking to fields that actually control
  // where money goes.
  PAYMENT_FIELD_PATTERN:
    /\b(account|iban|routing|swift|recipient|payee|beneficiary|wallet|address|amount|sum|total|transfer)\b/i,
  // Keystroke-timing thresholds for the BadUSB honeypot (see
  // monitors/keystroke-honeypot.ts): human typing has natural jitter;
  // scripted HID injection replays a pre-programmed sequence at
  // near-uniform, very fast intervals.
  BADUSB_MIN_KEY_COUNT: 6, // don't judge on too few samples
  BADUSB_MAX_MEAN_INTERVAL_MS: 30,
  BADUSB_MAX_STDDEV_MS: 8,
} as const;

export const DEFAULT_SETTINGS: Settings = {
  protectionEnabled: true,
  aiExplanationsEnabled: true,
};

export const MAX_STORED_INCIDENTS = 1000;

export const SERVER_PORT = Number(process.env["SENTINEL_PORT"]) || 4100;
export const SERVER_HOST = process.env["SENTINEL_HOST"] || "127.0.0.1";

// AI explanation upstream — same OpenAI-compatible contract as before.
export const OPENAI_BASE_URL = process.env["OPENAI_BASE_URL"] || "https://api.openai.com/v1";
export const OPENAI_MODEL = process.env["OPENAI_MODEL"] || "gpt-4o-mini";

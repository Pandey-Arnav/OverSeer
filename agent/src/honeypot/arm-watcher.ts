/**
 * Sentinel Agent — BadUSB honeypot arm watcher.
 *
 * Separate from usb-monitor.ts on purpose: usb-monitor.ts is about
 * incident logging and runs on a relaxed 3s cadence. This watcher is
 * about UX responsiveness — while honeypotArmed, it polls much faster
 * so the decoy terminal window can grab focus before a BadUSB script's
 * initial DELAY runs out and it starts typing into whatever's really
 * focused. usb-monitor.ts will still separately log the same device
 * attachment as a normal usb_hid_device incident on its own next tick.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { getSettings } from "../storage/store.ts";
import { listUsbDevices, type UsbDevice } from "../monitors/usb-monitor.ts";
import { SERVER_PORT } from "../shared/constants.ts";

const execFileAsync = promisify(execFile);

const CHROME_BINARY = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

async function launchHoneypotWindow(): Promise<void> {
  const url = `http://localhost:${SERVER_PORT}/honeypot.html`;
  try {
    // A dedicated --app= window has no browser chrome (no address bar/tabs
    // to click out of) and, launched fresh, takes keyboard focus.
    await execFileAsync(CHROME_BINARY, ["--new-window", `--app=${url}`]);
  } catch {
    try {
      await execFileAsync("open", [url]);
    } catch (err) {
      console.error("[Sentinel] failed to launch honeypot window:", (err as Error).message);
    }
  }
}

const knownKeys = new Set<string>();
let initialized = false;

export async function runArmWatcherTick(): Promise<void> {
  const settings = await getSettings();
  if (!settings.honeypotArmed) {
    // Re-baseline on disarm so re-arming later doesn't treat every
    // already-attached device as newly attached.
    initialized = false;
    knownKeys.clear();
    return;
  }

  const devices = await listUsbDevices();
  const currentKeys = new Set(devices.map((d) => d.key));

  if (!initialized) {
    currentKeys.forEach((k) => knownKeys.add(k));
    initialized = true;
    return;
  }

  const newKeyboard = devices.find((d) => d.category === "usb_hid_device" && !knownKeys.has(d.key));
  if (newKeyboard) {
    console.log(`[Sentinel] Honeypot armed: new keyboard-class device "${newKeyboard.name}" attached — launching decoy terminal`);
    void launchHoneypotWindow();
  }

  knownKeys.clear();
  currentKeys.forEach((k) => knownKeys.add(k));
}

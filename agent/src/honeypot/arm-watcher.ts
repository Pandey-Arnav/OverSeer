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
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { getSettings } from "../storage/store.ts";
import { listUsbHidDevices, type UsbDevice } from "../monitors/usb-monitor.ts";
import { SERVER_PORT } from "../shared/constants.ts";

const execFileAsync = promisify(execFile);

const CHROME_BINARY = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

function spawnDetached(command: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { detached: true, stdio: "ignore", windowsHide: false });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

export function windowsEdgeCandidates(environment: NodeJS.ProcessEnv): string[] {
  const candidates = [
    environment["ProgramFiles(x86)"] ? path.join(environment["ProgramFiles(x86)"], "Microsoft", "Edge", "Application", "msedge.exe") : null,
    environment["ProgramFiles"] ? path.join(environment["ProgramFiles"], "Microsoft", "Edge", "Application", "msedge.exe") : null,
    environment["LOCALAPPDATA"] ? path.join(environment["LOCALAPPDATA"], "Microsoft", "Edge", "Application", "msedge.exe") : null,
    "msedge.exe",
  ];
  return [...new Set(candidates.filter((candidate): candidate is string => Boolean(candidate)))];
}

async function launchWindowsHoneypot(url: string): Promise<void> {
  for (const edge of windowsEdgeCandidates(process.env)) {
    try {
      await spawnDetached(edge, ["--new-window", `--app=${url}`]);
      return;
    } catch {
      // Try the next standard Edge location before using the default browser.
    }
  }
  await execFileAsync("rundll32.exe", ["url.dll,FileProtocolHandler", url], { windowsHide: true });
}

async function launchHoneypotWindow(): Promise<void> {
  const url = `http://localhost:${SERVER_PORT}/honeypot.html`;
  if (process.platform === "win32") {
    try {
      await launchWindowsHoneypot(url);
    } catch (err) {
      console.error("[Sentinel] failed to launch Windows honeypot window:", (err as Error).message);
    }
    return;
  }

  try {
    // A dedicated --app= window has no browser chrome (no address bar/tabs
    // to click out of) and, launched fresh, takes keyboard focus.
    await execFileAsync(CHROME_BINARY, ["--new-window", `--app=${url}`]);
  } catch {
    try {
      if (process.platform === "darwin") await execFileAsync("open", [url]);
      else await execFileAsync("xdg-open", [url]);
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

  const devices = await listUsbHidDevices();
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

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
import { isSuspiciousHidSpawn, listWindowsProcesses } from "../monitors/windows-process-monitor.ts";
import { beginHardwareObservation, createHardwareAssessment, getCurrentHardwareAssessment, recordHardwareAssessment } from "../hardware/hid-assessment.ts";
import { SERVER_PORT } from "../shared/constants.ts";
import type { HidDeviceContext } from "../shared/types.ts";

const execFileAsync = promisify(execFile);

const CHROME_BINARY = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const HID_OBSERVATION_WINDOW_MS = 30_000;

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

function toDeviceContext(device: UsbDevice): HidDeviceContext {
  return {
    deviceKey: device.key,
    deviceName: device.name,
    vendorId: device.vendorId,
    productId: device.productId,
  };
}

async function launchHoneypotWindow(device: UsbDevice): Promise<void> {
  const localUrl = new URL(`http://localhost:${SERVER_PORT}/honeypot.html`);
  localUrl.searchParams.set("deviceKey", device.key);
  localUrl.searchParams.set("deviceName", device.name);
  if (device.vendorId) localUrl.searchParams.set("vendorId", device.vendorId);
  if (device.productId) localUrl.searchParams.set("productId", device.productId);
  const url = localUrl.toString();
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
const knownProcessIds = new Set<number>();
const activeObservations = new Map<string, { context: HidDeviceContext; expiresAt: number }>();
let initialized = false;

export async function runArmWatcherTick(): Promise<void> {
  const settings = await getSettings();
  if (!settings.honeypotArmed) {
    // Re-baseline on disarm so re-arming later doesn't treat every
    // already-attached device as newly attached.
    initialized = false;
    knownKeys.clear();
    knownProcessIds.clear();
    activeObservations.clear();
    return;
  }

  const [devices, processes] = await Promise.all([listUsbHidDevices(), listWindowsProcesses()]);
  const currentKeys = new Set(devices.map((d) => d.key));
  const currentProcessIds = new Set(processes.map((candidate) => candidate.pid));

  if (!initialized) {
    currentKeys.forEach((k) => knownKeys.add(k));
    currentProcessIds.forEach((pid) => knownProcessIds.add(pid));
    initialized = true;
    return;
  }

  const now = Date.now();
  const newKeyboards = devices.filter((device) => !knownKeys.has(device.key));
  for (const newKeyboard of newKeyboards) {
    const context = toDeviceContext(newKeyboard);
    activeObservations.set(newKeyboard.key, { context, expiresAt: now + HID_OBSERVATION_WINDOW_MS });
    await beginHardwareObservation(
      context,
      createHardwareAssessment(
        "observing",
        "Watching this newly attached keyboard-class device for scripted input and suspicious child processes.",
        ["new USB HID attachment"],
        "low",
        new Date(now)
      )
    );
    console.log(`[Sentinel] Honeypot armed: new keyboard-class device "${newKeyboard.name}" attached — launching decoy terminal`);
    void launchHoneypotWindow(newKeyboard);
  }

  const suspiciousSpawns = processes.filter(
    (candidate) => !knownProcessIds.has(candidate.pid) && isSuspiciousHidSpawn(candidate.name)
  );
  if (suspiciousSpawns.length > 0) {
    const evidence = suspiciousSpawns.map((candidate) => `new ${candidate.name} process (pid ${candidate.pid})`);
    for (const observation of activeObservations.values()) {
      if (observation.expiresAt < now) continue;
      if (getCurrentHardwareAssessment(observation.context.deviceKey)?.verdict === "harmful") continue;
      await recordHardwareAssessment(
        observation.context,
        createHardwareAssessment(
          "suspicious",
          "A shell or script-host process appeared immediately after the HID device was attached.",
          evidence,
          "medium",
          new Date(now)
        )
      );
    }
  }

  for (const [deviceKey, observation] of activeObservations) {
    if (observation.expiresAt > now) continue;
    if (getCurrentHardwareAssessment(deviceKey)?.verdict === "observing") {
      await recordHardwareAssessment(
        observation.context,
        createHardwareAssessment(
          "no_harmful_behavior_observed",
          "No harmful behavior was observed during the protected 30-second window. This is not a permanent trust guarantee.",
          ["observation window completed", "no suspicious shell or script-host process observed"],
          "medium",
          new Date(now)
        )
      );
    }
    activeObservations.delete(deviceKey);
  }

  knownKeys.clear();
  currentKeys.forEach((k) => knownKeys.add(k));
  knownProcessIds.clear();
  currentProcessIds.forEach((pid) => knownProcessIds.add(pid));
}

/**
 * Sentinel Agent — entry point.
 *
 * Starts the local dashboard/API server and the two monitors on their
 * own polling intervals. Meant to be run as a long-lived background
 * process (see launchd/ for the macOS LaunchAgent that keeps this
 * running across logins/crashes), but `npm start` in a terminal works
 * identically for development.
 */
import { startServer } from "./server/app.ts";
import { runNetworkMonitorTick } from "./monitors/network-monitor.ts";
import { runUsbMonitorTick } from "./monitors/usb-monitor.ts";
import { runArmWatcherTick } from "./honeypot/arm-watcher.ts";
import { TUNING } from "./shared/constants.ts";
import { dataDir } from "./storage/store.ts";
import { startAegisService, stopAegisService } from "./aegis/process.ts";

const ARM_WATCHER_POLL_INTERVAL_MS = 500;

console.log("Sentinel Agent starting…");
console.log(`Data directory: ${dataDir()}`);

startAegisService();
startServer();

async function tick(name: string, fn: () => Promise<{ length: number }>) {
  try {
    const incidents = await fn();
    if (incidents.length > 0) {
      console.log(`[Sentinel] ${name}: ${incidents.length} new incident(s) logged`);
    }
  } catch (err) {
    console.error(`[Sentinel] ${name} tick failed:`, (err as Error).message);
  }
}

setInterval(() => void tick("network monitor", runNetworkMonitorTick), TUNING.NETWORK_POLL_INTERVAL_MS);
setInterval(() => void tick("USB monitor", runUsbMonitorTick), TUNING.USB_POLL_INTERVAL_MS);
setInterval(() => {
  runArmWatcherTick().catch((err) => console.error("[Sentinel] honeypot arm watcher tick failed:", (err as Error).message));
}, ARM_WATCHER_POLL_INTERVAL_MS);

// Run once immediately on startup rather than waiting for the first interval.
void tick("network monitor", runNetworkMonitorTick);
void tick("USB monitor", runUsbMonitorTick);

process.on("SIGINT", () => {
  console.log("\nSentinel Agent shutting down.");
  stopAegisService();
  process.exit(0);
});
process.on("SIGTERM", () => {
  stopAegisService();
  process.exit(0);
});

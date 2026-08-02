"use strict";

const { GhostShieldApiClient } = require("./api-client");
const { agentId, discoverUsbVolumes } = require("./device-discovery");
const { scanWithDefender } = require("./defender-scanner");
const { inventoryVolume } = require("./volume-inventory");

const VERSION = "0.1.0";
const DEFAULT_POLL_MS = 5_000;

function emptyInventory() {
  return {
    totalFiles: 0,
    executableCount: 0,
    scriptCount: 0,
    shortcutCount: 0,
    archiveCount: 0,
    autorunPresent: false,
    truncated: true,
  };
}

function failedDefenderScan(status = "scan_failed") {
  return {
    available: false,
    completed: false,
    threatCount: 0,
    remediationSuccessful: false,
    status,
  };
}

function buildHardwareReport(identity, device, inventory, defender, startedAt, completedAt) {
  return {
    agentId: identity,
    device,
    inventory,
    defender,
    scanStartedAt: startedAt,
    scanCompletedAt: completedAt,
  };
}

class UsbAgent {
  constructor(options = {}) {
    this.identity = options.identity || agentId();
    this.client = options.client || new GhostShieldApiClient();
    this.discover = options.discover || discoverUsbVolumes;
    this.inventory = options.inventory || inventoryVolume;
    this.scan = options.scan || scanWithDefender;
    this.pollMs = options.pollMs || Number(process.env.GHOSTSHIELD_USB_POLL_MS) || DEFAULT_POLL_MS;
    this.known = new Map();
    this.running = false;
    this.status = "starting";
    this.scanQueue = Promise.resolve();
    this.timer = null;
  }

  async heartbeat() {
    try {
      await this.client.heartbeat({
        agentId: this.identity,
        status: this.status,
        currentVolumeCount: this.known.size,
        version: VERSION,
      });
    } catch (error) {
      console.warn(`[ghostshield-usb] API heartbeat unavailable: ${error.message}`);
    }
  }

  queueScan(device) {
    this.scanQueue = this.scanQueue
      .then(() => this.processDevice(device))
      .catch((error) => console.error(`[ghostshield-usb] Scan pipeline failed: ${error.message}`));
    return this.scanQueue;
  }

  async processDevice(device) {
    this.status = `scanning ${device.driveLetter}`;
    await this.heartbeat();
    const startedAt = new Date().toISOString();
    console.log(`[ghostshield-usb] USB volume detected: ${device.displayName} (${device.driveLetter})`);

    let inventory;
    try {
      inventory = await this.inventory(device.driveLetter);
    } catch (error) {
      console.warn(`[ghostshield-usb] Inventory failed: ${error.message}`);
      inventory = emptyInventory();
    }

    let defender;
    try {
      defender = await this.scan(device.driveLetter);
    } catch (error) {
      console.warn(`[ghostshield-usb] Defender scan failed: ${error.message}`);
      defender = failedDefenderScan();
    }

    const completedAt = new Date().toISOString();
    const report = buildHardwareReport(this.identity, device, inventory, defender, startedAt, completedAt);
    try {
      const response = await this.client.reportIncident(report);
      const incident = response.incident;
      console.log(`[ghostshield-usb] Scan complete: score ${incident.score}/100, decision ${incident.decision}`);
    } catch (error) {
      console.error(`[ghostshield-usb] Could not record scan result: ${error.message}`);
    }
    this.status = "monitoring";
    await this.heartbeat();
  }

  async poll({ scanNew = true } = {}) {
    const volumes = await this.discover();
    const currentKeys = new Set(volumes.map((volume) => volume.deviceIdHash));
    for (const knownKey of this.known.keys()) {
      if (!currentKeys.has(knownKey)) this.known.delete(knownKey);
    }
    for (const volume of volumes) {
      if (!this.known.has(volume.deviceIdHash)) {
        this.known.set(volume.deviceIdHash, volume);
        if (scanNew) this.queueScan(volume);
      } else {
        this.known.set(volume.deviceIdHash, volume);
      }
    }
    if (this.status === "starting") this.status = "monitoring";
    await this.heartbeat();
    return volumes;
  }

  async start(options = {}) {
    if (process.platform !== "win32") throw new Error("The GhostShield USB agent currently supports Windows only");
    if (this.running) return;
    this.running = true;
    await this.poll({ scanNew: options.scanExisting !== false });
    await this.scanQueue;
    if (options.once) {
      this.running = false;
      return;
    }
    this.timer = setInterval(async () => {
      if (!this.running) return;
      try {
        await this.poll();
      } catch (error) {
        this.status = "device discovery error";
        console.warn(`[ghostshield-usb] Device discovery failed: ${error.message}`);
        await this.heartbeat();
      }
    }, this.pollMs);
  }

  async stop() {
    this.running = false;
    if (this.timer) clearInterval(this.timer);
    this.status = "stopped";
    await this.heartbeat();
  }
}

async function main() {
  const once = process.argv.includes("--once");
  const agent = new UsbAgent();
  process.on("SIGINT", async () => {
    await agent.stop();
    process.exit(0);
  });
  process.on("SIGTERM", async () => {
    await agent.stop();
    process.exit(0);
  });
  await agent.start({ once, scanExisting: process.env.GHOSTSHIELD_SCAN_EXISTING_USB !== "0" });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[ghostshield-usb] Fatal error: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { UsbAgent, buildHardwareReport, emptyInventory, failedDefenderScan };

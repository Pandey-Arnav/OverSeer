/**
 * Sentinel Agent — USB device monitor.
 *
 * Polls `system_profiler SPUSBDataType -json` (verified against this
 * machine's real output — a nested tree of bus -> hub -> device objects)
 * and diffs the flattened device list against the previous snapshot so
 * only newly-attached devices are evaluated. Classification is
 * name-based (system_profiler doesn't expose the numeric USB device
 * class), which is a real limitation — see README known limitations.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { evaluateRisk, buildIncident } from "../risk/engine.ts";
import { addIncident, getSettings } from "../storage/store.ts";
import type { EventCategory, Incident, SentinelEvent } from "../shared/types.ts";

const execFileAsync = promisify(execFile);

interface UsbDeviceNode {
  _name?: string;
  vendor_id?: string;
  product_id?: string;
  location_id?: string;
  serial_num?: string;
  Media?: { bsd_name?: string }[];
  _items?: UsbDeviceNode[];
}

export interface UsbDevice {
  key: string; // stable-ish identity for diffing across polls
  name: string;
  vendorId?: string;
  productId?: string;
  category: EventCategory;
  bsdName: string | null;
}

interface DefenderScanResult {
  status: "clean" | "threat_found" | "unavailable";
  threatCount: number;
}

function classify(node: UsbDeviceNode): EventCategory {
  const name = (node._name || "").toLowerCase();
  if (node.Media && node.Media.length > 0) return "usb_storage_device";
  if (/keyboard|mouse|trackpad|\bhid\b/.test(name)) return "usb_hid_device";
  if (/ethernet|network adapter|wireless adapter|\blan\b/.test(name)) return "usb_network_device";
  return "usb_other_device";
}

function flattenDevices(nodes: UsbDeviceNode[] | undefined): UsbDevice[] {
  const devices: UsbDevice[] = [];
  if (!nodes) return devices;

  for (const node of nodes) {
    // Real peripherals carry a vendor_id; bus/hub structural nodes generally don't.
    if (node.vendor_id) {
      const bsdName = node.Media?.[0]?.bsd_name ?? null;
      devices.push({
        key: node.serial_num || node.location_id || `${node.vendor_id}:${node.product_id}:${node._name}`,
        name: node._name || "Unknown USB device",
        vendorId: node.vendor_id,
        productId: node.product_id,
        category: classify(node),
        bsdName,
      });
    }
    if (node._items) devices.push(...flattenDevices(node._items));
  }
  return devices;
}

async function listMacUsbDevices(): Promise<UsbDevice[]> {
  try {
    const { stdout } = await execFileAsync("system_profiler", ["SPUSBDataType", "-json"], {
      maxBuffer: 10 * 1024 * 1024,
    });
    const parsed = JSON.parse(stdout) as { SPUSBDataType?: UsbDeviceNode[] };
    return flattenDevices(parsed.SPUSBDataType);
  } catch (err) {
    console.error("[Sentinel] system_profiler USB scan failed:", (err as Error).message);
    return [];
  }
}

async function listWindowsUsbDevices(): Promise<UsbDevice[]> {
  const query = [
    "$ErrorActionPreference = 'Stop'",
    "$items = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' | Select-Object DeviceID,VolumeName,VolumeSerialNumber)",
    "ConvertTo-Json -InputObject $items -Compress",
  ].join("; ");
  try {
    const { stdout } = await execFileAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query], {
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });
    const parsed = JSON.parse(stdout || "[]") as Array<{ DeviceID?: string; VolumeName?: string; VolumeSerialNumber?: string }>;
    return parsed
      .filter((volume) => typeof volume.DeviceID === "string" && /^[A-Za-z]:$/.test(volume.DeviceID))
      .map((volume) => ({
        key: volume.VolumeSerialNumber || volume.DeviceID!,
        name: volume.VolumeName?.trim() || `Removable drive ${volume.DeviceID}`,
        category: "usb_storage_device" as const,
        bsdName: volume.DeviceID!,
      }));
  } catch (err) {
    console.error("[GhostShield] Windows USB discovery failed:", (err as Error).message);
    return [];
  }
}

async function listUsbDevices(): Promise<UsbDevice[]> {
  if (process.platform === "win32") return listWindowsUsbDevices();
  if (process.platform === "darwin") return listMacUsbDevices();
  return [];
}

async function scanWindowsVolume(deviceId: string): Promise<DefenderScanResult> {
  if (!/^[A-Za-z]:$/.test(deviceId)) return { status: "unavailable", threatCount: 0 };
  const root = `${deviceId.toUpperCase()}\\`;
  const scan = [
    "$ErrorActionPreference = 'Stop'",
    `Start-MpScan -ScanType CustomScan -ScanPath '${root}'`,
    "$cutoff = (Get-Date).AddMinutes(-10)",
    `$matches = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $cutoff -and (($_.Resources -join ' ') -like '*${root}*') })`,
    "[pscustomobject]@{ ThreatCount = $matches.Count } | ConvertTo-Json -Compress",
  ].join("; ");
  try {
    const { stdout } = await execFileAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", scan], {
      maxBuffer: 1024 * 1024,
      timeout: 10 * 60 * 1000,
      windowsHide: true,
    });
    const result = JSON.parse(stdout) as { ThreatCount?: number };
    const threatCount = Number(result.ThreatCount) || 0;
    return { status: threatCount > 0 ? "threat_found" : "clean", threatCount };
  } catch (err) {
    console.warn(`[GhostShield] Microsoft Defender could not scan ${deviceId}: ${(err as Error).message}`);
    return { status: "unavailable", threatCount: 0 };
  }
}

const knownDeviceKeys = new Set<string>();
let initialized = false;

/** Runs one poll cycle: lists USB devices, evaluates newly-attached ones, persists incidents. */
export async function runUsbMonitorTick(): Promise<Incident[]> {
  const settings = await getSettings();
  if (!settings.protectionEnabled) return [];

  const devices = await listUsbDevices();
  const currentKeys = new Set(devices.map((d) => d.key));
  const newIncidents: Incident[] = [];
  const now = Date.now();

  // First tick after startup: record the baseline without treating
  // already-connected devices (e.g. the built-in keyboard/trackpad) as
  // "newly attached" — only devices that appear in a *later* poll are novel.
  if (!initialized) {
    currentKeys.forEach((k) => knownDeviceKeys.add(k));
    initialized = true;
    return [];
  }

  for (const device of devices) {
    if (knownDeviceKeys.has(device.key)) continue;

    const defender =
      process.platform === "win32" && device.category === "usb_storage_device" && device.bsdName
        ? await scanWindowsVolume(device.bsdName)
        : null;

    const event: SentinelEvent = {
      category: device.category,
      timestamp: now,
      deviceName: device.name,
      vendorId: device.vendorId,
      productId: device.productId,
      bsdName: device.bsdName,
      defenderScanStatus: defender?.status,
      defenderThreatCount: defender?.threatCount,
    };
    const evaluation = evaluateRisk(event, {}, true);
    const remediation =
      device.category === "usb_storage_device" && device.bsdName
        ? { available: true, action: "eject_device" as const, reason: "Storage volumes can be safely ejected.", bsdName: device.bsdName, applied: false, appliedAt: null }
        : { available: false, action: null, reason: "No safe automated remediation for this device class — physical removal is the only reliable mitigation.", applied: false, appliedAt: null };

    const incident = buildIncident(event, evaluation, remediation, randomUUID(), new Date(now).toISOString());
    await addIncident(incident);
    newIncidents.push(incident);
  }

  knownDeviceKeys.clear();
  currentKeys.forEach((k) => knownDeviceKeys.add(k));

  return newIncidents;
}

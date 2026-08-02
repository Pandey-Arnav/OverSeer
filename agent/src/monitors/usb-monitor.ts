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
import { createHardwareAssessment, getCurrentHardwareAssessment } from "../hardware/hid-assessment.ts";
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

interface WindowsUsbRecord {
  Kind?: string;
  DeviceID?: string;
  VolumeName?: string;
  VolumeSerialNumber?: string;
  InstanceId?: string;
  Name?: string;
  Class?: string;
  ContainerId?: string;
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

function usbCategoryPriority(category: EventCategory): number {
  if (category === "usb_network_device") return 3;
  if (category === "usb_hid_device") return 2;
  return 1;
}

function classifyWindowsPnp(record: WindowsUsbRecord): EventCategory {
  const deviceClass = (record.Class || "").toLowerCase();
  const name = (record.Name || "").toLowerCase();
  if (deviceClass === "net" || /ethernet|network|wireless|\blan\b/.test(name)) return "usb_network_device";
  if (["keyboard", "mouse", "hidclass"].includes(deviceClass) || /keyboard|mouse|\bhid\b|input device/.test(name)) {
    return "usb_hid_device";
  }
  return "usb_other_device";
}

function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let field = "";
  let quoted = false;

  for (let index = 0; index < line.length; index++) {
    const character = line[index]!;
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        field += '"';
        index++;
      } else {
        quoted = !quoted;
      }
    } else if (character === "," && !quoted) {
      fields.push(field);
      field = "";
    } else {
      field += character;
    }
  }
  fields.push(field);
  return fields;
}

/** Parses the stable CSV output produced by `pnputil /enum-devices /connected /format csv`. */
export function parsePnputilUsbDevices(stdout: string): UsbDevice[] {
  const lines = stdout.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length < 2) return [];

  const headers = parseCsvLine(lines[0]!);
  const instanceIndex = headers.indexOf("InstanceId");
  const nameIndex = headers.indexOf("DeviceDescription");
  const classIndex = headers.indexOf("ClassName");
  if (instanceIndex < 0 || nameIndex < 0 || classIndex < 0) return [];

  const records: WindowsUsbRecord[] = [];
  for (const line of lines.slice(1)) {
    const fields = parseCsvLine(line);
    const instanceId = fields[instanceIndex];
    const deviceClass = fields[classIndex];
    if (!instanceId || !/^(USB|HID)\\VID_/i.test(instanceId)) continue;
    if (!deviceClass || !["keyboard", "mouse", "hidclass", "net"].includes(deviceClass.toLowerCase())) continue;
    records.push({
      Kind: "pnp",
      InstanceId: instanceId,
      Name: fields[nameIndex],
      Class: deviceClass,
    });
  }

  return parseWindowsUsbDevices(JSON.stringify(records));
}

/** Converts the bounded PowerShell snapshot into stable, de-duplicated USB devices. Exported for fixture tests. */
export function parseWindowsUsbDevices(stdout: string): UsbDevice[] {
  const decoded = JSON.parse(stdout || "[]") as WindowsUsbRecord | WindowsUsbRecord[] | null;
  const records = decoded == null ? [] : Array.isArray(decoded) ? decoded : [decoded];
  const devices = new Map<string, UsbDevice>();

  for (const record of records) {
    if (record.Kind === "storage") {
      if (typeof record.DeviceID !== "string" || !/^[A-Za-z]:$/.test(record.DeviceID)) continue;
      const deviceId = record.DeviceID.toUpperCase();
      const key = `volume:${record.VolumeSerialNumber || deviceId}`.toLowerCase();
      devices.set(key, {
        key,
        name: record.VolumeName?.trim() || `Removable drive ${deviceId}`,
        category: "usb_storage_device",
        bsdName: deviceId,
      });
      continue;
    }

    if (record.Kind !== "pnp" || typeof record.InstanceId !== "string") continue;
    if (!/^(USB|HID)\\VID_/i.test(record.InstanceId)) continue;

    const category = classifyWindowsPnp(record);
    const vendorId = record.InstanceId.match(/VID_([0-9A-F]{4})/i)?.[1]?.toUpperCase();
    const productId = record.InstanceId.match(/PID_([0-9A-F]{4})/i)?.[1]?.toUpperCase();
    // pnputil does not expose the Windows container ID. VID/PID is the
    // best privacy-preserving composite-device identity available in its
    // unprivileged CSV output and collapses a keyboard's USB + HID nodes.
    const identity = record.ContainerId?.trim() || (vendorId && productId ? `${vendorId}:${productId}` : record.InstanceId);
    const key = `pnp:${identity}`.toLowerCase();
    const device: UsbDevice = {
      key,
      name: record.Name?.trim() || (category === "usb_hid_device" ? "USB keyboard/HID device" : "USB device"),
      vendorId,
      productId,
      category,
      bsdName: null,
    };

    // Composite devices commonly expose both HIDClass and Keyboard nodes
    // with the same container ID. Keep one incident and prefer the category
    // carrying the stronger security signal.
    const existing = devices.get(key);
    if (!existing || usbCategoryPriority(device.category) > usbCategoryPriority(existing.category)) {
      devices.set(key, device);
    }
  }

  return [...devices.values()];
}

const WINDOWS_PNP_CACHE_MS = 350;
let cachedWindowsPnpSnapshot: { capturedAt: number; devices: UsbDevice[] } | null = null;
let windowsPnpScanInFlight: Promise<UsbDevice[]> | null = null;

async function listWindowsPnpDevices(): Promise<UsbDevice[]> {
  const now = Date.now();
  if (cachedWindowsPnpSnapshot && now - cachedWindowsPnpSnapshot.capturedAt <= WINDOWS_PNP_CACHE_MS) {
    return cachedWindowsPnpSnapshot.devices;
  }
  if (windowsPnpScanInFlight) return windowsPnpScanInFlight;

  windowsPnpScanInFlight = execFileAsync("pnputil.exe", ["/enum-devices", "/connected", "/format", "csv"], {
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true,
  }).then(({ stdout }) => parsePnputilUsbDevices(stdout));

  try {
    const devices = await windowsPnpScanInFlight;
    cachedWindowsPnpSnapshot = { capturedAt: Date.now(), devices };
    return devices;
  } finally {
    windowsPnpScanInFlight = null;
  }
}

async function listWindowsStorageDevices(): Promise<UsbDevice[]> {
  const query = [
    "$ErrorActionPreference = 'Stop'",
    "$records = [System.Collections.Generic.List[object]]::new()",
    "$volumes = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [System.IO.DriveType]::Removable })",
    "foreach ($volume in $volumes) { $label = $null; try { $label = $volume.VolumeLabel } catch {}; $records.Add([pscustomobject]@{ Kind = 'storage'; DeviceID = $volume.Name.Substring(0, 2); VolumeName = $label; VolumeSerialNumber = $null }) }",
    "ConvertTo-Json -InputObject @($records) -Depth 3 -Compress",
  ].join("; ");

  try {
    const { stdout } = await execFileAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query], {
      maxBuffer: 1024 * 1024,
      windowsHide: true,
    });
    return parseWindowsUsbDevices(stdout);
  } catch (err) {
    console.warn("[GhostShield] Windows removable-volume discovery failed:", (err as Error).message);
    return [];
  }
}

async function listWindowsUsbDevices(): Promise<UsbDevice[]> {
  const [pnpResult, storageResult] = await Promise.allSettled([listWindowsPnpDevices(), listWindowsStorageDevices()]);
  if (pnpResult.status === "rejected") {
    console.error("[GhostShield] Windows HID discovery failed:", pnpResult.reason instanceof Error ? pnpResult.reason.message : String(pnpResult.reason));
  }
  return [
    ...(pnpResult.status === "fulfilled" ? pnpResult.value : []),
    ...(storageResult.status === "fulfilled" ? storageResult.value : []),
  ];
}

export async function listUsbDevices(): Promise<UsbDevice[]> {
  if (process.platform === "win32") return listWindowsUsbDevices();
  if (process.platform === "darwin") return listMacUsbDevices();
  return [];
}

/** Fast path used by the armed watcher; it never waits for storage/Defender enumeration on Windows. */
export async function listUsbHidDevices(): Promise<UsbDevice[]> {
  const devices = process.platform === "win32" ? await listWindowsPnpDevices() : await listUsbDevices();
  return devices.filter((device) => device.category === "usb_hid_device");
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
      deviceKey: device.key,
      deviceName: device.name,
      vendorId: device.vendorId,
      productId: device.productId,
      hardwareAssessment:
        device.category === "usb_hid_device"
          ? getCurrentHardwareAssessment(device.key) ??
            createHardwareAssessment(
              "observing",
              "New keyboard-class hardware is being observed for scripted input and suspicious process activity.",
              ["new USB HID attachment"],
              "low",
              new Date(now)
            )
          : undefined,
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

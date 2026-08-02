"use strict";

const crypto = require("node:crypto");
const os = require("node:os");
const { runPowerShellJson } = require("./powershell");

const DISCOVERY_SCRIPT = `
$items = @()
Get-Disk -ErrorAction SilentlyContinue |
  Where-Object { $_.BusType -eq 'USB' } |
  ForEach-Object {
    $disk = $_
    Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
      Where-Object { $_.DriveLetter } |
      ForEach-Object {
        $partition = $_
        $volume = Get-Volume -DriveLetter $partition.DriveLetter -ErrorAction SilentlyContinue
        $items += [pscustomobject]@{
          rawIdentity = "$($disk.UniqueId)|$($disk.SerialNumber)|$($disk.Number)|$($partition.PartitionNumber)"
          driveLetter = "$($partition.DriveLetter):\\"
          volumeLabel = "$($volume.FileSystemLabel)"
          fileSystem = "$($volume.FileSystem)"
          sizeBytes = [long]$partition.Size
          manufacturer = "$($disk.Manufacturer)"
          model = "$($disk.FriendlyName)"
        }
      }
  }
ConvertTo-Json -InputObject @($items) -Compress -Depth 4
`;

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function sanitizeText(value, maximum = 80) {
  return String(value || "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, maximum);
}

function normalizeVolumes(rawVolumes) {
  const values = Array.isArray(rawVolumes) ? rawVolumes : rawVolumes ? [rawVolumes] : [];
  return values.flatMap((raw) => {
    const driveLetter = String(raw?.driveLetter || "").toUpperCase();
    if (!/^[A-Z]:\\$/.test(driveLetter)) return [];
    const volumeLabel = sanitizeText(raw.volumeLabel);
    const model = sanitizeText(raw.model);
    const manufacturer = sanitizeText(raw.manufacturer);
    const displayName = volumeLabel || [manufacturer, model].filter(Boolean).join(" ") || `USB volume ${driveLetter.slice(0, 2)}`;
    return [{
      deviceIdHash: sha256(raw.rawIdentity || `${driveLetter}|${displayName}`),
      driveLetter,
      displayName: displayName.slice(0, 160),
      fileSystem: sanitizeText(raw.fileSystem, 32) || "unknown",
      sizeBytes: Number.isSafeInteger(Number(raw.sizeBytes)) && Number(raw.sizeBytes) >= 0 ? Number(raw.sizeBytes) : 0,
      busType: "USB",
    }];
  });
}

async function discoverUsbVolumes() {
  const raw = await runPowerShellJson(DISCOVERY_SCRIPT, { timeoutMs: 30_000 });
  return normalizeVolumes(raw);
}

function agentId() {
  return sha256(`ghostshield|${os.hostname()}|${process.platform}|${process.arch}`);
}

module.exports = { discoverUsbVolumes, normalizeVolumes, agentId, sha256, sanitizeText };

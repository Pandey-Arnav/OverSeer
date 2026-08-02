"use strict";

const { quotePowerShell, runPowerShellJson } = require("./powershell");

async function scanWithDefender(driveRoot) {
  if (!/^[A-Z]:\\$/i.test(driveRoot)) throw new Error("Defender scan target must be a drive root");
  const target = quotePowerShell(driveRoot);
  const script = `
$target = ${target}
if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
  [pscustomobject]@{ available = $false; completed = $false; threatCount = 0; remediationSuccessful = $false; status = 'defender_cmdlet_unavailable' } | ConvertTo-Json -Compress
  exit 0
}
try {
  $started = Get-Date
  $detectionWindowStart = $started.AddMinutes(-5)
  Start-MpScan -ScanType CustomScan -ScanPath $target -ErrorAction Stop
  $matches = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
    $_.InitialDetectionTime -ge $detectionWindowStart -and ((@($_.Resources) -join '|') -like "*$target*")
  })
  $remediated = @($matches | Where-Object { $_.ActionSuccess -eq $true }).Count
  [pscustomobject]@{
    available = $true
    completed = $true
    threatCount = $matches.Count
    remediationSuccessful = ($matches.Count -eq 0 -or $remediated -eq $matches.Count)
    status = 'completed'
  } | ConvertTo-Json -Compress
} catch {
  [pscustomobject]@{ available = $true; completed = $false; threatCount = 0; remediationSuccessful = $false; status = 'scan_failed' } | ConvertTo-Json -Compress
}
`;
  const result = await runPowerShellJson(script, { timeoutMs: 30 * 60 * 1000 });
  return {
    available: result?.available === true,
    completed: result?.completed === true,
    threatCount: Number.isInteger(result?.threatCount) ? result.threatCount : 0,
    remediationSuccessful: result?.remediationSuccessful === true,
    status: typeof result?.status === "string" ? result.status : "unknown",
  };
}

module.exports = { scanWithDefender };

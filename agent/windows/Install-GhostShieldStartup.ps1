param()

$ErrorActionPreference = "Stop"
$taskName = "GhostShield Background Protection"
$aegisFirewallRule = "GhostShield AEGIS Local Only"
$dashboardFirewallRule = "GhostShield Dashboard Local Only"
$trayScript = (Resolve-Path (Join-Path $PSScriptRoot "GhostShield-Tray.ps1")).Path
$agentRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$powerShellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$trayScript`""

if (-not $env:LOCALAPPDATA) { throw "LOCALAPPDATA is unavailable, so the GhostShield Jac runtime cannot be located." }
$jacExecutable = Join-Path $env:LOCALAPPDATA "GhostShield\venv\Scripts\jac.exe"
if (-not (Test-Path (Join-Path $agentRoot "node_modules")) -or -not (Test-Path $jacExecutable)) {
  throw "GhostShield dependencies are not installed. Run Setup-GhostShield.ps1 first."
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this installer from an Administrator PowerShell window so it can protect GhostShield's local ports with Windows Firewall."
}

if (-not (Get-NetFirewallRule -DisplayName $aegisFirewallRule -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $aegisFirewallRule -Description "Blocks remote inbound access to GhostShield's local AEGIS Jac service." -Direction Inbound -Action Block -Protocol TCP -LocalPort 8012 -Profile Any | Out-Null
}
if (-not (Get-NetFirewallRule -DisplayName $dashboardFirewallRule -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName $dashboardFirewallRule -Description "Blocks remote inbound access to the GhostShield command center." -Direction Inbound -Action Block -Protocol TCP -LocalPort 4100 -Profile Any | Out-Null
}

$action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Starts GhostShield, AEGIS, and USB monitoring when the user signs in." -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "GhostShield background protection is installed and running."
Write-Host "Open http://127.0.0.1:4100 or use the shield icon in the Windows notification area."

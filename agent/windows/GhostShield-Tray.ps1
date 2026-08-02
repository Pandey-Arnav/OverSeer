param()

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$agentRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$localJac = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "GhostShield\venv\Scripts\jac.exe" } else { $null }
$dashboardUrl = "http://127.0.0.1:4100"
$healthUrl = "http://127.0.0.1:4100/health"
$aegisHealthUrl = "http://127.0.0.1:4100/api/aegis/health"
$stackProcess = $null

if (-not $env:JAC_EXECUTABLE -and $localJac -and (Test-Path $localJac)) { $env:JAC_EXECUTABLE = $localJac }
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

function Test-GhostShieldApi {
  try {
    $null = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
    return $true
  } catch { return $false }
}

function Start-GhostShieldStack {
  if (Test-GhostShieldApi) { return }
  $script:stackProcess = Start-Process -FilePath "npm.cmd" -ArgumentList @("start") -WorkingDirectory $agentRoot -WindowStyle Hidden -PassThru
}

function Stop-GhostShieldStack {
  if ($script:stackProcess -and -not $script:stackProcess.HasExited) {
    & taskkill.exe /PID $script:stackProcess.Id /T /F | Out-Null
  }
}

Start-GhostShieldStack

$context = New-Object System.Windows.Forms.ApplicationContext
$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
$notifyIcon.Text = "GhostShield protection"
$notifyIcon.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$statusItem = $menu.Items.Add("GhostShield is starting...")
$statusItem.Enabled = $false
$openItem = $menu.Items.Add("Open command center")
$restartItem = $menu.Items.Add("Restart protection")
$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$exitItem = $menu.Items.Add("Exit GhostShield")
$notifyIcon.ContextMenuStrip = $menu

$openAction = { Start-Process $dashboardUrl }
$openItem.add_Click($openAction)
$notifyIcon.add_DoubleClick($openAction)
$restartItem.add_Click({ Stop-GhostShieldStack; Start-Sleep -Seconds 1; Start-GhostShieldStack })
$exitItem.add_Click({ $notifyIcon.Visible = $false; Stop-GhostShieldStack; $context.ExitThread() })

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 5000
$timer.add_Tick({
  try {
    $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
    $aegisOnline = $false
    try { $aegisOnline = (Invoke-RestMethod -Uri $aegisHealthUrl -TimeoutSec 2).status -eq "ok" } catch {}
    $statusItem.Text = if ($aegisOnline) { "Protection active - AEGIS online" } else { "Protection active - AEGIS offline" }
    $notifyIcon.Text = if ($health.protectionEnabled) { "GhostShield - protection active" } else { "GhostShield - protection paused" }
  } catch {
    $statusItem.Text = "GhostShield service offline"
    $notifyIcon.Text = "GhostShield - service offline"
  }
})
$timer.Start()

$notifyIcon.BalloonTipTitle = "GhostShield is running"
$notifyIcon.BalloonTipText = "Network, USB, Defender, and AEGIS monitoring are active in the background."
$notifyIcon.ShowBalloonTip(4000)

try { [System.Windows.Forms.Application]::Run($context) } finally { $timer.Stop(); $notifyIcon.Dispose() }

param()

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$serverRoot = Join-Path $projectRoot "server"
$localJac = if ($env:LOCALAPPDATA) {
  Join-Path $env:LOCALAPPDATA "GhostShield\venv\Scripts\jac.exe"
} else {
  $null
}
$dashboardUrl = "http://127.0.0.1:4000/ghostshield/dashboard/dashboard.html"
$healthUrl = "http://127.0.0.1:4000/api/hardware/health"
$stackProcess = $null

if (-not $env:JAC_EXECUTABLE -and $localJac -and (Test-Path $localJac)) {
  $env:JAC_EXECUTABLE = $localJac
}
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

function Test-GhostShieldApi {
  try {
    $null = Invoke-RestMethod -Uri "http://127.0.0.1:4000/health" -TimeoutSec 2
    return $true
  } catch {
    return $false
  }
}

function Start-GhostShieldStack {
  if (Test-GhostShieldApi) { return }
  $script:stackProcess = Start-Process -FilePath "npm.cmd" `
    -ArgumentList @("run", "start:full") `
    -WorkingDirectory $serverRoot `
    -WindowStyle Hidden `
    -PassThru
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
$notifyIcon.Text = "GhostShield USB protection"
$notifyIcon.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$statusItem = $menu.Items.Add("GhostShield is starting...")
$statusItem.Enabled = $false
$openItem = $menu.Items.Add("Open command center")
$rescanItem = $menu.Items.Add("Rescan connected USB drives")
$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
$exitItem = $menu.Items.Add("Exit GhostShield")
$notifyIcon.ContextMenuStrip = $menu

$openAction = {
  Start-Process $dashboardUrl
}
$openItem.add_Click($openAction)
$notifyIcon.add_DoubleClick($openAction)

$rescanItem.add_Click({
  Start-Process -FilePath "npm.cmd" `
    -ArgumentList @("run", "agent:usb:once") `
    -WorkingDirectory $serverRoot `
    -WindowStyle Hidden
  $notifyIcon.BalloonTipTitle = "GhostShield"
  $notifyIcon.BalloonTipText = "A USB rescan has started. Results will appear in the command center."
  $notifyIcon.ShowBalloonTip(3500)
})

$exitItem.add_Click({
  $notifyIcon.Visible = $false
  Stop-GhostShieldStack
  $context.ExitThread()
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 5000
$timer.add_Tick({
  try {
    $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
    if ($health.online) {
      $agent = $health.agents | Where-Object { $_.online } | Select-Object -First 1
      $statusItem.Text = "USB agent: $($agent.status)"
      $notifyIcon.Text = "GhostShield - USB agent online"
    } else {
      $statusItem.Text = "USB agent: waiting"
      $notifyIcon.Text = "GhostShield - USB agent waiting"
    }
  } catch {
    $statusItem.Text = "GhostShield service offline"
    $notifyIcon.Text = "GhostShield - service offline"
  }
})
$timer.Start()

$notifyIcon.BalloonTipTitle = "GhostShield is running"
$notifyIcon.BalloonTipText = "Browser and USB monitoring are active in the background."
$notifyIcon.ShowBalloonTip(4000)

try {
  [System.Windows.Forms.Application]::Run($context)
} finally {
  $timer.Stop()
  $notifyIcon.Dispose()
}

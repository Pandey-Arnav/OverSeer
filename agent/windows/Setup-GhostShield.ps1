param()

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$serverRoot = Join-Path $projectRoot "server"

if (-not $env:LOCALAPPDATA) {
  throw "LOCALAPPDATA is unavailable, so GhostShield cannot create its per-user runtime."
}

$runtimeRoot = Join-Path $env:LOCALAPPDATA "GhostShield"
$venvRoot = Join-Path $runtimeRoot "venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$jacExecutable = Join-Path $venvRoot "Scripts\jac.exe"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

function Invoke-CheckedCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [Parameter(Mandatory = $true)]
    [string[]]$ArgumentList,
    [Parameter(Mandatory = $true)]
    [string]$Description
  )

  & $FilePath @ArgumentList
  if ($LASTEXITCODE -ne 0) {
    throw "$Description failed with exit code $LASTEXITCODE. GhostShield setup did not complete."
  }
}

if (-not (Get-Command node.exe -ErrorAction SilentlyContinue)) {
  throw "Node.js is required. Install Node.js 20 or newer, then run this setup again."
}
if (-not (Get-Command py.exe -ErrorAction SilentlyContinue) -and -not (Get-Command python.exe -ErrorAction SilentlyContinue)) {
  throw "Python 3.12 or newer is required to run AEGIS Jac."
}

New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

if (-not (Test-Path $venvPython)) {
  if (Get-Command py.exe -ErrorAction SilentlyContinue) {
    Invoke-CheckedCommand -FilePath "py.exe" -ArgumentList @("-3.12", "-m", "venv", $venvRoot) -Description "Creating the GhostShield Python environment"
  } else {
    Invoke-CheckedCommand -FilePath "python.exe" -ArgumentList @("-m", "venv", $venvRoot) -Description "Creating the GhostShield Python environment"
  }
}

Invoke-CheckedCommand -FilePath $venvPython -ArgumentList @("-m", "pip", "install", "--upgrade", "pip") -Description "Updating pip"
Invoke-CheckedCommand -FilePath $venvPython -ArgumentList @("-m", "pip", "install", "jaclang==0.16.7", "jaseci==2.3.28") -Description "Installing Jac and Jaseci"
Invoke-CheckedCommand -FilePath "npm.cmd" -ArgumentList @("install", "--prefix", $serverRoot) -Description "Installing GhostShield server dependencies"

if (-not (Test-Path $jacExecutable)) {
  throw "Jac was not installed at $jacExecutable. GhostShield setup did not complete."
}

$verifyPackages = "import importlib.metadata as m; import jaclang, jaseci; print('jaclang=' + m.version('jaclang')); print('jaseci=' + m.version('jaseci'))"
Invoke-CheckedCommand -FilePath $venvPython -ArgumentList @("-c", $verifyPackages) -Description "Verifying Jac and Jaseci"

Write-Host "GhostShield dependencies are installed."
Write-Host "Jac runtime: $venvRoot"
Write-Host "Next: run Install-GhostShieldStartup.ps1 to start protection at sign-in."

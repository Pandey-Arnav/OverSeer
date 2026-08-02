param()

$ErrorActionPreference = "Stop"
$taskName = "GhostShield Background Protection"
$firewallRuleName = "GhostShield AEGIS Local Only"

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
  Write-Host "GhostShield background startup was removed."
} else {
  Write-Host "GhostShield background startup is not installed."
}

Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule -ErrorAction SilentlyContinue

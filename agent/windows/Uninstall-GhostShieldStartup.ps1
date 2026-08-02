param()

$ErrorActionPreference = "Stop"
$taskName = "GhostShield Background Protection"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
foreach ($rule in @("GhostShield AEGIS Local Only", "GhostShield Dashboard Local Only")) {
  Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
Write-Host "GhostShield automatic startup and firewall rules were removed. Local incident data was preserved."

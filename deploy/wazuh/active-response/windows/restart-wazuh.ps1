$ErrorActionPreference = "Stop"
. "$PSScriptRoot\c2f-actions.ps1"

$knownActions = @(
  "firewall-drop",
  "host-deny",
  "netsh",
  "route-null",
  "win_route-null",
  "kill-process",
  "quarantine-file",
  "malware-scan",
  "sca-rescan",
  "restart-wazuh",
  "patch-linux",
  "patch-windows",
  "collect-forensics",
  "disable-account",
  "ioc-scan",
  "yara-scan",
  "collect-memory",
  "hash-blocklist",
  "service-restart",
  "threat-hunt-persistence",
  "rollback-kb"
)

if ($args -and $args.Count -gt 0 -and $knownActions -contains "$($args[0])") {
  $actionName = "$($args[0])"
  $forwardArgs = @()
  if ($args.Count -gt 1) {
    $forwardArgs = $args[1..($args.Count - 1)]
  }
  Invoke-C2FAction -ActionName $actionName -CliArgs $forwardArgs
}
else {
  # Backward compatible: treat restart wrapper as restart action.
  Invoke-C2FAction -ActionName "restart-wazuh" -CliArgs $args
}

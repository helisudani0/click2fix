$ErrorActionPreference = "Stop"

. "$PSScriptRoot\c2f-common.ps1"
. "$PSScriptRoot\c2f-actions.ps1"

if (-not $args -or $args.Count -lt 1 -or [string]::IsNullOrWhiteSpace("$($args[0])")) {
  Write-C2FLog -Action "c2f-runner" -Message "Failed: missing action argument"
  exit 1
}

$actionName = "$($args[0])"
$forwardArgs = @()
if ($args.Count -gt 1) {
  $forwardArgs = $args[1..($args.Count - 1)]
}

Invoke-C2FAction -ActionName $actionName -CliArgs $forwardArgs

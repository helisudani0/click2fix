$ErrorActionPreference = "Stop"
. "$PSScriptRoot\c2f-actions.ps1"
Invoke-C2FAction -ActionName "collect-memory" -CliArgs $args

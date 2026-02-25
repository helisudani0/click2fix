$ErrorActionPreference = "Stop"
. "$PSScriptRoot\c2f-actions.ps1"
Invoke-C2FAction -ActionName "rollback-kb" -CliArgs $args

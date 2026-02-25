$ErrorActionPreference = "Stop"
. "$PSScriptRoot\c2f-actions.ps1"
Invoke-C2FAction -ActionName "sca-rescan" -CliArgs $args

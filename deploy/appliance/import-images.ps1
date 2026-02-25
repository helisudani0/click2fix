param(
  [string]$InputFile = "click2fix-images.tar"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$inputPath = Join-Path $scriptDir $InputFile

if (-not (Test-Path $inputPath)) {
  throw "Image bundle not found: $inputPath"
}

Write-Host "Importing images from $inputPath ..."
docker load -i $inputPath
Write-Host "Import complete."

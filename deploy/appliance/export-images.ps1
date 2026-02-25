param(
  [string]$EnvFile = ".env.appliance",
  [string]$OutputFile = "click2fix-images.tar"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $scriptDir $EnvFile
$outputPath = Join-Path $scriptDir $OutputFile

function Get-EnvValue {
  param(
    [string]$Path,
    [string]$Key,
    [string]$Default = ""
  )
  if (-not (Test-Path $Path)) { return $Default }
  $line = (Get-Content -Path $Path | Where-Object { $_ -match "^\s*$Key=" } | Select-Object -First 1)
  if (-not $line) { return $Default }
  $value = ($line -replace "^\s*$Key=", "")
  if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
  return $value
}

$backendImage = Get-EnvValue -Path $envPath -Key "C2F_BACKEND_IMAGE" -Default "click2fix-backend"
$frontendImage = Get-EnvValue -Path $envPath -Key "C2F_FRONTEND_IMAGE" -Default "click2fix-frontend"
$imageTag = Get-EnvValue -Path $envPath -Key "C2F_IMAGE_TAG" -Default "local"

docker image inspect "$backendImage`:$imageTag" | Out-Null
docker image inspect "$frontendImage`:$imageTag" | Out-Null

Write-Host "Exporting images to $outputPath ..."
docker save -o $outputPath "$backendImage`:$imageTag" "$frontendImage`:$imageTag"
Write-Host "Export complete."

param(
  [string]$EnvFile = ".env.appliance"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Resolve-Path (Join-Path $scriptDir "../..")
$envPath = Join-Path $scriptDir $EnvFile

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
$agentManagerImage = Get-EnvValue -Path $envPath -Key "C2F_AGENT_MANAGER_IMAGE" -Default "click2fix-agent-manager"
$eventIndexerImage = Get-EnvValue -Path $envPath -Key "C2F_EVENT_INDEXER_IMAGE" -Default "click2fix-event-indexer"
$imageTag = Get-EnvValue -Path $envPath -Key "C2F_IMAGE_TAG" -Default "local"

Write-Host "Building local appliance images..."
Write-Host "  Backend:  $backendImage`:$imageTag"
Write-Host "  Frontend: $frontendImage`:$imageTag"
Write-Host "  Agent Manager: $agentManagerImage`:$imageTag"
Write-Host "  Event Indexer: $eventIndexerImage`:$imageTag"

docker build -f "$rootDir/docker/backend.Dockerfile" -t "$backendImage`:$imageTag" "$rootDir"
docker build -f "$rootDir/docker/frontend.Dockerfile" -t "$frontendImage`:$imageTag" "$rootDir"
docker build -f "$rootDir/docker/agent-manager.Dockerfile" -t "$agentManagerImage`:$imageTag" "$rootDir"
docker build -f "$rootDir/docker/event-indexer.Dockerfile" -t "$eventIndexerImage`:$imageTag" "$rootDir"

Write-Host "Build complete."

param(
  [string]$EnvFile = ".env.appliance",
  [string]$ComposeFile = "docker-compose.appliance.yml"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $scriptDir $EnvFile
$composePath = Join-Path $scriptDir $ComposeFile

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker is not installed."
}
docker compose version | Out-Null

if (-not (Test-Path $envPath)) {
  throw "Missing $envPath. Run install.ps1 first."
}

Write-Host "Pulling configured images..."
docker compose --env-file $envPath -f $composePath pull

Write-Host "Applying upgrade..."
docker compose --env-file $envPath -f $composePath up -d

Write-Host "Upgrade complete."
Write-Host "Check status:"
Write-Host "  docker compose --env-file $envPath -f $composePath ps"

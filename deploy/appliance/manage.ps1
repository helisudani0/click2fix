param(
  [string]$EnvFile = ".env.appliance",
  [string]$ComposeFile = "docker-compose.appliance.yml"
)

$ErrorActionPreference = "Stop"

function Invoke-NativeChecked {
  param(
    [string]$FilePath,
    [string[]]$Arguments = @(),
    [string]$FailureMessage = "Command failed."
  )
  & $FilePath @Arguments
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) {
    throw "$FailureMessage Exit code: $exitCode"
  }
}

function Ensure-DockerEngine {
  try {
    Invoke-NativeChecked -FilePath "docker" -Arguments @("info") -FailureMessage "Docker engine check failed."
  } catch {
    throw "Docker engine is not running. Start Docker Desktop (Linux containers mode), wait until it is Running, then retry."
  }
}

function Get-EnvValue {
  param(
    [string]$Path,
    [string]$Key
  )
  if (-not (Test-Path $Path)) { return "" }
  $line = (Get-Content -Path $Path | Where-Object { $_ -match "^\s*$Key=" } | Select-Object -First 1)
  if (-not $line) { return "" }
  return ($line -replace "^\s*$Key=", "")
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $scriptDir $EnvFile
$composePath = Join-Path $scriptDir $ComposeFile
$installScript = Join-Path $scriptDir "install.ps1"
$upgradeScript = Join-Path $scriptDir "upgrade.ps1"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker is not installed."
}
Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "version") -FailureMessage "Docker Compose plugin is required."
Ensure-DockerEngine

function Show-Menu {
  Write-Host ""
  Write-Host "== Click2Fix Appliance Control Center ==" -ForegroundColor Cyan
  Write-Host "1) First-time install / reconfigure"
  Write-Host "2) Start services"
  Write-Host "3) Stop services"
  Write-Host "4) Restart services"
  Write-Host "5) Show status"
  Write-Host "6) Tail backend logs"
  Write-Host "7) Upgrade images and restart"
  Write-Host "8) Show access URLs"
  Write-Host "9) Exit"
}

while ($true) {
  Show-Menu
  $choice = Read-Host "Select option"
  try {
    switch ($choice) {
      "1" {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $installScript -EnvFile $EnvFile -ComposeFile $ComposeFile
      }
      "2" {
        Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "--env-file", $envPath, "-f", $composePath, "up", "-d") -FailureMessage "Failed to start services."
      }
      "3" {
        Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "--env-file", $envPath, "-f", $composePath, "stop") -FailureMessage "Failed to stop services."
      }
      "4" {
        Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "--env-file", $envPath, "-f", $composePath, "restart") -FailureMessage "Failed to restart services."
      }
      "5" {
        Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "--env-file", $envPath, "-f", $composePath, "ps") -FailureMessage "Failed to get status."
      }
      "6" {
        & docker compose --env-file $envPath -f $composePath logs -f backend
      }
      "7" {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $upgradeScript -EnvFile $EnvFile -ComposeFile $ComposeFile
      }
      "8" {
        $publicHost = Get-EnvValue -Path $envPath -Key "C2F_PUBLIC_HOST"
        if ([string]::IsNullOrWhiteSpace($publicHost)) { $publicHost = "localhost" }
        $frontendPort = Get-EnvValue -Path $envPath -Key "C2F_FRONTEND_PORT"
        if ([string]::IsNullOrWhiteSpace($frontendPort)) { $frontendPort = "5173" }
        $backendPort = Get-EnvValue -Path $envPath -Key "C2F_BACKEND_PORT"
        if ([string]::IsNullOrWhiteSpace($backendPort)) { $backendPort = "8000" }
        Write-Host "UI URL: http://$publicHost`:$frontendPort"
        Write-Host "Backend API/docs: http://$publicHost`:$backendPort/docs"
        Write-Host "Backend Ops: http://$publicHost`:$backendPort/ops"
      }
      "9" { break }
      default { Write-Host "Invalid choice." -ForegroundColor Yellow }
    }
  } catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
  }
}

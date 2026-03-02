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

function Set-EnvValue {
  param(
    [string]$Path,
    [string]$Key,
    [string]$Value
  )
  if (-not (Test-Path $Path)) {
    New-Item -ItemType File -Path $Path | Out-Null
  }
  $lines = Get-Content -Path $Path -ErrorAction SilentlyContinue
  $found = $false
  $updated = @()
  foreach ($line in $lines) {
    if ($line -match "^\s*$Key=") {
      $updated += "$Key=$Value"
      $found = $true
    } else {
      $updated += $line
    }
  }
  if (-not $found) {
    $updated += "$Key=$Value"
  }
  Set-Content -Path $Path -Value $updated
}

function Test-PortInUse {
  param([int]$Port)
  try {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop
    return ($null -ne ($listeners | Select-Object -First 1))
  } catch {
    return $false
  }
}

function Test-PortOwnedByContainer {
  param(
    [int]$Port,
    [string]$ContainerName
  )
  $ports = & docker ps --filter "name=^$ContainerName$" --format "{{.Ports}}" 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $ports) { return $false }
  $joined = ($ports | Select-Object -First 1)
  return [regex]::IsMatch($joined, "[:.]$Port->")
}

function Find-FreePort {
  param(
    [int]$StartPort,
    [int]$MaxTries = 200
  )
  $candidate = $StartPort
  for ($i = 0; $i -lt $MaxTries; $i++) {
    if (-not (Test-PortInUse -Port $candidate)) {
      return $candidate
    }
    $candidate++
  }
  throw "No free port found starting at $StartPort after $MaxTries attempts."
}

function Parse-PortOrDefault {
  param(
    [string]$RawValue,
    [int]$DefaultPort
  )
  $parsed = 0
  if ([int]::TryParse($RawValue, [ref]$parsed) -and $parsed -gt 0 -and $parsed -lt 65536) {
    return $parsed
  }
  return $DefaultPort
}

function Resolve-PortConflicts {
  param([string]$EnvPath)
  if (-not (Test-Path $EnvPath)) { return }

  $publicHost = Get-EnvValue -Path $EnvPath -Key "C2F_PUBLIC_HOST"
  if ([string]::IsNullOrWhiteSpace($publicHost)) { $publicHost = "localhost" }
  $frontendRaw = Get-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT"
  $backendRaw = Get-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT"
  $dbRaw = Get-EnvValue -Path $EnvPath -Key "C2F_DB_PORT"
  $frontendPort = Parse-PortOrDefault -RawValue $frontendRaw -DefaultPort 5173
  $backendPort = Parse-PortOrDefault -RawValue $backendRaw -DefaultPort 8000
  $dbPort = Parse-PortOrDefault -RawValue $dbRaw -DefaultPort 5432
  $oldFrontendPort = $frontendPort
  $changed = $false

  if ((Test-PortInUse -Port $backendPort) -and -not (Test-PortOwnedByContainer -Port $backendPort -ContainerName "c2f-backend")) {
    $newBackend = Find-FreePort -StartPort ($backendPort + 1)
    Write-Host "Port $backendPort is in use. Reassigning backend to $newBackend." -ForegroundColor Yellow
    $backendPort = $newBackend
    Set-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT" -Value "$backendPort"
    $changed = $true
  }

  if ((Test-PortInUse -Port $frontendPort) -and -not (Test-PortOwnedByContainer -Port $frontendPort -ContainerName "c2f-frontend")) {
    $newFrontend = Find-FreePort -StartPort ($frontendPort + 1)
    Write-Host "Port $frontendPort is in use. Reassigning frontend to $newFrontend." -ForegroundColor Yellow
    $frontendPort = $newFrontend
    Set-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT" -Value "$frontendPort"
    $changed = $true
  }

  if ((Test-PortInUse -Port $dbPort) -and -not (Test-PortOwnedByContainer -Port $dbPort -ContainerName "c2f-db")) {
    $newDb = Find-FreePort -StartPort ($dbPort + 1)
    Write-Host "Port $dbPort is in use. Reassigning db host port to $newDb." -ForegroundColor Yellow
    $dbPort = $newDb
    Set-EnvValue -Path $EnvPath -Key "C2F_DB_PORT" -Value "$dbPort"
    $changed = $true
  }

  if ($frontendPort -ne $oldFrontendPort) {
    Set-EnvValue -Path $EnvPath -Key "C2F_CORS_ORIGINS" -Value "http://$publicHost`:$frontendPort"
    $changed = $true
  }

  if ($changed) {
    Write-Host "Updated $EnvPath with conflict-free port bindings." -ForegroundColor Yellow
  }
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
        Resolve-PortConflicts -EnvPath $envPath
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
        Resolve-PortConflicts -EnvPath $envPath
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

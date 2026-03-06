param(
  [string]$EnvFile = ".env.appliance",
  [string]$ComposeFile = "docker-compose.appliance.yml"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $scriptDir $EnvFile
$composePath = Join-Path $scriptDir $ComposeFile

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

function To-Bool {
  param(
    [string]$RawValue,
    [bool]$Default = $false
  )
  if ([string]::IsNullOrWhiteSpace($RawValue)) { return $Default }
  switch ($RawValue.Trim().ToLowerInvariant()) {
    "1" { return $true }
    "true" { return $true }
    "yes" { return $true }
    "on" { return $true }
    "0" { return $false }
    "false" { return $false }
    "no" { return $false }
    "off" { return $false }
    default { return $Default }
  }
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

function Resolve-PortConflicts {
  param([string]$EnvPath)
  if (-not (Test-Path $EnvPath)) { return }

  $publicHost = Get-EnvValue -Path $EnvPath -Key "C2F_PUBLIC_HOST"
  if ([string]::IsNullOrWhiteSpace($publicHost)) { $publicHost = "localhost" }
  $frontendPort = Parse-PortOrDefault -RawValue (Get-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT") -DefaultPort 5173
  $backendPort = Parse-PortOrDefault -RawValue (Get-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT") -DefaultPort 8000
  $dbPort = Parse-PortOrDefault -RawValue (Get-EnvValue -Path $EnvPath -Key "C2F_DB_PORT") -DefaultPort 5432
  $oldFrontendPort = $frontendPort

  if ((Test-PortInUse -Port $backendPort) -and -not (Test-PortOwnedByContainer -Port $backendPort -ContainerName "c2f-backend")) {
    $backendPort = Find-FreePort -StartPort ($backendPort + 1)
    Write-Host "Port conflict detected. Reassigned backend to $backendPort." -ForegroundColor Yellow
    Set-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT" -Value "$backendPort"
  }

  if ((Test-PortInUse -Port $frontendPort) -and -not (Test-PortOwnedByContainer -Port $frontendPort -ContainerName "c2f-frontend")) {
    $frontendPort = Find-FreePort -StartPort ($frontendPort + 1)
    Write-Host "Port conflict detected. Reassigned frontend to $frontendPort." -ForegroundColor Yellow
    Set-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT" -Value "$frontendPort"
  }

  if ((Test-PortInUse -Port $dbPort) -and -not (Test-PortOwnedByContainer -Port $dbPort -ContainerName "c2f-db")) {
    $dbPort = Find-FreePort -StartPort ($dbPort + 1)
    Write-Host "Port conflict detected. Reassigned db host port to $dbPort." -ForegroundColor Yellow
    Set-EnvValue -Path $EnvPath -Key "C2F_DB_PORT" -Value "$dbPort"
  }

  if ($frontendPort -ne $oldFrontendPort) {
    Set-EnvValue -Path $EnvPath -Key "C2F_CORS_ORIGINS" -Value "http://$publicHost`:$frontendPort"
  }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker is not installed."
}
Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "version") -FailureMessage "Docker Compose plugin is required."

if (-not (Test-Path $envPath)) {
  throw "Missing $envPath. Run install.ps1 first."
}

Resolve-PortConflicts -EnvPath $envPath

$backendImage = Get-EnvValue -Path $envPath -Key "C2F_BACKEND_IMAGE"
$frontendImage = Get-EnvValue -Path $envPath -Key "C2F_FRONTEND_IMAGE"
$agentManagerImage = Get-EnvValue -Path $envPath -Key "C2F_AGENT_MANAGER_IMAGE"
$eventIndexerImage = Get-EnvValue -Path $envPath -Key "C2F_EVENT_INDEXER_IMAGE"
$imageTag = Get-EnvValue -Path $envPath -Key "C2F_IMAGE_TAG"
$skipPull = To-Bool -RawValue (Get-EnvValue -Path $envPath -Key "C2F_SKIP_PULL") -Default $false

if ($skipPull) {
  Write-Host "C2F_SKIP_PULL=true, using local images only."
  foreach ($image in @(
    "$backendImage`:$imageTag",
    "$frontendImage`:$imageTag",
    "$agentManagerImage`:$imageTag",
    "$eventIndexerImage`:$imageTag"
  )) {
    Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", $image) -FailureMessage "Required local image not found: $image."
  }
} else {
  Write-Host "Pulling configured images..."
  Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "--env-file", $envPath, "-f", $composePath, "pull") -FailureMessage "Failed to pull images."
}

Write-Host "Applying upgrade..."
$composeArgs = @("compose", "--env-file", $envPath, "-f", $composePath, "up", "-d")
if ($skipPull) {
  $composeArgs += @("--force-recreate", "agent-manager", "event-indexer", "backend", "frontend")
}
Invoke-NativeChecked -FilePath "docker" -Arguments $composeArgs -FailureMessage "Failed to apply upgrade."

Write-Host "Upgrade complete."
Write-Host "Check status:"
Write-Host "  docker compose --env-file $envPath -f $composePath ps"

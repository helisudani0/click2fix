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

function Invoke-ComposeChecked {
  param(
    [string[]]$Arguments = @(),
    [string]$FailureMessage = "Compose command failed."
  )
  Assert-NoDeadProjectContainers -ProjectName $script:composeProjectName
  Invoke-NativeChecked -FilePath "docker" -Arguments ((Get-ComposeBaseArguments) + $Arguments) -FailureMessage $FailureMessage
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

function Get-DefaultComposeProjectName {
  param([string]$ProjectRoot)
  $leaf = Split-Path -Leaf $ProjectRoot
  if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = "click2fix" }
  $normalized = $leaf.ToLowerInvariant() -replace '[^a-z0-9_-]', ''
  $normalized = $normalized -replace '^[^a-z0-9]+', ''
  if ([string]::IsNullOrWhiteSpace($normalized)) { return "click2fix" }
  return $normalized
}

function Ensure-ComposeProjectName {
  param(
    [string]$EnvPath,
    [string]$ProjectRoot
  )
  $projectName = Get-EnvValue -Path $EnvPath -Key "COMPOSE_PROJECT_NAME"
  if ([string]::IsNullOrWhiteSpace($projectName)) {
    $projectName = Get-DefaultComposeProjectName -ProjectRoot $ProjectRoot
    Set-EnvValue -Path $EnvPath -Key "COMPOSE_PROJECT_NAME" -Value $projectName
  }
  return $projectName
}

function Get-ComposeBaseArguments {
  return @("compose", "-p", $script:composeProjectName, "--env-file", $script:composeEnvPath, "-f", $script:composeFilePath)
}

function Get-ServicePorts {
  param(
    [string]$ProjectName,
    [string[]]$ServiceNames
  )
  foreach ($serviceName in @($ServiceNames)) {
    if ([string]::IsNullOrWhiteSpace($serviceName)) { continue }
    $ports = & docker ps `
      --filter "label=com.docker.compose.project=$ProjectName" `
      --filter "label=com.docker.compose.service=$serviceName" `
      --format "{{.Ports}}" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $ports) { continue }
    $first = $ports | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace($first)) { return $first.Trim() }
  }
  return ""
}

function Get-ComposeLabelValue {
  param(
    [string]$Labels,
    [string]$Key
  )
  foreach ($entry in (($Labels -split ',') | ForEach-Object { $_.Trim() })) {
    if ([string]::IsNullOrWhiteSpace($entry)) { continue }
    $parts = $entry -split '=', 2
    if ($parts.Count -ne 2) { continue }
    if ($parts[0] -eq $Key) { return $parts[1] }
  }
  return ""
}

function Get-DeadProjectContainers {
  param([string]$ProjectName)
  $rows = & docker ps -a `
    --filter "label=com.docker.compose.project=$ProjectName" `
    --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Labels}}' 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $rows) { return @() }

  $dead = @()
  foreach ($row in @($rows)) {
    if ([string]::IsNullOrWhiteSpace($row)) { continue }
    $parts = $row -split '\|', 4
    if ($parts.Count -lt 4) { continue }
    if ($parts[2] -notmatch '^Dead\b') { continue }
    $labels = $parts[3].Trim()
    $dead += [PSCustomObject]@{
      Id      = $parts[0].Trim()
      Name    = $parts[1].Trim()
      Status  = $parts[2].Trim()
      Service = Get-ComposeLabelValue -Labels $labels -Key "com.docker.compose.service"
      Replace = Get-ComposeLabelValue -Labels $labels -Key "com.docker.compose.replace"
    }
  }
  return @($dead)
}

function Assert-NoDeadProjectContainers {
  param([string]$ProjectName)
  $deadContainers = @(Get-DeadProjectContainers -ProjectName $ProjectName)
  if ($deadContainers.Count -eq 0) { return }

  Write-Host "Detected stale Click2Fix containers in Docker 'Dead' state. Attempting automatic project cleanup..." -ForegroundColor Yellow
  Remove-ProjectContainers -ProjectName $ProjectName
  Start-Sleep -Seconds 2
  $deadContainers = @(Get-DeadProjectContainers -ProjectName $ProjectName)
  if ($deadContainers.Count -eq 0) {
    Write-Host "Recovered stale project container state." -ForegroundColor Yellow
    return
  }

  $affected = @(
    $deadContainers |
      ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_.Service)) { return $_.Service }
        if (-not [string]::IsNullOrWhiteSpace($_.Replace)) { return $_.Replace }
        return $_.Id
      } |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
      Sort-Object -Unique
  )
  $affectedText = if ($affected.Count -gt 0) { $affected -join ", " } else { "unknown services" }
  throw "Docker has stale Click2Fix containers in the 'Dead' state for project '$ProjectName' ($affectedText). Automatic cleanup was attempted but Docker still reports orphaned container metadata. Restart Docker Desktop to clear it, then reopen the Control Center. Named volumes such as the Click2Fix database volume are preserved by a Docker restart."
}

function Get-ProjectContainerIds {
  param(
    [string]$ProjectName,
    [switch]$IncludeAll
  )
  $args = @("ps")
  if ($IncludeAll) { $args += "-a" }
  $args += @(
    "--filter", "label=com.docker.compose.project=$ProjectName",
    "--format", "{{.ID}}"
  )
  $containerIds = & docker @args 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $containerIds) { return @() }
  return @(
    $containerIds |
      ForEach-Object { $_.Trim() } |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  )
}

function Remove-ProjectContainers {
  param([string]$ProjectName)
  $containerIds = @(Get-ProjectContainerIds -ProjectName $ProjectName -IncludeAll)
  $previousErrorAction = $ErrorActionPreference
  $nativePreferenceFound = $false
  $previousNativePreference = $null
  try {
    $ErrorActionPreference = "Continue"
    $nativePreferenceVar = Get-Variable -Name "PSNativeCommandUseErrorActionPreference" -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $nativePreferenceVar) {
      $nativePreferenceFound = $true
      $previousNativePreference = $global:PSNativeCommandUseErrorActionPreference
      $global:PSNativeCommandUseErrorActionPreference = $false
    }

    foreach ($containerId in $containerIds) {
      & docker rm -f $containerId 1>$null 2>$null | Out-Null
    }
    & docker network rm "$ProjectName`_default" 1>$null 2>$null | Out-Null
  } finally {
    $ErrorActionPreference = $previousErrorAction
    if ($nativePreferenceFound) {
      $global:PSNativeCommandUseErrorActionPreference = $previousNativePreference
    }
  }
}

function Prepare-ComposeProjectForUp {
  param([string]$ProjectName)
  $allContainers = @(Get-ProjectContainerIds -ProjectName $ProjectName -IncludeAll)
  if ($allContainers.Count -eq 0) { return }

  $runningContainers = @(Get-ProjectContainerIds -ProjectName $ProjectName)
  if ($runningContainers.Count -gt 0) { return }

  Write-Host "No Click2Fix services are currently running. Recreating project containers to avoid stale Docker restart state." -ForegroundColor Yellow
  Remove-ProjectContainers -ProjectName $ProjectName
}

function Show-ProjectContainers {
  & docker ps -a `
    --filter "label=com.docker.compose.project=$script:composeProjectName" `
    --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}'
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

function Test-PortOwnedByService {
  param(
    [int]$Port,
    [string[]]$ServiceNames
  )
  $ports = Get-ServicePorts -ProjectName $script:composeProjectName -ServiceNames $ServiceNames
  if ([string]::IsNullOrWhiteSpace($ports)) { return $false }
  return [regex]::IsMatch($ports, "[:.]$Port->")
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

function Get-CurrentAdvertiseHost {
  param([string]$FallbackHost = "localhost")

  try {
    $socket = [System.Net.Sockets.Socket]::new(
      [System.Net.Sockets.AddressFamily]::InterNetwork,
      [System.Net.Sockets.SocketType]::Dgram,
      [System.Net.Sockets.ProtocolType]::Udp
    )
    try {
      $socket.Connect("1.1.1.1", 53)
      $endpoint = [System.Net.IPEndPoint]$socket.LocalEndPoint
      $ip = $endpoint.Address.IPAddressToString
      if (-not [string]::IsNullOrWhiteSpace($ip) -and $ip -notmatch '^(0\.|127\.|169\.254\.)') {
        return $ip
      }
    } finally {
      $socket.Dispose()
    }
  } catch {}

  try {
    $ip = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
      Where-Object {
        $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
        $_.IPAddressToString -notmatch '^(0\.|127\.|169\.254\.)'
      } |
      Select-Object -First 1 -ExpandProperty IPAddressToString
    if (-not [string]::IsNullOrWhiteSpace($ip)) {
      return $ip
    }
  } catch {}

  if (-not [string]::IsNullOrWhiteSpace($FallbackHost)) {
    return $FallbackHost
  }
  return "localhost"
}

function Test-IPv4Literal {
  param([string]$Value)
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return $false }
  if ($text -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') { return $false }
  foreach ($part in $text.Split(".")) {
    $num = 0
    if (-not [int]::TryParse($part, [ref]$num)) { return $false }
    if ($num -lt 0 -or $num -gt 255) { return $false }
  }
  return $true
}

function Resolve-RuntimePublicHost {
  param([string]$ConfiguredHost)
  $configured = [string]$ConfiguredHost
  if ([string]::IsNullOrWhiteSpace($configured)) {
    return Get-CurrentAdvertiseHost -FallbackHost "localhost"
  }
  $normalized = $configured.Trim()
  if ($normalized.ToLowerInvariant() -eq "localhost" -or (Test-IPv4Literal -Value $normalized)) {
    return Get-CurrentAdvertiseHost -FallbackHost $normalized
  }
  return $normalized
}

function Split-EnvList {
  param([string]$RawValue)
  if ([string]::IsNullOrWhiteSpace($RawValue)) { return @() }
  return @(
    $RawValue.Split(",") |
      ForEach-Object { $_.Trim() } |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  )
}

function Join-UniqueList {
  param([string[]]$Values)
  $seen = @{}
  $out = @()
  foreach ($value in @($Values)) {
    $text = [string]$value
    if ([string]::IsNullOrWhiteSpace($text)) { continue }
    $key = $text.ToLowerInvariant()
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $out += $text
  }
  return ($out -join ",")
}

function Build-CorsOriginsValue {
  param(
    [string]$PublicHost,
    [int]$FrontendPort,
    [string]$ExistingValue
  )
  $primary = "http://$PublicHost`:$FrontendPort"
  $merged = @($primary)
  foreach ($candidate in (Split-EnvList -RawValue $ExistingValue)) {
    if ($candidate -eq $primary) { continue }
    $merged += $candidate
  }
  return Join-UniqueList -Values $merged
}

function Build-TrustedHostsValue {
  param(
    [string]$PublicHost,
    [string]$ExistingValue
  )
  $base = @(
    "localhost",
    "127.0.0.1",
    "*.localhost",
    "backend",
    "frontend",
    "c2f-backend",
    "c2f-frontend",
    "c2f-lb"
  )
  $merged = @($base)
  $merged += Split-EnvList -RawValue $ExistingValue
  if (-not [string]::IsNullOrWhiteSpace($PublicHost)) {
    $merged += $PublicHost
  }
  return Join-UniqueList -Values $merged
}

function Resolve-PortConflicts {
  param([string]$EnvPath)
  if (-not (Test-Path $EnvPath)) { return }

  $configuredHost = Get-EnvValue -Path $EnvPath -Key "C2F_PUBLIC_HOST"
  $publicHost = Resolve-RuntimePublicHost -ConfiguredHost $configuredHost
  if ([string]::IsNullOrWhiteSpace($publicHost)) { $publicHost = "localhost" }
  $frontendRaw = Get-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT"
  $backendRaw = Get-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT"
  $dbRaw = Get-EnvValue -Path $EnvPath -Key "C2F_DB_PORT"
  $frontendPort = Parse-PortOrDefault -RawValue $frontendRaw -DefaultPort 5173
  $backendPort = Parse-PortOrDefault -RawValue $backendRaw -DefaultPort 8000
  $dbPort = Parse-PortOrDefault -RawValue $dbRaw -DefaultPort 5432
  $changed = $false

  if ($publicHost -ne $configuredHost) {
    Set-EnvValue -Path $EnvPath -Key "C2F_PUBLIC_HOST" -Value $publicHost
    $changed = $true
  }

  if ((Test-PortInUse -Port $backendPort) -and -not (Test-PortOwnedByService -Port $backendPort -ServiceNames @("c2f-lb", "backend"))) {
    $newBackend = Find-FreePort -StartPort ($backendPort + 1)
    Write-Host "Port $backendPort is in use. Reassigning backend to $newBackend." -ForegroundColor Yellow
    $backendPort = $newBackend
    Set-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT" -Value "$backendPort"
    $changed = $true
  }

  if ((Test-PortInUse -Port $frontendPort) -and -not (Test-PortOwnedByService -Port $frontendPort -ServiceNames @("frontend"))) {
    $newFrontend = Find-FreePort -StartPort ($frontendPort + 1)
    Write-Host "Port $frontendPort is in use. Reassigning frontend to $newFrontend." -ForegroundColor Yellow
    $frontendPort = $newFrontend
    Set-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT" -Value "$frontendPort"
    $changed = $true
  }

  if ((Test-PortInUse -Port $dbPort) -and -not (Test-PortOwnedByService -Port $dbPort -ServiceNames @("db"))) {
    $newDb = Find-FreePort -StartPort ($dbPort + 1)
    Write-Host "Port $dbPort is in use. Reassigning db host port to $newDb." -ForegroundColor Yellow
    $dbPort = $newDb
    Set-EnvValue -Path $EnvPath -Key "C2F_DB_PORT" -Value "$dbPort"
    $changed = $true
  }

  $existingCors = Get-EnvValue -Path $EnvPath -Key "C2F_CORS_ORIGINS"
  $desiredCors = Build-CorsOriginsValue -PublicHost $publicHost -FrontendPort $frontendPort -ExistingValue $existingCors
  if ($desiredCors -ne $existingCors) {
    Set-EnvValue -Path $EnvPath -Key "C2F_CORS_ORIGINS" -Value $desiredCors
    $changed = $true
  }

  $existingTrustedHosts = Get-EnvValue -Path $EnvPath -Key "C2F_TRUSTED_HOSTS"
  $desiredTrustedHosts = Build-TrustedHostsValue -PublicHost $publicHost -ExistingValue $existingTrustedHosts
  if ($desiredTrustedHosts -ne $existingTrustedHosts) {
    Set-EnvValue -Path $EnvPath -Key "C2F_TRUSTED_HOSTS" -Value $desiredTrustedHosts
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

$script:composeEnvPath = $envPath
$script:composeFilePath = $composePath
$script:composeProjectName = Ensure-ComposeProjectName -EnvPath $envPath -ProjectRoot $scriptDir

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
        Prepare-ComposeProjectForUp -ProjectName $script:composeProjectName
        Invoke-ComposeChecked -Arguments @("up", "-d", "--remove-orphans") -FailureMessage "Failed to start services."
      }
      "3" {
        $runningContainers = @(Get-ProjectContainerIds -ProjectName $script:composeProjectName)
        if ($runningContainers.Count -eq 0) {
          Write-Host "No Click2Fix services are currently running."
        } else {
          Invoke-ComposeChecked -Arguments @("stop") -FailureMessage "Failed to stop services."
        }
      }
      "4" {
        $runningContainers = @(Get-ProjectContainerIds -ProjectName $script:composeProjectName)
        if ($runningContainers.Count -eq 0) {
          Resolve-PortConflicts -EnvPath $envPath
          Prepare-ComposeProjectForUp -ProjectName $script:composeProjectName
          Invoke-ComposeChecked -Arguments @("up", "-d", "--remove-orphans") -FailureMessage "Failed to restart services."
        } else {
          Invoke-ComposeChecked -Arguments @("restart") -FailureMessage "Failed to restart services."
        }
      }
      "5" {
        Show-ProjectContainers
      }
      "6" {
        Assert-NoDeadProjectContainers -ProjectName $script:composeProjectName
        $backendContainer = Get-ServiceContainerId -ProjectName $script:composeProjectName -ServiceName "backend" -IncludeAll
        if ([string]::IsNullOrWhiteSpace($backendContainer)) {
          Write-Host "No backend container exists for project '$script:composeProjectName'. Start services first."
        } else {
          & docker @("logs", "-f", $backendContainer)
        }
      }
      "7" {
        Resolve-PortConflicts -EnvPath $envPath
        & powershell -NoProfile -ExecutionPolicy Bypass -File $upgradeScript -EnvFile $EnvFile -ComposeFile $ComposeFile
      }
      "8" {
        $configuredHost = Get-EnvValue -Path $envPath -Key "C2F_PUBLIC_HOST"
        $publicHost = Get-CurrentAdvertiseHost -FallbackHost $configuredHost
        $frontendPort = Get-EnvValue -Path $envPath -Key "C2F_FRONTEND_PORT"
        if ([string]::IsNullOrWhiteSpace($frontendPort)) { $frontendPort = "5173" }
        $backendPort = Get-EnvValue -Path $envPath -Key "C2F_BACKEND_PORT"
        if ([string]::IsNullOrWhiteSpace($backendPort)) { $backendPort = "8000" }
        if (-not [string]::IsNullOrWhiteSpace($configuredHost) -and $configuredHost -ne $publicHost) {
          Write-Host "Detected current host IP: $publicHost" -ForegroundColor Cyan
          Write-Host "Configured host from first setup: $configuredHost" -ForegroundColor DarkGray
        }
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

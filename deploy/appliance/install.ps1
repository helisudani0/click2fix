param(
  [string]$EnvFile = ".env.appliance",
  [string]$ComposeFile = "docker-compose.appliance.yml"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$preflight = Join-Path $scriptDir "preflight.ps1"
if (Test-Path $preflight) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $preflight -Root $scriptDir
} else {
  try {
    Get-ChildItem -Path $scriptDir -Recurse -File -ErrorAction SilentlyContinue |
      ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }
  } catch {
    Write-Host "Warning: Unable to remove download security markers. If scripts are blocked, run Unblock-File on the installer folder." -ForegroundColor Yellow
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

function Read-Value {
  param(
    [string]$Prompt,
    [string]$Default = ""
  )
  if ([string]::IsNullOrWhiteSpace($Default)) {
    $value = Read-Host $Prompt
  } else {
    $value = Read-Host "$Prompt [$Default]"
  }
  if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
  return $value
}

function Read-SecretValue {
  param(
    [string]$Prompt,
    [string]$Default = ""
  )
  $secure = Read-Host "$Prompt (hidden, Enter keeps current)" -AsSecureString
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  )
  if ([string]::IsNullOrWhiteSpace($plain)) { return $Default }
  return $plain
}

function To-Bool {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
  return @("1","true","yes","on") -contains $Value.Trim().ToLowerInvariant()
}

function Get-PreferredIPv4 {
  try {
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
      Where-Object { $_.NextHop -and $_.NextHop -ne "0.0.0.0" } |
      Sort-Object RouteMetric, ifMetric |
      Select-Object -First 1
    if ($route) {
      $routedIp = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } |
        Select-Object -ExpandProperty IPAddress -First 1
      if ($routedIp) { return $routedIp }
    }
  } catch {}

  $fallback = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
      $_.IPAddress -notlike "169.254.*" -and
      $_.IPAddress -ne "127.0.0.1" -and
      $_.InterfaceAlias -notmatch "vEthernet|VirtualBox|VMware|Hyper-V|Loopback|Docker|WSL"
    } |
    Select-Object -ExpandProperty IPAddress -First 1
  if ($fallback) { return $fallback }
  return "localhost"
}

function New-StrongSecret {
  param([int]$Bytes = 48)
  $buffer = New-Object byte[] $Bytes
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($buffer)
  } finally {
    if ($null -ne $rng) { $rng.Dispose() }
  }
  return ([Convert]::ToBase64String($buffer)).TrimEnd("=")
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

function Get-ServiceContainerId {
  param(
    [string]$ProjectName,
    [string]$ServiceName,
    [switch]$IncludeAll
  )
  $args = @("ps")
  if ($IncludeAll) { $args += "-a" }
  $args += @(
    "--filter", "label=com.docker.compose.project=$ProjectName",
    "--filter", "label=com.docker.compose.service=$ServiceName",
    "--format", "{{.ID}}"
  )
  $containerIds = & docker @args 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $containerIds) { return "" }
  $first = $containerIds | Select-Object -First 1
  if ([string]::IsNullOrWhiteSpace($first)) { return "" }
  return $first.Trim()
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
  throw "Docker has stale Click2Fix containers in the 'Dead' state for project '$ProjectName' ($affectedText). Automatic cleanup was attempted but Docker still reports orphaned container metadata. Restart Docker Desktop to clear it, then rerun setup. Named volumes such as the Click2Fix database volume are preserved by a Docker restart."
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

function Resolve-PortConflict {
  param(
    [int]$RequestedPort,
    [string[]]$ServiceNames,
    [string]$Label
  )
  if (-not (Test-PortInUse -Port $RequestedPort) -or (Test-PortOwnedByService -Port $RequestedPort -ServiceNames $ServiceNames)) {
    return $RequestedPort
  }
  $newPort = Find-FreePort -StartPort ($RequestedPort + 1)
  Write-Host "Port $RequestedPort is in use. Reassigning $Label to $newPort." -ForegroundColor Yellow
  return $newPort
}

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
    throw "Docker engine is not running. Start Docker Desktop (Linux containers mode), wait until it shows Running, then rerun setup."
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

function Get-ServiceStatus {
  param([string]$ServiceName)
  $containerId = Get-ServiceContainerId -ProjectName $script:composeProjectName -ServiceName $ServiceName -IncludeAll
  if ([string]::IsNullOrWhiteSpace($containerId)) { return "" }
  $status = & docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $containerId 2>$null
  if ($LASTEXITCODE -ne 0) { return "" }
  return ($status | Select-Object -First 1).Trim()
}

function Show-ComposeDiagnostics {
  Write-Host ""
  Write-Host "---- project containers ----" -ForegroundColor Yellow
  & docker ps -a `
    --filter "label=com.docker.compose.project=$script:composeProjectName" `
    --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}'

  $deadContainers = @(Get-DeadProjectContainers -ProjectName $script:composeProjectName)
  if ($deadContainers.Count -gt 0) {
    Write-Host ""
    Write-Host "Docker still reports dead Click2Fix containers for project '$script:composeProjectName'." -ForegroundColor Yellow
    Write-Host "Restart Docker Desktop to clear the stale container metadata, then rerun setup." -ForegroundColor Yellow
    return
  }

  Write-Host ""
  Write-Host "---- docker compose ps ----" -ForegroundColor Yellow
  & docker @((Get-ComposeBaseArguments) + @("ps"))
  Write-Host ""
  Write-Host "---- backend logs (tail 160) ----" -ForegroundColor Yellow
  & docker @((Get-ComposeBaseArguments) + @("logs", "--tail", "160", "backend"))
  Write-Host ""
  Write-Host "---- db logs (tail 80) ----" -ForegroundColor Yellow
  & docker @((Get-ComposeBaseArguments) + @("logs", "--tail", "80", "db"))
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envTemplate = Join-Path $scriptDir ".env.appliance.template"
$envPath = Join-Path $scriptDir $EnvFile
$composePath = Join-Path $scriptDir $ComposeFile

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker is not installed."
}
Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "version") -FailureMessage "Docker Compose plugin is required."
Ensure-DockerEngine

if (-not (Test-Path $envPath)) {
  Copy-Item -Path $envTemplate -Destination $envPath -Force
}

$script:composeEnvPath = $envPath
$script:composeFilePath = $composePath
$script:composeProjectName = Ensure-ComposeProjectName -EnvPath $envPath -ProjectRoot $scriptDir

Write-Host "== Click2Fix Appliance First-Boot Setup (Windows) ==" -ForegroundColor Cyan

$defaultHost = Get-PreferredIPv4

$currentPublicHost = Get-EnvValue $envPath "C2F_PUBLIC_HOST"
if ([string]::IsNullOrWhiteSpace($currentPublicHost)) { $currentPublicHost = $defaultHost }
$publicHost = Read-Value "Public host or static IP for UI access" $currentPublicHost
$frontendPort = Read-Value "Frontend port" (Get-EnvValue $envPath "C2F_FRONTEND_PORT")
$backendPort = Read-Value "Backend port" (Get-EnvValue $envPath "C2F_BACKEND_PORT")
$dbPort = Get-EnvValue $envPath "C2F_DB_PORT"

$wazuhUrl = Read-Value "Wazuh manager URL (include https:// and port)" (Get-EnvValue $envPath "WAZUH_URL")
$wazuhUser = Read-Value "Wazuh API user" (Get-EnvValue $envPath "WAZUH_USER")
$wazuhPassword = Read-SecretValue "Wazuh API password" (Get-EnvValue $envPath "WAZUH_PASSWORD")

$indexerUrl = Read-Value "Wazuh indexer URL (include https:// and port)" (Get-EnvValue $envPath "INDEXER_URL")
$indexerUser = Read-Value "Wazuh indexer user" (Get-EnvValue $envPath "INDEXER_USER")
$indexerPassword = Read-SecretValue "Wazuh indexer password" (Get-EnvValue $envPath "INDEXER_PASSWORD")

$winrmUser = Read-Value "Global WinRM username (blank if per-agent strategy later)" (Get-EnvValue $envPath "C2F_WINRM_USERNAME")
$winrmPassword = Read-SecretValue "Global WinRM password" (Get-EnvValue $envPath "C2F_WINRM_PASSWORD")

$adminUser = Read-Value "Initial Click2Fix admin username" (Get-EnvValue $envPath "C2F_BOOTSTRAP_ADMIN_USERNAME")
$adminPassword = Read-SecretValue "Initial Click2Fix admin password" (Get-EnvValue $envPath "C2F_BOOTSTRAP_ADMIN_PASSWORD")

$appBrand = Get-EnvValue $envPath "APP_BRAND"
if ([string]::IsNullOrWhiteSpace($appBrand)) { $appBrand = "Click2Fix" }
$backendImage = Get-EnvValue $envPath "C2F_BACKEND_IMAGE"
$frontendImage = Get-EnvValue $envPath "C2F_FRONTEND_IMAGE"
$postgresImageTag = Get-EnvValue $envPath "POSTGRES_IMAGE_TAG"
$imageTag = Get-EnvValue $envPath "C2F_IMAGE_TAG"
$skipPull = Get-EnvValue $envPath "C2F_SKIP_PULL"
if ([string]::IsNullOrWhiteSpace($backendImage) -or [string]::IsNullOrWhiteSpace($frontendImage) -or [string]::IsNullOrWhiteSpace($imageTag)) {
  throw "Image configuration is missing in .env.appliance. Expected C2F_BACKEND_IMAGE, C2F_FRONTEND_IMAGE, C2F_IMAGE_TAG."
}
if ([string]::IsNullOrWhiteSpace($skipPull)) { $skipPull = "false" }
if ([string]::IsNullOrWhiteSpace($postgresImageTag)) { $postgresImageTag = "16" }
$jwtSecret = Get-EnvValue $envPath "JWT_SECRET"
if ([string]::IsNullOrWhiteSpace($jwtSecret) -or $jwtSecret -match "^CHANGE_ME" -or $jwtSecret.Length -lt 32) {
  $jwtSecret = New-StrongSecret
  Write-Host "Generated secure JWT secret for this appliance." -ForegroundColor Yellow
}

if ([string]::IsNullOrWhiteSpace($publicHost)) { throw "Public host/IP is required." }
if ([string]::IsNullOrWhiteSpace($wazuhPassword) -or [string]::IsNullOrWhiteSpace($indexerPassword) -or [string]::IsNullOrWhiteSpace($adminPassword)) {
  throw "Passwords cannot be empty."
}
if ($adminUser.Trim().Length -lt 3) {
  throw "Initial admin username must be at least 3 characters."
}
if ($adminPassword.Length -lt 8) {
  throw "Initial admin password must be at least 8 characters."
}

$frontendPort = Resolve-PortConflict -RequestedPort (Parse-PortOrDefault -RawValue $frontendPort -DefaultPort 5173) -ServiceNames @("frontend") -Label "frontend"
$backendPort = Resolve-PortConflict -RequestedPort (Parse-PortOrDefault -RawValue $backendPort -DefaultPort 8000) -ServiceNames @("c2f-lb", "backend") -Label "backend"
$dbPort = Resolve-PortConflict -RequestedPort (Parse-PortOrDefault -RawValue $dbPort -DefaultPort 5432) -ServiceNames @("db") -Label "db host"

$trustedHosts = "localhost,127.0.0.1,*.localhost,backend,frontend,c2f-backend,c2f-frontend,$publicHost"
$corsOrigins = "http://$publicHost`:$frontendPort"

Set-EnvValue -Path $envPath -Key "APP_BRAND" -Value $appBrand
Set-EnvValue -Path $envPath -Key "C2F_PUBLIC_HOST" -Value $publicHost
Set-EnvValue -Path $envPath -Key "C2F_FRONTEND_PORT" -Value $frontendPort
Set-EnvValue -Path $envPath -Key "C2F_BACKEND_PORT" -Value $backendPort
Set-EnvValue -Path $envPath -Key "C2F_DB_PORT" -Value $dbPort
Set-EnvValue -Path $envPath -Key "C2F_TRUSTED_HOSTS" -Value $trustedHosts
Set-EnvValue -Path $envPath -Key "C2F_CORS_ORIGINS" -Value $corsOrigins
Set-EnvValue -Path $envPath -Key "WAZUH_URL" -Value $wazuhUrl
Set-EnvValue -Path $envPath -Key "WAZUH_USER" -Value $wazuhUser
Set-EnvValue -Path $envPath -Key "WAZUH_PASSWORD" -Value $wazuhPassword
Set-EnvValue -Path $envPath -Key "INDEXER_URL" -Value $indexerUrl
Set-EnvValue -Path $envPath -Key "INDEXER_USER" -Value $indexerUser
Set-EnvValue -Path $envPath -Key "INDEXER_PASSWORD" -Value $indexerPassword
Set-EnvValue -Path $envPath -Key "JWT_SECRET" -Value $jwtSecret
Set-EnvValue -Path $envPath -Key "C2F_WINRM_USERNAME" -Value $winrmUser
Set-EnvValue -Path $envPath -Key "C2F_WINRM_PASSWORD" -Value $winrmPassword
Set-EnvValue -Path $envPath -Key "C2F_BOOTSTRAP_ADMIN_USERNAME" -Value $adminUser
Set-EnvValue -Path $envPath -Key "C2F_BOOTSTRAP_ADMIN_PASSWORD" -Value $adminPassword

if (To-Bool $skipPull) {
  Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", "postgres:$postgresImageTag") -FailureMessage "Postgres image not found locally: postgres:$postgresImageTag."
  Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", "$backendImage`:$imageTag") -FailureMessage "Backend image not found locally: $backendImage`:$imageTag."
  Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", "$frontendImage`:$imageTag") -FailureMessage "Frontend image not found locally: $frontendImage`:$imageTag."
} else {
  Write-Host "Pulling configured images..."
  $requiredImages = @(
    "postgres:$postgresImageTag",
    "$backendImage`:$imageTag",
    "$frontendImage`:$imageTag"
  )
  try {
    foreach ($image in $requiredImages) {
      Invoke-NativeChecked -FilePath "docker" -Arguments @("pull", $image) -FailureMessage "Image pull failed for $image."
    }
  } catch {
    $detail = $_.Exception.Message
    if ($detail -match "unauthorized|denied|authentication") {
      throw "Image pull failed: registry authentication denied. If using private GHCR images, run 'docker login ghcr.io' (PAT with read:packages), then rerun setup."
    }
    if ($detail -match "dockerDesktopLinuxEngine|Cannot connect to the Docker daemon|error during connect|pipe") {
      throw "Image pull failed because Docker engine is unavailable. Start Docker Desktop and rerun setup."
    }
    throw "Image pull failed. Details: $detail"
  }
}

try {
  # Bring up DB + backend first so backend health is evaluated before frontend dependency kicks in.
  Prepare-ComposeProjectForUp -ProjectName $script:composeProjectName
  Invoke-ComposeChecked -Arguments @("up", "-d", "--remove-orphans", "db", "backend") -FailureMessage "Failed to start backend stack."
} catch {
  Show-ComposeDiagnostics
  throw
}

for ($i = 0; $i -lt 60; $i++) {
  $status = Get-ServiceStatus -ServiceName "backend"
  if ($status -eq "healthy") { break }
  Start-Sleep -Seconds 2
}
$status = Get-ServiceStatus -ServiceName "backend"
if ($status -ne "healthy") {
  Show-ComposeDiagnostics
  throw "Backend is not healthy. Check logs: docker compose -p $script:composeProjectName --env-file $envPath -f $composePath logs backend"
}

try {
  Invoke-ComposeChecked -Arguments @("up", "-d", "--remove-orphans", "frontend") -FailureMessage "Failed to start frontend."
} catch {
  Show-ComposeDiagnostics
  throw
}

$forceReset = Get-EnvValue $envPath "C2F_BOOTSTRAP_ADMIN_FORCE_RESET"
$resetArg = @()
if (To-Bool $forceReset) { $resetArg += "--force-reset" }
$bootstrapArgs = (Get-ComposeBaseArguments) + @(
  "exec", "-T", "-w", "/app", "backend",
  "python", "-m", "tools.bootstrap_admin",
  "--username", $adminUser,
  "--password", $adminPassword,
  "--role", "admin"
) + $resetArg
try {
  Assert-NoDeadProjectContainers -ProjectName $script:composeProjectName
  $bootstrapOutput = & docker @bootstrapArgs 2>&1
  $bootstrapExit = $LASTEXITCODE
  if ($bootstrapOutput) { $bootstrapOutput | ForEach-Object { Write-Host $_ } }
  if ($bootstrapExit -ne 0) {
    throw "Bootstrap command failed with exit code $bootstrapExit."
  }
} catch {
  Show-ComposeDiagnostics
  throw "Failed to bootstrap admin user. $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Appliance is ready." -ForegroundColor Green
Write-Host "UI URL: http://$publicHost`:$frontendPort"
Write-Host "Backend API/docs: http://$publicHost`:$backendPort/docs"
Write-Host "Backend Ops: http://$publicHost`:$backendPort/ops"
Write-Host "Login user: $adminUser"

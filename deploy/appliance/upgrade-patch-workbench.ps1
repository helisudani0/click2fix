param(
  [string]$EnvFile = ".env.patch-workbench",
  [string]$ComposeFile = "docker-compose.patch-workbench.yml"
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

function To-IntOrDefault {
  param(
    [string]$RawValue,
    [int]$Default = 0
  )
  $parsed = 0
  if ([int]::TryParse($RawValue, [ref]$parsed)) {
    return $parsed
  }
  return $Default
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

function Get-ImageRepositoryFromRef {
  param([string]$ImageRef)
  $value = [string]$ImageRef
  if ([string]::IsNullOrWhiteSpace($value)) { return "" }
  if ($value.Contains("@")) {
    $value = $value.Split("@", 2)[0]
  }
  if ($value -match '^[^/]+:[^/]+$') {
    # Handles image:tag without path safely.
    return ($value -split ':', 2)[0]
  }
  if ($value.Contains(":")) {
    return ($value.Substring(0, $value.LastIndexOf(":")))
  }
  return $value
}

function Invoke-RepoImageRetentionCleanup {
  param(
    [string]$ImageRef,
    [int]$KeepCount = 2
  )
  $repo = Get-ImageRepositoryFromRef -ImageRef $ImageRef
  if ([string]::IsNullOrWhiteSpace($repo)) { return }

  $rows = & docker image ls $repo --format "{{.ID}}|{{.Repository}}:{{.Tag}}" 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $rows) {
    Write-Host "Image retention: no local images found for $repo."
    return
  }

  $ids = @()
  $seen = @{}
  foreach ($row in @($rows)) {
    if ([string]::IsNullOrWhiteSpace($row)) { continue }
    $parts = $row -split '\|', 2
    if ($parts.Count -lt 2) { continue }
    $id = $parts[0].Trim()
    $repoTag = $parts[1].Trim()
    if ([string]::IsNullOrWhiteSpace($id) -or $repoTag -eq "<none>:<none>") { continue }
    if ($seen.ContainsKey($id)) { continue }
    $seen[$id] = $true
    $ids += $id
  }

  if ($ids.Count -le $KeepCount) {
    Write-Host "Image retention: $repo has $($ids.Count) image(s); keep=$KeepCount, nothing to prune."
    return
  }

  $removed = 0
  for ($i = $KeepCount; $i -lt $ids.Count; $i++) {
    $id = $ids[$i]
    try {
      & docker image rm $id 1>$null 2>$null | Out-Null
      $removed++
    } catch {
      # Ignore images in use or already removed.
    }
  }

  Write-Host "Image retention: pruned $removed old image(s) for $repo; kept newest $KeepCount."
}

function Invoke-ApplianceImageRetentionCleanup {
  param(
    [string]$EnvPath,
    [string]$BackendImageRef,
    [string]$FrontendImageRef,
    [string]$PostgresImageRef
  )
  $keepRaw = Get-EnvValue -Path $EnvPath -Key "C2F_IMAGE_RETENTION_COUNT"
  $keepCount = To-IntOrDefault -RawValue $keepRaw -Default 2
  if ($keepCount -lt 1) {
    Write-Host "Image retention disabled (C2F_IMAGE_RETENTION_COUNT=$keepRaw)."
    return
  }

  Invoke-RepoImageRetentionCleanup -ImageRef $BackendImageRef -KeepCount $keepCount
  Invoke-RepoImageRetentionCleanup -ImageRef $FrontendImageRef -KeepCount $keepCount
  Invoke-RepoImageRetentionCleanup -ImageRef $PostgresImageRef -KeepCount $keepCount
  try {
    & docker image prune -f 1>$null 2>$null | Out-Null
  } catch {}
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
  throw "Docker has stale Click2Fix containers in the 'Dead' state for project '$ProjectName' ($affectedText). Automatic cleanup was attempted but Docker still reports orphaned container metadata. Restart Docker Desktop to clear it, then rerun the upgrade. Named volumes such as the Click2Fix database volume are preserved by a Docker restart."
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
      try {
        & docker rm -f $containerId 1>$null 2>$null | Out-Null
      } catch {
        # Docker Desktop can transiently return "No such container" for stale metadata.
      }
    }
    try {
      & docker network rm "$ProjectName`_default" 1>$null 2>$null | Out-Null
    } catch {
      # Ignore absent network during cleanup.
    }
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
  $frontendPort = Parse-PortOrDefault -RawValue (Get-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT") -DefaultPort 5173
  $backendPort = Parse-PortOrDefault -RawValue (Get-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT") -DefaultPort 8000
  $dbPort = Parse-PortOrDefault -RawValue (Get-EnvValue -Path $EnvPath -Key "C2F_DB_PORT") -DefaultPort 5432

  if ($publicHost -ne $configuredHost) {
    Set-EnvValue -Path $EnvPath -Key "C2F_PUBLIC_HOST" -Value $publicHost
  }

  if ((Test-PortInUse -Port $backendPort) -and -not (Test-PortOwnedByService -Port $backendPort -ServiceNames @("c2f-lb", "backend"))) {
    $backendPort = Find-FreePort -StartPort ($backendPort + 1)
    Write-Host "Port conflict detected. Reassigned backend to $backendPort." -ForegroundColor Yellow
    Set-EnvValue -Path $EnvPath -Key "C2F_BACKEND_PORT" -Value "$backendPort"
  }

  if ((Test-PortInUse -Port $frontendPort) -and -not (Test-PortOwnedByService -Port $frontendPort -ServiceNames @("frontend"))) {
    $frontendPort = Find-FreePort -StartPort ($frontendPort + 1)
    Write-Host "Port conflict detected. Reassigned frontend to $frontendPort." -ForegroundColor Yellow
    Set-EnvValue -Path $EnvPath -Key "C2F_FRONTEND_PORT" -Value "$frontendPort"
  }

  if ((Test-PortInUse -Port $dbPort) -and -not (Test-PortOwnedByService -Port $dbPort -ServiceNames @("db"))) {
    $dbPort = Find-FreePort -StartPort ($dbPort + 1)
    Write-Host "Port conflict detected. Reassigned db host port to $dbPort." -ForegroundColor Yellow
    Set-EnvValue -Path $EnvPath -Key "C2F_DB_PORT" -Value "$dbPort"
  }

  $existingCors = Get-EnvValue -Path $EnvPath -Key "C2F_CORS_ORIGINS"
  $desiredCors = Build-CorsOriginsValue -PublicHost $publicHost -FrontendPort $frontendPort -ExistingValue $existingCors
  if ($desiredCors -ne $existingCors) {
    Set-EnvValue -Path $EnvPath -Key "C2F_CORS_ORIGINS" -Value $desiredCors
  }

  $existingTrustedHosts = Get-EnvValue -Path $EnvPath -Key "C2F_TRUSTED_HOSTS"
  $desiredTrustedHosts = Build-TrustedHostsValue -PublicHost $publicHost -ExistingValue $existingTrustedHosts
  if ($desiredTrustedHosts -ne $existingTrustedHosts) {
    Set-EnvValue -Path $EnvPath -Key "C2F_TRUSTED_HOSTS" -Value $desiredTrustedHosts
  }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker is not installed."
}
Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "version") -FailureMessage "Docker Compose plugin is required."
Ensure-DockerEngine

if (-not (Test-Path $envPath)) {
  throw "Missing $envPath. Run install-patch-workbench.ps1 first."
}

$script:composeEnvPath = $envPath
$script:composeFilePath = $composePath
$script:composeProjectName = Ensure-ComposeProjectName -EnvPath $envPath -ProjectRoot $scriptDir

Resolve-PortConflicts -EnvPath $envPath

$backendImage = Get-EnvValue -Path $envPath -Key "C2F_BACKEND_IMAGE"
$frontendImage = Get-EnvValue -Path $envPath -Key "C2F_FRONTEND_IMAGE"
$postgresImageTag = Get-EnvValue -Path $envPath -Key "POSTGRES_IMAGE_TAG"
$imageTag = Get-EnvValue -Path $envPath -Key "C2F_IMAGE_TAG"
$skipPull = To-Bool -RawValue (Get-EnvValue -Path $envPath -Key "C2F_SKIP_PULL") -Default $false
if ([string]::IsNullOrWhiteSpace($postgresImageTag)) { $postgresImageTag = "16" }

if ($skipPull) {
  Write-Host "C2F_SKIP_PULL=true, using local images only."
  foreach ($image in @(
    "postgres:$postgresImageTag",
    "$backendImage`:$imageTag",
    "$frontendImage`:$imageTag"
  )) {
    Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", $image) -FailureMessage "Required local image not found: $image."
  }
} else {
  Write-Host "Pulling configured images..."
  $requiredImages = @(
    "postgres:$postgresImageTag",
    "$backendImage`:$imageTag",
    "$frontendImage`:$imageTag"
  )
  foreach ($image in $requiredImages) {
    Invoke-NativeChecked -FilePath "docker" -Arguments @("pull", $image) -FailureMessage "Failed to pull image: $image."
  }
}

Write-Host "Applying upgrade..."
$composeArgs = @("up", "-d", "--remove-orphans")
if ($skipPull) {
  $composeArgs += @("--force-recreate", "backend", "frontend")
}
Prepare-ComposeProjectForUp -ProjectName $script:composeProjectName
Invoke-ComposeChecked -Arguments $composeArgs -FailureMessage "Failed to apply upgrade."
Invoke-ApplianceImageRetentionCleanup `
  -EnvPath $envPath `
  -BackendImageRef "$backendImage`:$imageTag" `
  -FrontendImageRef "$frontendImage`:$imageTag" `
  -PostgresImageRef "postgres:$postgresImageTag"

Write-Host "Upgrade complete."
Write-Host "Check status:"
Write-Host "  docker compose -p $script:composeProjectName --env-file $envPath -f $composePath ps"

param(
  [string]$EnvFile = ".env.appliance",
  [string]$ComposeFile = "docker-compose.appliance.yml"
)

$ErrorActionPreference = "Stop"

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

function Get-ContainerStatus {
  param([string]$ContainerName)
  $exists = & docker ps -a --filter "name=^$ContainerName$" --format "{{.Names}}" 2>$null
  if ($LASTEXITCODE -ne 0) { return "" }
  $first = $exists | Select-Object -First 1
  if ([string]::IsNullOrWhiteSpace($first)) { return "" }
  $status = & docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $ContainerName 2>$null
  if ($LASTEXITCODE -ne 0) { return "" }
  return ($status | Select-Object -First 1).Trim()
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

Write-Host "== Click2Fix Appliance First-Boot Setup (Windows) ==" -ForegroundColor Cyan

$defaultHost = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } |
  Select-Object -ExpandProperty IPAddress -First 1)
if (-not $defaultHost) { $defaultHost = "localhost" }

$currentPublicHost = Get-EnvValue $envPath "C2F_PUBLIC_HOST"
if ([string]::IsNullOrWhiteSpace($currentPublicHost)) { $currentPublicHost = $defaultHost }
$publicHost = Read-Value "Public host or static IP for UI access" $currentPublicHost
$frontendPort = Read-Value "Frontend port" (Get-EnvValue $envPath "C2F_FRONTEND_PORT")
$backendPort = Read-Value "Backend port" (Get-EnvValue $envPath "C2F_BACKEND_PORT")

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
$imageTag = Get-EnvValue $envPath "C2F_IMAGE_TAG"
$skipPull = Get-EnvValue $envPath "C2F_SKIP_PULL"
if ([string]::IsNullOrWhiteSpace($backendImage) -or [string]::IsNullOrWhiteSpace($frontendImage) -or [string]::IsNullOrWhiteSpace($imageTag)) {
  throw "Image configuration is missing in .env.appliance. Expected C2F_BACKEND_IMAGE, C2F_FRONTEND_IMAGE, C2F_IMAGE_TAG."
}
if ([string]::IsNullOrWhiteSpace($skipPull)) { $skipPull = "false" }

if ([string]::IsNullOrWhiteSpace($publicHost)) { throw "Public host/IP is required." }
if ([string]::IsNullOrWhiteSpace($wazuhPassword) -or [string]::IsNullOrWhiteSpace($indexerPassword) -or [string]::IsNullOrWhiteSpace($adminPassword)) {
  throw "Passwords cannot be empty."
}

$trustedHosts = "localhost,127.0.0.1,*.localhost,backend,frontend,c2f-backend,c2f-frontend,$publicHost"
$corsOrigins = "http://$publicHost`:$frontendPort"

Set-EnvValue -Path $envPath -Key "APP_BRAND" -Value $appBrand
Set-EnvValue -Path $envPath -Key "C2F_PUBLIC_HOST" -Value $publicHost
Set-EnvValue -Path $envPath -Key "C2F_FRONTEND_PORT" -Value $frontendPort
Set-EnvValue -Path $envPath -Key "C2F_BACKEND_PORT" -Value $backendPort
Set-EnvValue -Path $envPath -Key "C2F_TRUSTED_HOSTS" -Value $trustedHosts
Set-EnvValue -Path $envPath -Key "C2F_CORS_ORIGINS" -Value $corsOrigins
Set-EnvValue -Path $envPath -Key "WAZUH_URL" -Value $wazuhUrl
Set-EnvValue -Path $envPath -Key "WAZUH_USER" -Value $wazuhUser
Set-EnvValue -Path $envPath -Key "WAZUH_PASSWORD" -Value $wazuhPassword
Set-EnvValue -Path $envPath -Key "INDEXER_URL" -Value $indexerUrl
Set-EnvValue -Path $envPath -Key "INDEXER_USER" -Value $indexerUser
Set-EnvValue -Path $envPath -Key "INDEXER_PASSWORD" -Value $indexerPassword
Set-EnvValue -Path $envPath -Key "C2F_WINRM_USERNAME" -Value $winrmUser
Set-EnvValue -Path $envPath -Key "C2F_WINRM_PASSWORD" -Value $winrmPassword
Set-EnvValue -Path $envPath -Key "C2F_BOOTSTRAP_ADMIN_USERNAME" -Value $adminUser
Set-EnvValue -Path $envPath -Key "C2F_BOOTSTRAP_ADMIN_PASSWORD" -Value $adminPassword

if (To-Bool $skipPull) {
  Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", "$backendImage`:$imageTag") -FailureMessage "Backend image not found locally: $backendImage`:$imageTag."
  Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", "$frontendImage`:$imageTag") -FailureMessage "Frontend image not found locally: $frontendImage`:$imageTag."
} else {
  try {
    Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "--env-file", $envPath, "-f", $composePath, "pull") -FailureMessage "Image pull failed."
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

Invoke-NativeChecked -FilePath "docker" -Arguments @("compose", "--env-file", $envPath, "-f", $composePath, "up", "-d") -FailureMessage "Failed to start services."

for ($i = 0; $i -lt 60; $i++) {
  $status = Get-ContainerStatus -ContainerName "c2f-backend"
  if ($status -eq "healthy") { break }
  Start-Sleep -Seconds 2
}
$status = Get-ContainerStatus -ContainerName "c2f-backend"
if ($status -ne "healthy") {
  throw "Backend is not healthy. Check logs: docker compose --env-file $envPath -f $composePath logs backend"
}

$forceReset = Get-EnvValue $envPath "C2F_BOOTSTRAP_ADMIN_FORCE_RESET"
$resetArg = @()
if (To-Bool $forceReset) { $resetArg += "--force-reset" }
$bootstrapArgs = @(
  "compose", "--env-file", $envPath, "-f", $composePath, "exec", "-T", "backend",
  "python", "tools/bootstrap_admin.py",
  "--username", $adminUser,
  "--password", $adminPassword,
  "--role", "admin"
) + $resetArg
Invoke-NativeChecked -FilePath "docker" -Arguments $bootstrapArgs -FailureMessage "Failed to bootstrap admin user."

Write-Host ""
Write-Host "Appliance is ready." -ForegroundColor Green
Write-Host "UI URL: http://$publicHost`:$frontendPort"
Write-Host "Login user: $adminUser"

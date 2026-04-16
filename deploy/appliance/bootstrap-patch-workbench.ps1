param(
  [string]$Owner = "helisudani0",
  [string]$Repo = "click2fix",
  [string]$Version = "min-v1.1.4",
  [string]$InstallDir = "C:\Click2Fix-PatchWorkbench",
  [switch]$PullImages,
  [switch]$LaunchSetup
)

$ErrorActionPreference = "Stop"

function Normalize-VersionTag {
  param([string]$RawVersion)
  $value = [string]$RawVersion
  if ([string]::IsNullOrWhiteSpace($value)) {
    return "min-v0.0.0"
  }
  if ($value.StartsWith("min-v")) {
    return $value
  }
  if ($value.StartsWith("v")) {
    return "min-$value"
  }
  return "min-v$value"
}

function Get-CleanImageTag {
  param([string]$RawVersion)
  $value = [string]$RawVersion
  if ($value.StartsWith("min-v")) {
    return $value.Substring(5)
  }
  if ($value.StartsWith("v")) {
    return $value.TrimStart("v")
  }
  return $value
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

function Update-ImageDefaults {
  param(
    [string]$Path,
    [string]$Owner,
    [string]$VersionTag
  )
  Set-EnvValue -Path $Path -Key "C2F_BACKEND_IMAGE" -Value "ghcr.io/$Owner/click2fix-backend-min"
  Set-EnvValue -Path $Path -Key "C2F_FRONTEND_IMAGE" -Value "ghcr.io/$Owner/click2fix-frontend-min"
  Set-EnvValue -Path $Path -Key "C2F_IMAGE_TAG" -Value $VersionTag
  Set-EnvValue -Path $Path -Key "C2F_SKIP_PULL" -Value "false"
}

$Version = Normalize-VersionTag -RawVersion $Version
$imageTag = Get-CleanImageTag -RawVersion $Version

$baseUrl = "https://raw.githubusercontent.com/$Owner/$Repo/$Version/deploy/appliance"
$files = @(
  ".env.patch-workbench.template",
  "docker-compose.patch-workbench.yml",
  "nginx.conf",
  "preflight.ps1",
  "install-patch-workbench.ps1",
  "manage-patch-workbench.ps1",
  "upgrade-patch-workbench.ps1",
  "install-patch-workbench.sh",
  "manage-patch-workbench.sh",
  "upgrade-patch-workbench.sh",
  "README.md"
)

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

foreach ($file in $files) {
  $uri = "$baseUrl/$file"
  $destination = Join-Path $InstallDir $file
  Write-Host "Downloading $file ..."
  Invoke-WebRequest -Uri $uri -OutFile $destination
}

$templatePath = Join-Path $InstallDir ".env.patch-workbench.template"
Update-ImageDefaults -Path $templatePath -Owner $Owner -VersionTag $imageTag

$envPath = Join-Path $InstallDir ".env.patch-workbench"
if (Test-Path $envPath) {
  Update-ImageDefaults -Path $envPath -Owner $Owner -VersionTag $imageTag
}

Get-ChildItem -Path $InstallDir -Recurse -File -ErrorAction SilentlyContinue |
  ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }

if ($PullImages) {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed. Skipping image pulls." -ForegroundColor Yellow
  } else {
    Write-Host "Pulling patch-workbench appliance images ..."
    docker pull "postgres:16"
    docker pull "ghcr.io/$Owner/click2fix-backend-min:$imageTag"
    docker pull "ghcr.io/$Owner/click2fix-frontend-min:$imageTag"
    Set-EnvValue -Path $templatePath -Key "C2F_SKIP_PULL" -Value "true"
    if (Test-Path $envPath) {
      Set-EnvValue -Path $envPath -Key "C2F_SKIP_PULL" -Value "true"
    }
  }
}

Write-Host ""
Write-Host "Patch Workbench bootstrap complete."
Write-Host "Install directory: $InstallDir"
Write-Host "Next step: run `"$InstallDir\install-patch-workbench.ps1`""

if ($LaunchSetup) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallDir "install-patch-workbench.ps1")
}

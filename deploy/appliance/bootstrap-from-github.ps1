param(
  [string]$Owner = "helisudani0",
  [string]$Repo = "click2fix",
  [string]$Version = "v1.1.4",
  [string]$InstallDir = "C:\Click2Fix",
  [switch]$PullImages,
  [switch]$LaunchSetup
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

function Update-ImageDefaults {
  param(
    [string]$Path,
    [string]$Owner,
    [string]$VersionTag
  )
  $cleanTag = $VersionTag.TrimStart("v")
  Set-EnvValue -Path $Path -Key "C2F_BACKEND_IMAGE" -Value "ghcr.io/$Owner/click2fix-backend"
  Set-EnvValue -Path $Path -Key "C2F_FRONTEND_IMAGE" -Value "ghcr.io/$Owner/click2fix-frontend"
  Set-EnvValue -Path $Path -Key "C2F_IMAGE_TAG" -Value $cleanTag
  Set-EnvValue -Path $Path -Key "C2F_SKIP_PULL" -Value "false"
}

if ([string]::IsNullOrWhiteSpace($Version)) {
  throw "Version is required."
}
if (-not $Version.StartsWith("v")) {
  $Version = "v$Version"
}

$baseUrl = "https://raw.githubusercontent.com/$Owner/$Repo/$Version/deploy/appliance"
$files = @(
  ".env.appliance.template",
  "docker-compose.appliance.yml",
  "nginx.conf",
  "preflight.ps1",
  "install.ps1",
  "manage.ps1",
  "upgrade.ps1",
  "setup.cmd",
  "setup.sh",
  "install.sh",
  "manage.sh",
  "upgrade.sh",
  "README.md"
)

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

foreach ($file in $files) {
  $uri = "$baseUrl/$file"
  $destination = Join-Path $InstallDir $file
  Write-Host "Downloading $file ..."
  Invoke-WebRequest -Uri $uri -OutFile $destination
}

$templatePath = Join-Path $InstallDir ".env.appliance.template"
Update-ImageDefaults -Path $templatePath -Owner $Owner -VersionTag $Version

$envPath = Join-Path $InstallDir ".env.appliance"
if (Test-Path $envPath) {
  Update-ImageDefaults -Path $envPath -Owner $Owner -VersionTag $Version
}

Get-ChildItem -Path $InstallDir -Recurse -File -ErrorAction SilentlyContinue |
  ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }

if ($PullImages) {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed. Skipping image pulls." -ForegroundColor Yellow
  } else {
    $tag = $Version.TrimStart("v")
    Write-Host "Pulling appliance images ..."
    docker pull "postgres:16"
    docker pull "ghcr.io/$Owner/click2fix-backend:$tag"
    docker pull "ghcr.io/$Owner/click2fix-frontend:$tag"
    Set-EnvValue -Path $templatePath -Key "C2F_SKIP_PULL" -Value "true"
    if (Test-Path $envPath) {
      Set-EnvValue -Path $envPath -Key "C2F_SKIP_PULL" -Value "true"
    }
  }
}

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host "Install directory: $InstallDir"
Write-Host "Next step: run `"$InstallDir\setup.cmd`""

if ($LaunchSetup) {
  & cmd /c (Join-Path $InstallDir "setup.cmd")
}

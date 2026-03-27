param(
  [Parameter(Mandatory = $false)][string]$Version = "v0.0.0-local",
  [Parameter(Mandatory = $false)][string]$Owner = "your-org",
  [Parameter(Mandatory = $false)][string]$BackendImage = "",
  [Parameter(Mandatory = $false)][string]$FrontendImage = "",
  [Parameter(Mandatory = $false)][string]$ImageTag = ""
)

$ErrorActionPreference = "Stop"

function Test-GitSourceAvailable {
  param(
    [string]$RootDir
  )
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    return $false
  }
  & git -C $RootDir rev-parse --is-inside-work-tree 1>$null 2>$null
  return ($LASTEXITCODE -eq 0)
}

function Test-SourceFileExists {
  param(
    [string]$RootDir,
    [string]$FileSystemPath,
    [string]$RepoRelativePath,
    [bool]$UseGitSource
  )
  if ($UseGitSource) {
    & git -C $RootDir cat-file -e "HEAD:$RepoRelativePath" 2>$null
    return ($LASTEXITCODE -eq 0)
  }
  return (Test-Path $FileSystemPath)
}

function Read-SourceText {
  param(
    [string]$RootDir,
    [string]$FileSystemPath,
    [string]$RepoRelativePath,
    [bool]$UseGitSource
  )
  if ($UseGitSource) {
    return ((& git -C $RootDir show "HEAD:$RepoRelativePath") -join "`n")
  }
  return Get-Content -Path $FileSystemPath -Raw
}

function Export-SourceFile {
  param(
    [string]$RootDir,
    [string]$FileSystemPath,
    [string]$RepoRelativePath,
    [string]$DestinationPath,
    [bool]$UseGitSource
  )
  $parent = Split-Path -Parent $DestinationPath
  if (-not (Test-Path $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  if ($UseGitSource) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($DestinationPath, (Read-SourceText -RootDir $RootDir -FileSystemPath $FileSystemPath -RepoRelativePath $RepoRelativePath -UseGitSource $UseGitSource), $utf8NoBom)
    return
  }
  Copy-Item -Path $FileSystemPath -Destination $DestinationPath -Force
}

function Assert-CurrentApplianceLayout {
  param(
    [string]$RootDir,
    [string]$ApplianceDir,
    [bool]$UseGitSource
  )

  $required = @(
    ".env.appliance.template",
    "docker-compose.appliance.yml",
    "install.sh",
    "setup.sh",
    "manage.sh",
    "upgrade.sh",
    "firstboot/c2f-firstboot.sh",
    "firstboot/c2f-firstboot.service",
    "firstboot/install-firstboot-service.sh"
  )

  foreach ($relativePath in $required) {
    $target = Join-Path $ApplianceDir $relativePath
    if (-not (Test-SourceFileExists -RootDir $RootDir -FileSystemPath $target -RepoRelativePath "deploy/appliance/$relativePath" -UseGitSource $UseGitSource)) {
      throw "Missing required appliance file: $relativePath"
    }
  }

  $composePath = Join-Path $ApplianceDir "docker-compose.appliance.yml"
  $envTemplatePath = Join-Path $ApplianceDir ".env.appliance.template"
  $compose = Read-SourceText -RootDir $RootDir -FileSystemPath $composePath -RepoRelativePath "deploy/appliance/docker-compose.appliance.yml" -UseGitSource $UseGitSource
  $envTemplate = Read-SourceText -RootDir $RootDir -FileSystemPath $envTemplatePath -RepoRelativePath "deploy/appliance/.env.appliance.template" -UseGitSource $UseGitSource

  $forbiddenCompose = @(
    '^\s*agent-manager\s*:',
    '^\s*event-indexer\s*:',
    '^\s*alert-service\s*:',
    '^\s*case-service\s*:',
    '^\s*ingest-gateway\s*:',
    '^\s*soar-service\s*:',
    '^\s*detection-service\s*:'
  )
  foreach ($pattern in $forbiddenCompose) {
    if ($compose -match "(?m)$pattern") {
      throw "The appliance compose file currently includes v2-only services. Clean deploy/appliance/docker-compose.appliance.yml before building current-version OVA assets."
    }
  }

  if ($compose -notmatch '(?m)^\s*db\s*:' -or $compose -notmatch '(?m)^\s*backend\s*:' -or $compose -notmatch '(?m)^\s*frontend\s*:') {
    throw "The appliance compose file must contain db, backend, and frontend services for the current release line."
  }

  $forbiddenEnv = @(
    '^\s*AGENT_MANAGER_IMAGE=',
    '^\s*EVENT_INDEXER_IMAGE=',
    '^\s*ALERT_SERVICE_IMAGE=',
    '^\s*CASE_SERVICE_IMAGE=',
    '^\s*INGEST_GATEWAY_IMAGE=',
    '^\s*SOAR_SERVICE_IMAGE=',
    '^\s*DETECTION_SERVICE_IMAGE='
  )
  foreach ($pattern in $forbiddenEnv) {
    if ($envTemplate -match "(?m)$pattern") {
      throw "The appliance env template currently includes v2-only image settings. Clean deploy/appliance/.env.appliance.template before building current-version OVA assets."
    }
  }
}

function Set-EnvValue {
  param(
    [string]$Path,
    [string]$Key,
    [string]$Value
  )
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

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Resolve-Path (Join-Path $scriptDir "../../..")
$applianceDir = Join-Path $rootDir "deploy/appliance"
$useGitSource = Test-GitSourceAvailable -RootDir $rootDir

Assert-CurrentApplianceLayout -RootDir $rootDir -ApplianceDir $applianceDir -UseGitSource $useGitSource

if ([string]::IsNullOrWhiteSpace($BackendImage)) {
  $BackendImage = "ghcr.io/$Owner/click2fix-backend"
}
if ([string]::IsNullOrWhiteSpace($FrontendImage)) {
  $FrontendImage = "ghcr.io/$Owner/click2fix-frontend"
}
if ([string]::IsNullOrWhiteSpace($ImageTag)) {
  $ImageTag = $Version.TrimStart("v")
}

$outDir = Join-Path $rootDir "deploy/releases/$Version"
$stageDir = Join-Path $outDir "click2fix-appliance-ova-stage-$Version"
$stageRoot = Join-Path $stageDir "opt/click2fix/deploy/appliance"
$stageReadme = Join-Path $stageDir "OVA_STAGE_README.txt"

$applianceFiles = @(
  ".env.appliance.template",
  "bootstrap-from-github.ps1",
  "bootstrap-from-github.sh",
  "build-local-images.ps1",
  "build-local-images.sh",
  "docker-compose.appliance.yml",
  "nginx.conf",
  "export-images.ps1",
  "export-images.sh",
  "import-images.ps1",
  "import-images.sh",
  "install.ps1",
  "install.sh",
  "manage.cmd",
  "manage.ps1",
  "manage.sh",
  "preflight.ps1",
  "README.md",
  "setup.cmd",
  "setup.sh",
  "upgrade.ps1",
  "upgrade.sh",
  "firstboot/c2f-firstboot.service",
  "firstboot/c2f-firstboot.sh",
  "firstboot/install-firstboot-service.sh"
)

if (Test-Path $stageDir) {
  Remove-Item -Path $stageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
foreach ($file in $applianceFiles) {
  Export-SourceFile `
    -RootDir $rootDir `
    -FileSystemPath (Join-Path $applianceDir $file) `
    -RepoRelativePath "deploy/appliance/$file" `
    -DestinationPath (Join-Path $stageRoot $file) `
    -UseGitSource $useGitSource
}

$envFile = Join-Path $stageRoot ".env.appliance.template"
Set-EnvValue -Path $envFile -Key "C2F_BACKEND_IMAGE" -Value $BackendImage
Set-EnvValue -Path $envFile -Key "C2F_FRONTEND_IMAGE" -Value $FrontendImage
Set-EnvValue -Path $envFile -Key "C2F_IMAGE_TAG" -Value $ImageTag
Set-EnvValue -Path $envFile -Key "C2F_SKIP_PULL" -Value "false"

@"
Click2Fix OVA Stage Bundle
==========================

Version: $Version
Backend image: ${BackendImage}:${ImageTag}
Frontend image: ${FrontendImage}:${ImageTag}
Database image: postgres:16

This staged directory is intended to be copied into a Linux VM image at:

  /opt/click2fix/deploy/appliance

Recommended VM build flow:

1. Start from Ubuntu Server LTS.
2. Install Docker Engine and the Docker Compose plugin inside the VM.
3. Copy the staged opt/ tree from this bundle into the VM root filesystem.
4. Inside the VM, run:

     cd /opt/click2fix/deploy/appliance/firstboot
     sudo ./install-firstboot-service.sh

5. Power off the VM and export it as an OVA from your hypervisor.

When the customer boots the VM, the first-boot unit launches the existing
Click2Fix installer and keeps the runtime on the supported v1.1.4 image set.
"@ | Set-Content -Path $stageReadme

Write-Host "Built OVA stage bundle:"
Write-Host "  $stageDir"
Write-Host ""
Write-Host "Next step:"
Write-Host "  Copy the staged opt/ tree into a Linux VM image and install the first-boot service."

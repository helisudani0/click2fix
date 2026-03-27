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

  $composePath = Join-Path $ApplianceDir "docker-compose.appliance.yml"
  $envTemplatePath = Join-Path $ApplianceDir ".env.appliance.template"
  foreach ($required in @("docker-compose.appliance.yml", ".env.appliance.template")) {
    if (-not (Test-SourceFileExists -RootDir $RootDir -FileSystemPath (Join-Path $ApplianceDir $required) -RepoRelativePath "deploy/appliance/$required" -UseGitSource $UseGitSource)) {
      throw "Missing required appliance file: $required"
    }
  }
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
      throw "The appliance compose file currently includes v2-only services. Clean deploy/appliance/docker-compose.appliance.yml before building the current release bundle."
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
      throw "The appliance env template currently includes v2-only image settings. Clean deploy/appliance/.env.appliance.template before building the current release bundle."
    }
  }
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
$bundleDir = Join-Path $outDir "click2fix-appliance-$Version"
$zipFile = Join-Path $outDir "click2fix-appliance-installer-$Version.zip"
$shaFile = Join-Path $outDir "click2fix-appliance-installer-$Version.sha256"
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

if (Test-Path $bundleDir) { Remove-Item -Path $bundleDir -Recurse -Force }
if (Test-Path $zipFile) { Remove-Item -Path $zipFile -Force }
if (Test-Path $shaFile) { Remove-Item -Path $shaFile -Force }
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

foreach ($file in $applianceFiles) {
  Export-SourceFile `
    -RootDir $rootDir `
    -FileSystemPath (Join-Path $applianceDir $file) `
    -RepoRelativePath "deploy/appliance/$file" `
    -DestinationPath (Join-Path $bundleDir $file) `
    -UseGitSource $useGitSource
}

$envFile = Join-Path $bundleDir ".env.appliance.template"
if (-not (Test-Path -LiteralPath $envFile)) {
  throw "Expected env template missing after export: $envFile"
}
$content = Get-Content -Path $envFile
$content = $content -replace '^C2F_BACKEND_IMAGE=.*$', "C2F_BACKEND_IMAGE=$BackendImage"
$content = $content -replace '^C2F_FRONTEND_IMAGE=.*$', "C2F_FRONTEND_IMAGE=$FrontendImage"
$content = $content -replace '^C2F_IMAGE_TAG=.*$', "C2F_IMAGE_TAG=$ImageTag"
$content = $content -replace '^C2F_SKIP_PULL=.*$', "C2F_SKIP_PULL=false"
Set-Content -Path $envFile -Value $content

# Compress-Archive on PowerShell/Linux can fail to resolve dotfiles (for example
# .env.appliance.template). Build the zip via .NET APIs so hidden files are
# always included consistently across Windows/Linux runners.
if (Test-Path -LiteralPath $zipFile) {
  Remove-Item -Path $zipFile -Force
}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipArchive = [System.IO.Compression.ZipFile]::Open(
  $zipFile,
  [System.IO.Compression.ZipArchiveMode]::Create
)
try {
  $bundleFiles = Get-ChildItem -LiteralPath $bundleDir -Recurse -Force -File
  $bundleRoot = (Resolve-Path -LiteralPath $bundleDir).Path.TrimEnd('\', '/')
  foreach ($file in $bundleFiles) {
    $fullPath = (Resolve-Path -LiteralPath $file.FullName).Path
    $entryName = $fullPath.Substring($bundleRoot.Length).TrimStart('\', '/').Replace('\', '/')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zipArchive,
      $file.FullName,
      $entryName,
      [System.IO.Compression.CompressionLevel]::Optimal
    ) | Out-Null
  }
} finally {
  $zipArchive.Dispose()
}

$hash = Get-FileHash -Path $zipFile -Algorithm SHA256
"$($hash.Hash.ToLower())  $(Split-Path $zipFile -Leaf)" | Set-Content -Path $shaFile

Write-Host "Built installer bundle:"
Write-Host "  $zipFile"
Write-Host "  $shaFile"

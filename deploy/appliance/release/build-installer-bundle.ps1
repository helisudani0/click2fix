param(
  [Parameter(Mandatory = $false)][string]$Version = "v0.0.0-local",
  [Parameter(Mandatory = $false)][string]$Owner = "your-org",
  [Parameter(Mandatory = $false)][string]$BackendImage = "",
  [Parameter(Mandatory = $false)][string]$FrontendImage = "",
  [Parameter(Mandatory = $false)][string]$ImageTag = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Resolve-Path (Join-Path $scriptDir "../../..")
$applianceDir = Join-Path $rootDir "deploy/appliance"

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

if (Test-Path $bundleDir) { Remove-Item -Path $bundleDir -Recurse -Force }
if (Test-Path $zipFile) { Remove-Item -Path $zipFile -Force }
if (Test-Path $shaFile) { Remove-Item -Path $shaFile -Force }
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Copy-Item -Path "$applianceDir/*" -Destination $bundleDir -Recurse -Force

$envFile = Join-Path $bundleDir ".env.appliance.template"
$content = Get-Content -Path $envFile
$content = $content -replace '^C2F_BACKEND_IMAGE=.*$', "C2F_BACKEND_IMAGE=$BackendImage"
$content = $content -replace '^C2F_FRONTEND_IMAGE=.*$', "C2F_FRONTEND_IMAGE=$FrontendImage"
$content = $content -replace '^C2F_IMAGE_TAG=.*$', "C2F_IMAGE_TAG=$ImageTag"
$content = $content -replace '^C2F_SKIP_PULL=.*$', "C2F_SKIP_PULL=false"
Set-Content -Path $envFile -Value $content

Compress-Archive -Path "$bundleDir/*" -DestinationPath $zipFile -CompressionLevel Optimal -Force

$hash = Get-FileHash -Path $zipFile -Algorithm SHA256
"$($hash.Hash.ToLower())  $(Split-Path $zipFile -Leaf)" | Set-Content -Path $shaFile

Write-Host "Built installer bundle:"
Write-Host "  $zipFile"
Write-Host "  $shaFile"

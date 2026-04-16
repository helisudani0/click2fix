param(
  [string]$Root = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$ErrorActionPreference = "Stop"

function Unblock-Click2FixBundle {
  param([string]$PathRoot)
  if ([string]::IsNullOrWhiteSpace($PathRoot) -or -not (Test-Path $PathRoot)) { return }
  try {
    Get-ChildItem -Path $PathRoot -Recurse -File -ErrorAction SilentlyContinue |
      ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }
  } catch {
    Write-Host "Warning: Unable to remove download security markers for some files." -ForegroundColor Yellow
  }
}

function Get-ZoneMarkedFiles {
  param([string]$PathRoot, [string[]]$FilesToCheck)
  $blocked = @()
  foreach ($file in $FilesToCheck) {
    $target = Join-Path $PathRoot $file
    if (-not (Test-Path $target)) { continue }
    try {
      $stream = Get-Item -Path $target -Stream Zone.Identifier -ErrorAction SilentlyContinue
      if ($stream) { $blocked += $file }
    } catch {}
  }
  return $blocked
}

$fullRequired = @(
  "install.ps1",
  "manage.ps1",
  "upgrade.ps1",
  "docker-compose.appliance.yml",
  "nginx.conf",
  ".env.appliance.template",
  "setup.cmd"
)

$patchWorkbenchRequired = @(
  "install-patch-workbench.ps1",
  "manage-patch-workbench.ps1",
  "upgrade-patch-workbench.ps1",
  "install-patch-workbench.sh",
  "manage-patch-workbench.sh",
  "upgrade-patch-workbench.sh",
  "docker-compose.patch-workbench.yml",
  "nginx.conf",
  ".env.patch-workbench.template",
  "README.md"
)

$isPatchWorkbenchBundle = (Test-Path (Join-Path $Root "docker-compose.patch-workbench.yml")) -or
  (Test-Path (Join-Path $Root "install-patch-workbench.ps1")) -or
  (Test-Path (Join-Path $Root "manage-patch-workbench.ps1"))

$required = if ($isPatchWorkbenchBundle) { $patchWorkbenchRequired } else { $fullRequired }

Unblock-Click2FixBundle -PathRoot $Root

$missing = @()
foreach ($file in $required) {
  if (-not (Test-Path (Join-Path $Root $file))) { $missing += $file }
}

$blocked = Get-ZoneMarkedFiles -PathRoot $Root -FilesToCheck $required

if ($missing.Count -gt 0) {
  Write-Host "ERROR: Installer files are missing: $($missing -join ', ')." -ForegroundColor Red
  Write-Host "This is usually caused by security software quarantining files after extraction." -ForegroundColor Yellow
  Write-Host "Re-extract the ZIP to a clean folder and allowlist the installer hash or folder if needed." -ForegroundColor Yellow
  throw "Installer preflight failed due to missing files."
}

if ($blocked.Count -gt 0) {
  Write-Host "Warning: Some files still have download security markers: $($blocked -join ', ')." -ForegroundColor Yellow
  Write-Host "If script execution fails, run Unblock-File recursively on the installer folder." -ForegroundColor Yellow
}

Write-Host "Installer preflight completed." -ForegroundColor Green

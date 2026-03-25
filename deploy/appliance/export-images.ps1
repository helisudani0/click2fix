param(
  [string]$EnvFile = ".env.appliance",
  [string]$OutputFile = "click2fix-images.tar"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $scriptDir $EnvFile
$outputPath = Join-Path $scriptDir $OutputFile

function Get-EnvValue {
  param(
    [string]$Path,
    [string]$Key,
    [string]$Default = ""
  )
  if (-not (Test-Path $Path)) { return $Default }
  $line = (Get-Content -Path $Path | Where-Object { $_ -match "^\s*$Key=" } | Select-Object -First 1)
  if (-not $line) { return $Default }
  $value = ($line -replace "^\s*$Key=", "")
  if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
  return $value
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

$backendImage = Get-EnvValue -Path $envPath -Key "C2F_BACKEND_IMAGE" -Default "click2fix-backend"
$frontendImage = Get-EnvValue -Path $envPath -Key "C2F_FRONTEND_IMAGE" -Default "click2fix-frontend"
$postgresImageTag = Get-EnvValue -Path $envPath -Key "POSTGRES_IMAGE_TAG" -Default "16"
$imageTag = Get-EnvValue -Path $envPath -Key "C2F_IMAGE_TAG" -Default "local"
$postgresImage = "postgres:$postgresImageTag"

try {
  Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", $postgresImage) -FailureMessage "Postgres image not found locally."
} catch {
  Write-Host "Pulling $postgresImage ..." -ForegroundColor Yellow
  Invoke-NativeChecked -FilePath "docker" -Arguments @("pull", $postgresImage) -FailureMessage "Failed to pull $postgresImage."
}
Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", "$backendImage`:$imageTag") -FailureMessage "Backend image not found locally."
Invoke-NativeChecked -FilePath "docker" -Arguments @("image", "inspect", "$frontendImage`:$imageTag") -FailureMessage "Frontend image not found locally."

Write-Host "Exporting images to $outputPath ..."
docker save -o $outputPath $postgresImage "$backendImage`:$imageTag" "$frontendImage`:$imageTag"
Write-Host "Export complete."

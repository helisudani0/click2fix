param(
  [Parameter(Mandatory = $true)]
  [string]$Version,
  [Parameter(Mandatory = $true)]
  [string]$SourceOvaPath,
  [string]$AssetName
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = Resolve-Path (Join-Path $scriptDir "..\..\..")

$resolvedSource = Resolve-Path -LiteralPath $SourceOvaPath -ErrorAction Stop
if (-not $AssetName) {
  $AssetName = "click2fix-appliance-$Version.ova"
}

$outDir = Join-Path $rootDir "deploy\releases\$Version"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$targetOva = Join-Path $outDir $AssetName
Copy-Item -LiteralPath $resolvedSource -Destination $targetOva -Force

$hash = (Get-FileHash -Path $targetOva -Algorithm SHA256).Hash.ToLowerInvariant()
$shaFile = "$targetOva.sha256"
$shaLine = "$hash  $(Split-Path -Leaf $targetOva)"
Set-Content -Path $shaFile -Value $shaLine

Write-Host "Prepared OVA release assets:"
Write-Host "  $targetOva"
Write-Host "  $shaFile"
Write-Host ""
Write-Host "Upload both files to the GitHub release for $Version."

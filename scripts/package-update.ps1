[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$PackageName,
    
    [Parameter(Mandatory=$false)]
    [string]$Version = "latest",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Package ID mapping regex patterns
$PackageMapping = @{
    'vcredist' = @{
        'winget' = 'Microsoft.VisualC.Redistributable.x64'
        'apt'    = 'libstdc++6'
        'regex'  = '^(vc|visual.*redist)'
    }
    'dotnet' = @{
        'winget' = 'Microsoft.DotNet.Runtime.8'
        'apt'    = 'dotnet-runtime-8.0'
        'regex'  = '^dotnet.*(\d+\.\d+)?'
    }
    'python' = @{
        'winget' = 'Python.Python.3.11'
        'apt'    = 'python3.11'
        'regex'  = '^python\d+\.\d+'
    }
    'git' = @{
        'winget' = 'Git.Git'
        'apt'    = 'git'
        'regex'  = '^git$'
    }
}

function Test-SourceAvailable {
    [CmdletBinding()]
    param(
        [string]$PackageId,
        [string]$Manager
    )
    
    try {
        if ($Manager -eq "winget") {
            $result = & winget search --id $PackageId --exact 2>&1
            if ($LASTEXITCODE -eq 0 -and $result -notmatch "No packages found") {
                return $true
            }
        }
        elseif ($Manager -eq "apt") {
            $result = apt-cache search "^$PackageId" 2>&1
            if ($LASTEXITCODE -eq 0 -and $result -notmatch "^$") {
                return $true
            }
        }
        return $false
    }
    catch {
        Write-Verbose "SOURCE_UNAVAILABLE: $_"
        return $false
    }
}

function Resolve-PackageId {
    [CmdletBinding()]
    param(
        [string]$InputPackage,
        [string]$Manager
    )
    
    $normalized = $InputPackage.ToLower() -replace '[^a-z0-9\.]', ''
    
    foreach ($entry in $PackageMapping.GetEnumerator()) {
        $pattern = $entry.Value['regex']
        if ($normalized -match $pattern) {
            return $entry.Value[$Manager]
        }
    }
    
    return $normalized
}

function Install-Package {
    [CmdletBinding()]
    param(
        [string]$PackageId,
        [string]$Manager,
        [string]$Version = "latest"
    )
    
    Write-Verbose "Installing $PackageId via $Manager (version: $Version)"
    
    if ($Manager -eq "winget") {
        if ($Version -eq "latest") {
            & winget install --id $PackageId --accept-source-agreements --accept-package-agreements
        } else {
            & winget install --id $PackageId --version $Version --accept-source-agreements --accept-package-agreements
        }
    }
    elseif ($Manager -eq "apt") {
        if ($Version -eq "latest") {
            & apt-get install -y $PackageId
        } else {
            & apt-get install -y "$PackageId=$Version*"
        }
    }
    
    if ($LASTEXITCODE -eq 0) {
        return @{ status = "success"; package = $PackageId; manager = $Manager }
    } else {
        return @{ status = "failed"; package = $PackageId; manager = $Manager; error = "Installation exited with code $LASTEXITCODE" }
    }
}

# Main execution
try {
    # Detect OS and package manager
    $isWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    $Manager = if ($isWindows) { "winget" } else { "apt" }
    
    Write-Host "Detected package manager: $Manager" -ForegroundColor Cyan
    
    # Normalize package ID
    $ResolvedPackageId = Resolve-PackageId -InputPackage $PackageName -Manager $Manager
    
    # Pre-flight SOURCE_UNAVAILABLE check
    Write-Verbose "Performing pre-flight SOURCE_UNAVAILABLE check for $ResolvedPackageId"
    if (-not (Test-SourceAvailable -PackageId $ResolvedPackageId -Manager $Manager)) {
        throw "SOURCE_UNAVAILABLE: Package '$ResolvedPackageId' not found in $Manager repository"
    }
    
    # Install package
    $result = Install-Package -PackageId $ResolvedPackageId -Manager $Manager -Version $Version
    
    # Output result as JSON
    $result | ConvertTo-Json | Write-Host
    exit 0
}
catch {
    $errorResult = @{
        status  = "error"
        package = $PackageName
        error   = $_.Exception.Message
    }
    $errorResult | ConvertTo-Json | Write-Error
    exit 1
}

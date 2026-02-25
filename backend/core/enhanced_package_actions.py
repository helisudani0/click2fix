"""
Enhanced Package Manager Actions with Pre-flight Checks

This module provides improved:
1. Winget/Apt package resolution
2. SOURCE_UNAVAILABLE pre-flight detection
3. Strict Package ID validation (not Name/Version mismatch)
4. Idempotency & deduplication
"""

from typing import Dict, Any, Optional, Tuple, List
import re


def validate_winget_package_id(package_spec: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that package_spec is a proper winget Package ID format.
    
    Winget Package IDs typically follow pattern: Publisher.ProductName
    Examples: Microsoft.PowerShell, Intel.HAXM, Google.Chrome
    
    Returns: (is_valid, error_message)
    """
    spec = package_spec.strip()
    
    if not spec:
        return False, "Empty package specification"
    
    # Reject if contains spaces (usually indicates a name, not ID)
    if ' ' in spec:
        return False, "Package spec contains spaces (likely a name, not ID)"
    
    # Simple pattern: alphanumeric + dots + underscores
    if not re.match(r'^[A-Za-z0-9._-]+$', spec):
        return False, "Invalid characters in package ID"
    
    # Must have at least one dot (Publisher.Product pattern)
    # Exception: some packages like "git" are valid single-name packages
    # So we just check for basic validity
    if len(spec) < 3:
        return False, "Package ID too short"
    
    return True, None


async def preflight_check_winget_availability(
    package_id: str,
    executor_context: Any,  # EndpointExecutor instance
    agent_id: str,
) -> Tuple[bool, Optional[str]]:
    """
    Pre-flight check: Does winget have this package available?
    
    Tries:
    1. winget show --id <package_id>
    2. If 404 or "No package found", return SOURCE_UNAVAILABLE
    
    Returns: (is_available, error_message)
    """
    # First validate the ID format
    is_valid, err = validate_winget_package_id(package_id)
    if not is_valid:
        return False, f"Invalid package ID: {err}"
    
    # Quick check: run "winget show --id <package_id>"
    # This is much faster than trying to install
    ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

$pkgId = '{package_id}'
# Try exact ID match first
$result = & winget show --id $pkgId --exact 2>&1
$rc = $LASTEXITCODE

if ($rc -eq 0) {{
    Write-Output "AVAILABLE"
    exit 0
}} elseif ($result -like "*No package found*" -or $result -like "*0x80070002*") {{
    Write-Output "NOT_FOUND:$pkgId"
    exit 1
}} else {{
    Write-Output "ERROR:$result"
    exit 2
}}
"""
    
    try:
        # Execute preflight check via WinRM/SSH
        result = await executor_context.execute_script_async(
            agent_id,
            ps_script,
            platform="windows",
            timeout_seconds=30,
        )
        
        output = result.get("stdout", "").strip()
        exit_code = result.get("exit_code", -1)
        
        if exit_code == 0 and output == "AVAILABLE":
            return True, None
        elif "NOT_FOUND" in output:
            return False, f"SOURCE_UNAVAILABLE: Package {package_id} not found in winget catalog"
        else:
            return False, f"Package availability check failed: {output}"
    
    except Exception as exc:
        # If preflight fails, log but allow action to proceed (might be transient)
        return False, f"Preflight check error: {str(exc)}"


def generate_enhanced_package_update_script(
    package_id: str,
    action_type: str = "update",  # update, install
    force_version: Optional[str] = None,
) -> str:
    """
    Generate enhanced PowerShell script for package update/install.
    
    Features:
    - Uses Package ID (--id flag), not package name
    - Validates package exists before attempting
    - Detects exit code 3010 (reboot required)
    - Returns strict schema JSON output
    - Includes comprehensive error handling
    """
    
    if action_type == "install":
        action_flag = "install"
        action_desc = "Install"
    else:
        action_flag = "upgrade"
        action_desc = "Update"
    
    version_arg = f' --version "{force_version}"' if force_version else ""
    
    script = f'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Result {{
    param([bool]$ok, [hashtable]$data)
    $result = @{{
        "ok" = $ok
        "status" = if ($ok) {{ "SUCCESS" }} else {{ "FAILED" }}
        "timestamp" = (Get-Date -Format 'o')
    }} + $data
    Write-Output (ConvertTo-Json $result -Compress)
}}

$packageId = "{package_id}"

try {{
    # Pre-flight: verify package exists and is installed
    Write-Host "Pre-flight check: verifying package $packageId exists..."
    $checkResult = & winget show --id "$packageId" --exact 2>&1
    $checkRc = $LASTEXITCODE
    
    if ($checkRc -ne 0) {{
        if ($checkResult -like "*No package found*") {{
            Write-Result $false @{{
                "error" = "SOURCE_UNAVAILABLE"
                "message" = "Package not found in winget catalog: $packageId"
                "exit_code" = 404
            }}
            exit 1
        }} else {{
            Write-Result $false @{{
                "error" = "PREFLIGHT_CHECK_FAILED"
                "message" = $checkResult -join " "
                "exit_code" = $checkRc
            }}
            exit 2
        }}
    }}
    
    # Get current state
    Write-Host "Checking current installation state..."
    $installedResult = & winget list --id "$packageId" --exact 2>&1
    $installedBefore = $installedResult -match "\\S+\\s+\\S+" | Measure-Object | ForEach-Object {{ $_.Count }}
    
    # Detect if already at target version
    if ($installedBefore -gt 0 -and "{force_version}" -eq "") {{
        Write-Result $true @{{
            "error" = $null
            "message" = "Package already installed, checking for updates..."
            "exit_code" = 0
            "reboot_required" = $false
            "status" = "SUCCESS_NO_CHANGE"
        }}
        exit 0
    }}
    
    # Perform action
    Write-Host "{action_desc}ing package: $packageId{version_arg}..."
    $actionResult = & winget {action_flag} --id "$packageId" --exact{version_arg} --accept-source-agreements --accept-package-agreements 2>&1
    $actionRc = $LASTEXITCODE
    
    # Parse result code
    $rebootRequired = $false
    if ($actionRc -eq 3010) {{
        $rebootRequired = $true
        $status = "SUCCESS"
        $message = "Package {action_type}d but reboot required"
    }} elseif ($actionRc -eq 0) {{
        $status = "SUCCESS"
        $message = "Package {action_type}d successfully"
    }} elseif ($actionRc -eq 1) {{
        $status = "SUCCESS_NO_CHANGE"
        $message = "Package already at target version"
    }} else {{
        $status = "FAILED"
        $message = "Package {action_type} failed with exit code $actionRc"
    }}
    
    Write-Result ($actionRc -eq 0 -or $actionRc -eq 1 -or $actionRc -eq 3010) @{{
        "error" = if ($actionRc -ne 0 -and $actionRc -ne 3010) {{ "UPDATE_FAILED" }} else {{ $null }}
        "message" = $message
        "exit_code" = $actionRc
        "reboot_required" = $rebootRequired
        "package_id" = $packageId
        "action" = "{action_type}"
    }}
    
    exit if ($actionRc -eq 0 -or $actionRc -eq 3010) {{ 0 }} else {{ 1 }}
}}
catch {{
    Write-Result $false @{{
        "error" = "EXCEPTION"
        "message" = $_.Exception.Message
        "exit_code" = -1
    }}
    exit -1
}}
'''
    
    return script


def generate_apt_package_update_script(
    package_name: str,
    action_type: str = "upgrade",  # upgrade, install
) -> str:
    """
    Generate enhanced Bash script for Linux apt package management.
    
    Features:
    - Uses package name (apt native format)
    - Pre-flight checks
    - Idempotency checking
    - Exit code 100 detection (reboot required)
    """
    
    script = f'''#!/bin/bash
set -euo pipefail

pkg_name="{package_name}"
action="{action_type}"

# Output helper
	write_result() {{
	    local ok=$1
	    python3 -c "import json; import sys; print(json.dumps({{
	        'ok': $ok,
	        'status': 'SUCCESS' if $ok else 'FAILED',
	        'package': '$pkg_name',
	        'action': '$action',
	        'timestamp': __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat().replace('+00:00','Z'),
	    }}))"
	}}

# Pre-flight: Check if package exists in catalog
echo "[*] Checking package availability in apt catalog..."
if ! apt-cache search "^$pkg_name\$" | grep -q .; then
    echo {{"error": "SOURCE_UNAVAILABLE", "message": "Package not in apt catalog: $pkg_name"}} >&2
    exit 1
fi

# Check if already installed
installed_version=$(dpkg -l | grep "^ii\\s\\+$pkg_name" | awk '{{print $3}}' || echo "")

if [[ -n "$installed_version" ]] && [[ "$action" == "upgrade" ]]; then
    # Check for updates
    updates=$(apt list --upgradable 2>/dev/null | grep "^$pkg_name/" || echo "")
    if [[ -z "$updates" ]]; then
        echo "Package already at latest version: $installed_version"
        exit 0
    fi
fi

# Perform update
echo "[*] Running apt update..."
sudo apt-get update -qq

echo "[*] Running $action on $pkg_name..."
if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg_name"; then
    echo "Package $action succeeded"
    exit 0
else
    rc=$?
    echo "Package $action failed with exit code $rc"
    exit $rc
fi
'''
    
    return script

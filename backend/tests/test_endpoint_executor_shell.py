from __future__ import annotations

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.endpoint_executor import EndpointExecutor  # noqa: E402


def _executor() -> EndpointExecutor:
    executor = EndpointExecutor.__new__(EndpointExecutor)
    executor.default_timeout = 120
    return executor


def test_effective_timeout_extends_install_update_actions():
    executor = _executor()

    assert executor._effective_action_timeout_seconds("package-update", ["Git.Git"], {}) >= 3600
    assert executor._effective_action_timeout_seconds("software-install-upgrade", ["Git.Git"], {}) >= 3600
    assert executor._effective_action_timeout_seconds("windows-os-update", [], {}) >= 5400


def test_effective_timeout_extends_long_running_global_shell_commands():
    executor = _executor()

    assert (
        executor._effective_action_timeout_seconds(
            "custom-os-command",
            ["Invoke-WebRequest -Uri 'https://example.invalid/pkg.msi' -OutFile $env:TEMP\\pkg.msi; msiexec /i $env:TEMP\\pkg.msi /qn"],
            {"action_id": "global-shell"},
        )
        >= 3600
    )
    assert (
        executor._effective_action_timeout_seconds(
            "custom-os-command",
            ["Get-ComputerInfo | Select-Object WindowsVersion"],
            {},
        )
        == executor._action_timeout_seconds("custom-os-command")
    )


def test_custom_os_command_script_executes_uploaded_file_directly():
    executor = _executor()

    script = executor._windows_action_script_content("custom-os-command")

    assert "function C2F-RunCommandFile" in script
    assert "& $CommandFile 2>&1 | Out-String" in script
    assert "C2F-RunCommandFile -CommandPath $CommandFile" in script
    assert "ScriptBlock]::Create($CommandText)" not in script


def test_package_update_script_contains_winget_bootstrap_path():
    executor = _executor()

    script = executor._windows_action_script_content("package-update")

    assert "Install-Module -Name Microsoft.WinGet.Client" in script
    assert "Repair-WinGetPackageManager" in script
    assert "Automatic App Installer/Repair-WinGetPackageManager bootstrap was attempted" in script

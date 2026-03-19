from __future__ import annotations

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.action_execution import _requires_endpoint_transport  # noqa: E402
from core.endpoint_executor import (  # noqa: E402
    EndpointExecutor,
    _ps_encoded_command,
    _ps_encoded_command_args,
)


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


def test_windows_custom_command_normalization_unwraps_powershell_command():
    wrapped_command = 'powershell.exe -Command "Invoke-WebRequest -Uri https://example.com/pkg.msi -OutFile $env:TEMP\\\\pkg.msi"'

    normalized = EndpointExecutor._normalize_windows_custom_command(wrapped_command)

    assert normalized == "Invoke-WebRequest -Uri https://example.com/pkg.msi -OutFile $env:TEMP\\\\pkg.msi"


def test_windows_custom_command_normalization_decodes_encoded_powershell_wrapper():
    inner = "Invoke-WebRequest -Uri https://example.com/pkg.msi -OutFile $env:TEMP\\pkg.msi"
    wrapped_command = "powershell.exe " + " ".join(_ps_encoded_command_args(inner))

    normalized = EndpointExecutor._normalize_windows_custom_command(wrapped_command)

    assert normalized == inner


def test_powershell_transport_uses_explicit_encoded_command():
    command = "Write-Output 'transport-ok'"

    args = _ps_encoded_command_args(command)

    assert args[:4] == ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
    assert args[4] == "-EncodedCommand"
    assert _ps_encoded_command(command) == args[5]


def test_package_update_script_contains_winget_bootstrap_path():
    executor = _executor()

    script = executor._windows_action_script_content("package-update")

    assert "Install-Module -Name Microsoft.WinGet.Client" in script
    assert "Repair-WinGetPackageManager" in script
    assert "Automatic App Installer/Repair-WinGetPackageManager bootstrap was attempted" in script
    assert "post_verify_fresh_install_present_no_version" in script
    assert "post_verify_present_after_unknown_before" in script
    assert "afterInstalledDetected = (($afterRows -and $afterRows.Count -gt 0) -or $afterArpPresent)" in script
    assert "if (Test-C2FNoiseLine $lineNorm) { continue }" in script
    assert "$skippedNoChange++" in script


def test_global_shell_requires_endpoint_transport():
    assert _requires_endpoint_transport("global-shell", {"action_command": "custom-os-command"}) is True
    assert _requires_endpoint_transport("custom-os-command", {"action_command": "custom-os-command"}) is True
    assert _requires_endpoint_transport("firewall-drop", {"action_command": "firewall-drop"}) is False

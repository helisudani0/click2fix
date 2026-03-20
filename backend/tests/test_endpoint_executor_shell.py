from __future__ import annotations

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import actions as actions_api  # noqa: E402
from api.actions import _coerce_custom_os_command_arguments  # noqa: E402
from core import action_execution as action_execution_module  # noqa: E402
from core.action_execution import _requires_endpoint_transport  # noqa: E402
from core.endpoint_executor import (  # noqa: E402
    EndpointExecutor,
    _ps_encoded_command,
    _ps_encoded_command_args,
)
from core.wazuh_verification import PostActionVerificationLoop, derive_verification_state  # noqa: E402


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
        == 300
    )
    assert (
        executor._effective_action_timeout_seconds(
            "custom-os-command",
            ["Get-ComputerInfo | Select-Object WindowsVersion"],
            {},
        )
        == executor._action_timeout_seconds("custom-os-command")
    )


def test_custom_os_command_script_executes_encoded_powershell_payload():
    executor = _executor()

    script = executor._windows_action_script_content("custom-os-command")

    assert "function C2F-LoadCommandPayload" in script
    assert "function C2F-RunEncodedCommand" in script
    assert "function C2F-RunSessionCommand" in script
    assert "function C2F-EnsureSessionHost" in script
    assert '-EncodedCommand", $EncodedCommand' in script
    assert "C2F-RunEncodedCommand -EncodedCommand $encodedCommand" in script
    assert "C2F-RunSessionCommand -Id $sessionKey" in script
    assert "ScriptBlock]::Create($CommandText)" not in script
    assert "[string]$SessionId" in script
    assert "IdleTimeoutSeconds = 1800" in script


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
    assert "reason=already_target_state" in script
    assert "afterInstalledDetected = (($afterRows -and $afterRows.Count -gt 0) -or $afterArpPresent)" in script
    assert "if (Test-C2FNoiseLine $lineNorm) { continue }" in script
    assert "$skippedNoChange++" in script
    assert "$zeroSkippedProblem = [Math]::Max(0, ($skipped - $skippedNotInstalled - $skippedNoChange))" in script


def test_global_shell_requires_endpoint_transport():
    assert _requires_endpoint_transport("global-shell", {"action_command": "custom-os-command"}) is True
    assert _requires_endpoint_transport("custom-os-command", {"action_command": "custom-os-command"}) is True
    assert _requires_endpoint_transport("firewall-drop", {"action_command": "firewall-drop"}) is False


def test_custom_os_command_arguments_preserve_session_id():
    args = _coerce_custom_os_command_arguments([], command="Write-Host hi")
    assert args == ["Write-Host hi", "", "", "", "false", ""]

    preserved = _coerce_custom_os_command_arguments(
        ["Write-Host hi", "", "", "", "false", "session-2"],
        command="Write-Host hi",
        session_id="session-2",
    )
    assert preserved == ["Write-Host hi", "", "", "", "false", "session-2"]


def test_async_global_shell_builds_dispatch_for_powershell(monkeypatch):
    class _DummyResult:
        def __init__(self, scalar_value=None):
            self._scalar_value = scalar_value

        def scalar(self):
            return self._scalar_value

    class _DummyDB:
        def execute(self, *_args, **_kwargs):
            return _DummyResult(None)

        def commit(self):
            return None

        def close(self):
            return None

    dispatch_calls = []

    monkeypatch.setattr(actions_api, "connect", lambda: _DummyDB())
    monkeypatch.setattr(actions_api, "publish_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(actions_api, "_store_execution_targets", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        actions_api,
        "enforce_command_safety",
        lambda *_args, **_kwargs: {"risk_score": 0, "reasons": []},
    )

    def _fake_build_dispatch(**kwargs):
        dispatch_calls.append(kwargs)
        return {"transport": "custom-os-command"}, ["Write-Host hi", "", "", "", "false", "session-alpha"]

    monkeypatch.setattr(actions_api, "_build_global_shell_dispatch", _fake_build_dispatch)
    monkeypatch.setattr(
        actions_api,
        "execute_action",
        lambda *_args, **_kwargs: {
            "channel": "endpoint",
            "mode": "endpoint",
            "result": {
                "success": 1,
                "failed": 0,
                "total": 1,
                "results": [{"agent_id": "001", "ok": True, "stdout": "ok", "stderr": ""}],
            },
        },
    )

    actions_api._run_global_shell_async_job(
        execution_id=999,
        action_id="global-shell",
        shell="powershell",
        selected_ids=["001"],
        raw_command="Write-Host hi",
        run_as_system=False,
        session_id="session-alpha",
        ai_config={"provider": "openai", "model": "test-model"},
    )

    assert dispatch_calls
    assert dispatch_calls[0]["command_to_run"] == "Write-Host hi"
    assert dispatch_calls[0]["session_id"] == "session-alpha"


def test_execute_serializes_custom_os_command_targets():
    executor = EndpointExecutor.__new__(EndpointExecutor)
    executor.max_workers = 8
    executor.stop_on_error = False
    executor.windows_patch_stagger_seconds = 0
    executor.windows_patch_stagger_min_targets = 5

    target_rows = {
        "001": {"agent_id": "001", "agent_name": "alpha", "ip": "10.0.0.1", "platform": "windows"},
        "002": {"agent_id": "002", "agent_name": "beta", "ip": "10.0.0.2", "platform": "windows"},
        "003": {"agent_id": "003", "agent_name": "gamma", "ip": "10.0.0.3", "platform": "windows"},
    }
    order = []

    executor._build_agent_lookup = lambda agent_ids: {agent_id: {} for agent_id in agent_ids}
    executor._resolve_agent_target = lambda agent_id, agent_lookup=None: target_rows[agent_id]
    executor._guard_task_ingestion_for_memory = lambda *_args, **_kwargs: None

    def _fake_execute_target(action_id, action_args, target, context):
        order.append(target["agent_id"])
        return {
            "agent_id": target["agent_id"],
            "agent_name": target["agent_name"],
            "target_ip": target["ip"],
            "platform": target["platform"],
            "ok": True,
            "stdout": f"ok-{target['agent_id']}",
            "stderr": "",
        }

    executor._execute_target = _fake_execute_target

    result = executor.execute(
        action_id="custom-os-command",
        action_args=["Write-Host hi"],
        agent_ids=["001", "002", "003"],
        context={},
    )

    assert order == ["001", "002", "003"]
    assert [row["agent_id"] for row in result["results"]] == ["001", "002", "003"]


def test_post_action_verification_short_circuits_already_satisfied_package_targets():
    verifier = PostActionVerificationLoop(client=object())

    result = verifier.verify_targets(
        "package-update",
        225,
        [
            {
                "agent_id": "003",
                "ok": True,
                "stdout": "package update complete: outcome=SUCCESS applicable=0 installable=0 installed=0 failed=0 remaining=0 skipped=1 unresolved=0\nreason=no_applicable_update\nupdates_skipped_no_change=1",
                "stderr": "",
            }
        ],
    )
    state = derive_verification_state(result)

    assert result["ok"] is True
    assert result["strategy"] == "already_at_target_state_short_circuit"
    assert result["summary"]["already_satisfied"] == 1
    assert state["ok"] is True
    assert state["pending"] is False
    assert state["execution_status"] is None


def test_post_action_verification_short_circuits_already_target_state_marker():
    verifier = PostActionVerificationLoop(client=object())

    result = verifier.verify_targets(
        "software-install-upgrade",
        278,
        [
            {
                "agent_id": "002",
                "ok": True,
                "stdout": "skipped_update_0=Notepad++.Notepad++|Notepad++|reason=already_target_state|installed_before=8.7.2",
                "stderr": "",
            }
        ],
    )

    assert result["ok"] is True
    assert result["strategy"] == "already_at_target_state_short_circuit"


def test_run_endpoint_returns_partial_without_raising(monkeypatch):
    class _FakeExecutor:
        def __init__(self, _client):
            return None

        def execute(self, **_kwargs):
            return {
                "ok": False,
                "total": 2,
                "success": 1,
                "failed": 1,
                "results": [
                    {"agent_id": "001", "ok": True, "stdout": "ok", "stderr": ""},
                    {"agent_id": "002", "ok": False, "stdout": "", "stderr": "timed out"},
                ],
            }

    monkeypatch.setattr(action_execution_module, "EndpointExecutor", _FakeExecutor)
    monkeypatch.setattr(action_execution_module, "publish_event", lambda *_args, **_kwargs: None)

    payload = action_execution_module._run_endpoint(  # noqa: SLF001
        client=object(),
        action_id="package-update",
        dispatch={"action_command": "package-update", "arguments": []},
        agent_ids=["001", "002"],
        execution_id=901,
        context={},
    )

    assert payload["result"]["overall_status"] == "PARTIAL"
    assert payload["result"]["success"] == 1
    assert payload["result"]["failed"] == 1


def test_execute_action_batches_large_endpoint_runs(monkeypatch):
    calls = []
    progress_events = []

    def _fake_run_endpoint(client, action_id, dispatch, agent_ids, execution_id=None, context=None):
        calls.append(list(agent_ids))
        rows = [
            {
                "agent_id": agent_id,
                "agent_name": f"agent-{agent_id}",
                "target_ip": "10.0.0.1",
                "platform": "windows",
                "ok": True,
                "stdout": f"ok-{agent_id}",
                "stderr": "",
            }
            for agent_id in agent_ids
        ]
        return {
            "channel": "endpoint",
            "mode": "endpoint",
            "command_used": action_id,
            "attempts": [action_id],
            "result": {
                "ok": True,
                "total": len(rows),
                "success": len(rows),
                "failed": 0,
                "results": rows,
            },
        }

    monkeypatch.setattr(action_execution_module, "_run_endpoint", _fake_run_endpoint)
    monkeypatch.setattr(action_execution_module, "_resolve_manager_api_action", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(action_execution_module, "orchestration_mode", lambda: "endpoint")
    monkeypatch.setattr(action_execution_module, "_execution_batch_size", lambda: 2)
    monkeypatch.setattr(action_execution_module, "_execution_batch_threshold", lambda: 3)
    monkeypatch.setattr(action_execution_module, "publish_event", lambda *_args, **_kwargs: None)

    payload = action_execution_module.execute_action(
        client=object(),
        action_id="package-update",
        dispatch={"action_command": "package-update", "arguments": []},
        agent_ids=["001", "002", "003", "004", "005"],
        execution_id=777,
        context={
            "approval_id": 777,
            "approval_status": "APPROVED",
            "_batch_progress_callback": lambda progress: progress_events.append(dict(progress)),
        },
    )

    assert calls == [["001", "002"], ["003", "004"], ["005"]]
    assert payload["result"]["batched"] is True
    assert payload["result"]["total"] == 5
    assert payload["result"]["success"] == 5
    assert len(progress_events) == 3
    assert progress_events[-1]["completed"] == 5
    assert progress_events[-1]["status"] == "SUCCESS"

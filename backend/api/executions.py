import json
import os
import re
import shlex

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import text

from core.actions import get_action
from core.action_execution import resolve_agent_ids
from core.endpoint_executor import EndpointExecutor
from core.playbook_generator import build_playbook_path
from core.security import current_user, require_role
from core.settings import SETTINGS
from core.time_utils import serialize_row
from core.wazuh_client import WazuhClient
from core.ws_bus import publish_event
from db.database import connect

router = APIRouter(prefix="/executions")

_UPDATE_METRIC_KEYS = {
    "outcome",
    "updates_applicable",
    "updates_installable",
    "updates_skipped_interactive",
    "updates_skipped",
    "updates_skipped_non_target",
    "updates_unresolved",
    "updates_no_change",
    "updates_installed",
    "updates_failed",
    "updates_remaining",
    "updates_discovered",
    "updates_remaining_non_target",
    "updates_installed_estimate",
    "updates_failed_estimate",
    "download_result",
    "install_result",
    "reboot_required",
    "reboot_pending",
    "reboot_scheduled",
    "reboot_policy",
}

_SCAN_METRIC_KEYS = {
    "scan_type",
    "scan_scope",
    "scan_engine",
    "scan_report_path",
    "scan_total_examined",
    "scan_matches",
    "scan_status",
    "scan_summary",
}

_UPDATE_ACTION_IDS = {
    "patch-windows",
    "patch-linux",
    "windows-os-update",
    "fleet-software-update",
    "package-update",
    "software-install-upgrade",
}

_SCAN_ACTION_IDS = {
    "ioc-scan",
    "toc-scan",
    "yara-scan",
    "collect-forensics",
    "collect-memory",
    "malware-scan",
    "threat-hunt-persistence",
}

_HEALTHCHECK_ACTION_IDS = {
    "endpoint-healthcheck",
}


def _serialize_row(row):
    return serialize_row(row)


def _extract_c2f_evidence_lines(stdout: str) -> list[str]:
    lines: list[str] = []
    for raw in str(stdout or "").splitlines():
        line = raw.strip()
        if not line.startswith("C2F_LOG "):
            continue
        lines.append(line[len("C2F_LOG ") :].strip())
    return lines


def _extract_index(key: str, prefix: str) -> int:
    suffix = key[len(prefix) :]
    return int(suffix) if suffix.isdigit() else -1


def _parse_int(value):
    text_value = str(value or "").strip()
    if not text_value:
        return None
    if text_value.startswith("+"):
        text_value = text_value[1:]
    if text_value.startswith("-"):
        sign = -1
        text_value = text_value[1:]
    else:
        sign = 1
    if not text_value.isdigit():
        return None
    return sign * int(text_value)


def _parse_update_entry(raw_value: str) -> dict:
    raw = str(raw_value or "").strip()
    parts = [p.strip() for p in raw.split("|")]
    entry: dict = {"raw": raw}
    if not parts:
        return entry

    if len(parts) >= 4 and _parse_int(parts[0]) is not None and _parse_int(parts[1]) is not None:
        entry["result_code"] = _parse_int(parts[0])
        entry["hresult"] = _parse_int(parts[1])
        entry["identifier"] = parts[2] or ""
        entry["title"] = "|".join(parts[3:]).strip()
        return entry

    if parts[0].lower() in {"interactive", "manual", "not_installable"}:
        entry["reason"] = parts[0].lower()
        if len(parts) > 1:
            entry["identifier"] = parts[1] or ""
        if len(parts) > 2:
            entry["title"] = "|".join(parts[2:]).strip()
        return entry

    entry["identifier"] = parts[0] or ""
    if len(parts) > 1:
        entry["title"] = parts[1] or ""

    extras = []
    for extra in parts[2:]:
        if "=" in extra:
            key, value = extra.split("=", 1)
            key_norm = key.strip().lower()
            val = value.strip()
            if key_norm in {"rc", "result", "result_code"}:
                parsed = _parse_int(val)
                entry["result_code"] = parsed if parsed is not None else val
                continue
            if key_norm in {"hr", "hresult"}:
                parsed = _parse_int(val)
                entry["hresult"] = parsed if parsed is not None else val
                continue
            entry[key_norm] = val
            continue
        extras.append(extra)
    if extras:
        entry["extra"] = "|".join(extras)
    return entry


def _build_update_report(stdout: str) -> dict | None:
    evidence_lines = _extract_c2f_evidence_lines(stdout)
    if not evidence_lines:
        return None

    available: list[tuple[int, dict]] = []
    installed: list[tuple[int, dict]] = []
    failed: list[tuple[int, dict]] = []
    remaining: list[tuple[int, dict]] = []
    skipped: list[tuple[int, dict]] = []
    fallback_available: list[tuple[int, dict]] = []
    fallback_installed: list[tuple[int, dict]] = []
    fallback_failed: list[tuple[int, dict]] = []
    metrics: dict = {}

    for line in evidence_lines:
        marker = " evidence="
        marker_idx = line.find(marker)
        if marker_idx < 0:
            continue
        payload = line[marker_idx + len(marker) :].strip()
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if key in _UPDATE_METRIC_KEYS:
            metrics[key] = value
            continue

        if key.startswith("available_update_"):
            available.append((_extract_index(key, "available_update_"), _parse_update_entry(value)))
            continue
        if key.startswith("installed_update_"):
            installed.append((_extract_index(key, "installed_update_"), _parse_update_entry(value)))
            continue
        if key.startswith("failed_update_"):
            failed.append((_extract_index(key, "failed_update_"), _parse_update_entry(value)))
            continue
        if key.startswith("remaining_update_"):
            remaining.append((_extract_index(key, "remaining_update_"), _parse_update_entry(value)))
            continue
        if key.startswith("skipped_update_"):
            skipped.append((_extract_index(key, "skipped_update_"), _parse_update_entry(value)))
            continue

        if key.startswith("update_") and re.fullmatch(r"update_\d+", key):
            fallback_available.append((_extract_index(key, "update_"), _parse_update_entry(value)))
            continue
        if key.startswith("update_skipped_"):
            skipped.append((_extract_index(key, "update_skipped_"), _parse_update_entry(value)))
            continue
        if key.startswith("update_result_"):
            parsed = _parse_update_entry(value)
            rc = parsed.get("result_code")
            idx = _extract_index(key, "update_result_")
            if rc in {2, 3}:
                fallback_installed.append((idx, parsed))
            else:
                fallback_failed.append((idx, parsed))

    if not available and fallback_available:
        available = fallback_available
    if not installed and fallback_installed:
        installed = fallback_installed
    if not failed and fallback_failed:
        failed = fallback_failed

    def _sorted_entries(items: list[tuple[int, dict]]) -> list[dict]:
        return [entry for _, entry in sorted(items, key=lambda x: x[0])]

    report = {
        "metrics": metrics,
        "available": _sorted_entries(available),
        "installed": _sorted_entries(installed),
        "failed": _sorted_entries(failed),
        "remaining": _sorted_entries(remaining),
        "skipped": _sorted_entries(skipped),
    }
    has_any = (
        bool(report["metrics"])
        or bool(report["available"])
        or bool(report["installed"])
        or bool(report["failed"])
        or bool(report["remaining"])
        or bool(report["skipped"])
    )
    return report if has_any else None


def _parse_scan_entry(raw_value: str) -> dict:
    raw = str(raw_value or "").strip()
    parts = [p.strip() for p in raw.split("|")]
    entry: dict = {"raw": raw}
    if not parts:
        return entry
    entry["category"] = parts[0] or ""
    if len(parts) > 1:
        entry["name"] = parts[1] or ""
    extras = []
    for extra in parts[2:]:
        if "=" in extra:
            key, value = extra.split("=", 1)
            key_norm = key.strip().lower()
            if key_norm:
                entry[key_norm] = value.strip()
            continue
        extras.append(extra)
    if extras:
        entry["detail"] = "|".join(extras)
    return entry


def _build_scan_report(stdout: str) -> dict | None:
    evidence_lines = _extract_c2f_evidence_lines(stdout)
    if not evidence_lines:
        return None

    metrics: dict = {}
    hits: list[tuple[int, dict]] = []
    artifacts: list[tuple[int, dict]] = []

    for line in evidence_lines:
        marker = " evidence="
        marker_idx = line.find(marker)
        if marker_idx < 0:
            continue
        payload = line[marker_idx + len(marker) :].strip()
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if key in _SCAN_METRIC_KEYS:
            metrics[key] = value
            continue
        if key.startswith("scan_hit_"):
            hits.append((_extract_index(key, "scan_hit_"), _parse_scan_entry(value)))
            continue
        if key.startswith("artifact_"):
            artifacts.append((_extract_index(key, "artifact_"), _parse_scan_entry(value)))

    def _sorted_entries(items: list[tuple[int, dict]]) -> list[dict]:
        return [entry for _, entry in sorted(items, key=lambda x: x[0])]

    report = {
        "metrics": metrics,
        "hits": _sorted_entries(hits),
        "artifacts": _sorted_entries(artifacts),
    }
    has_any = bool(report["metrics"]) or bool(report["hits"]) or bool(report["artifacts"])
    return report if has_any else None


def _build_healthcheck_report(stdout: str) -> dict | None:
    data: dict = {}
    for raw in str(stdout or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("C2F_LOG "):
            continue
        if line.lower() == "healthcheck ok":
            data["status"] = "ok"
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        k = key.strip().lower()
        v = value.strip()
        if k not in {"host", "user", "is_admin", "time"}:
            continue
        if k == "is_admin":
            data[k] = v.lower() in {"1", "true", "yes", "on"}
        else:
            data[k] = v
    return data or None


def _read_endpoint_report_content(
    agent_id: str,
    platform: str,
    report_path: str,
    *,
    max_chars: int | None = None,
) -> dict | None:
    aid = str(agent_id or "").strip()
    path = str(report_path or "").strip()
    if not aid or not path:
        return None

    try:
        client = WazuhClient()
        executor = EndpointExecutor(client)
        target = executor._resolve_agent_target(aid)  # noqa: SLF001
        target_platform = str(platform or target.get("platform") or "").strip().lower()
        if target_platform == "windows":
            safe_path = path.replace("'", "''")
            script = (
                "$ErrorActionPreference='SilentlyContinue';"
                "$ProgressPreference='SilentlyContinue';"
                f"$p='{safe_path}';"
                "if(Test-Path $p){ Get-Content -Path $p -Raw }"
            )
            status_code, out, _ = executor._run_winrm(target, script, timeout_seconds=45)  # noqa: SLF001
        elif target_platform == "linux":
            quoted = shlex.quote(path)
            script = f"if [ -f {quoted} ]; then cat {quoted}; fi"
            status_code, out, _ = executor._run_ssh(str(target.get("ip") or ""), script, timeout_seconds=45)  # noqa: SLF001
        else:
            return None

        if int(status_code) != 0:
            return None
        raw = str(out or "").strip()
        if not raw:
            return None

        truncated = bool(isinstance(max_chars, int) and max_chars > 0 and len(raw) > max_chars)
        if truncated and isinstance(max_chars, int):
            raw = raw[:max_chars]

        payload: dict = {
            "path": path,
            "truncated": truncated,
        }
        try:
            payload["format"] = "json"
            payload["json"] = json.loads(raw)
        except Exception:
            payload["format"] = "text"
            payload["text"] = raw
        return payload
    except Exception:
        return None


def _parse_execution_target_ids(target: str) -> tuple[list[str], str | None]:
    raw = str(target or "").strip()
    if not raw:
        return [], None
    low = raw.lower()
    if low.startswith("multi:"):
        parts = [p.strip() for p in raw.split(":", 1)[1].split(",")]
        return [p for p in parts if p], None
    if low.startswith("group:"):
        return [], raw.split(":", 1)[1].strip() or None
    if low in {"all", "*", "fleet", "all-active"}:
        return ["all"], None
    return [raw], None


def _windows_control_flag_script(exec_id: int, command: str) -> str:
    safe_exec = str(exec_id).replace("'", "''")
    safe_cmd = str(command or "").replace("'", "''").lower()
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$ProgressPreference='SilentlyContinue';"
        "$dir='C:\\\\Click2Fix\\\\control';"
        "New-Item -ItemType Directory -Path $dir -Force | Out-Null;"
        f"$pause=Join-Path $dir ('pause-{safe_exec}.flag');"
        f"$cancel=Join-Path $dir ('cancel-{safe_exec}.flag');"
        f"$cmd='{safe_cmd}';"
        "if($cmd -eq 'pause'){ New-Item -ItemType File -Path $pause -Force | Out-Null; Write-Output ('paused='+$pause); exit 0 };"
        "if($cmd -eq 'resume'){ Remove-Item -Path $pause -Force -ErrorAction SilentlyContinue; Write-Output 'resumed'; exit 0 };"
        "if($cmd -eq 'cancel' -or $cmd -eq 'end'){ New-Item -ItemType File -Path $cancel -Force | Out-Null; Write-Output ('cancelled='+$cancel); exit 0 };"
        "Write-Output 'noop'; exit 0;"
    )


def _windows_kill_script(exec_id: int | None = None, delay_seconds: int = 3) -> str:
    delay = max(1, int(delay_seconds or 3))
    safe_exec = str(exec_id).replace("'", "''") if exec_id is not None else ""
    # Kill winget + WinGet temp installers; then schedule wsmprovhost termination so the current WinRM call can return.
    return (
        "$ErrorActionPreference='SilentlyContinue';"
        "$ProgressPreference='SilentlyContinue';"
        "$killed=@();"
        f"$execId='{safe_exec}';"
        "if($execId){"
        "$c2f=Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and $_.CommandLine -match '\\\\Click2Fix\\\\scripts\\\\' -and $_.CommandLine -match ('-ExecId\\s+'+$execId) };"
        "foreach($p in $c2f){"
        "try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed += ('killed_pid='+$p.ProcessId+' name='+$p.Name+' reason=exec_id_match') }catch{ $killed += ('kill_failed_pid='+$p.ProcessId+' err='+$_.Exception.Message) }"
        "};"
        "$tasks=(& schtasks.exe /Query /FO LIST /V 2>$null | Out-String);"
        "foreach($tn in ([regex]::Matches($tasks,'(?im)^TaskName:\\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() })){"
        "if($tn -match ('C2F_.*_'+$execId+'$')){ try{ & schtasks.exe /Delete /TN $tn /F | Out-Null; $killed += ('deleted_task='+$tn) }catch{} }"
        "}"
        "};"
        "$procs=Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -and ($_.CommandLine -match '\\\\AppData\\\\Local\\\\Temp\\\\WinGet\\\\') };"
        "foreach($p in $procs){"
        "try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed += ('killed_pid='+$p.ProcessId+' name='+$p.Name) }catch{ $killed += ('kill_failed_pid='+$p.ProcessId+' err='+$_.Exception.Message) }"
        "};"
        "foreach($n in @('winget.exe','WindowsPackageManagerServer.exe','AppInstallerCLI.exe')){"
        "$ps2=Get-CimInstance Win32_Process -Filter (\"Name='\"+$n+\"'\");"
        "foreach($p in $ps2){"
        "try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed += ('killed_pid='+$p.ProcessId+' name='+$p.Name) }catch{ $killed += ('kill_failed_pid='+$p.ProcessId+' err='+$_.Exception.Message) }"
        "}"
        "};"
        "Write-Output ('killed_count='+$killed.Count);"
        "foreach($line in $killed){ Write-Output $line };"
        f"$d={delay};"
        "$cmd=('/c timeout /t '+$d+' /nobreak >NUL & taskkill /F /IM wsmprovhost.exe /T >NUL 2>&1');"
        "Start-Process -FilePath cmd.exe -ArgumentList $cmd -WindowStyle Hidden | Out-Null;"
        "Write-Output ('scheduled_taskkill_wsmprovhost_after_seconds='+$d);"
    )


@router.get("")
def list_executions(
    limit: int = Query(default=200, ge=1, le=1000),
    status: str | None = None,
    q: str | None = None,
    user=Depends(current_user),
):
    """
    Unified execution history (actions + playbooks).
    """
    db = connect()
    try:
        where = []
        params = {"limit": limit}
        if status:
            where.append("e.status = :status")
            params["status"] = status
        if q:
            where.append("(e.agent ILIKE :q OR e.action ILIKE :q OR e.playbook ILIKE :q)")
            params["q"] = f"%{q}%"
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        rows = db.execute(
            text(
                f"""
                SELECT
                    e.id,
                    e.agent,
                    COALESCE(e.action, e.playbook) AS action,
                    e.args,
                    e.status,
                    e.approved_by,
                    e.alert_id,
                    e.started_at,
                    e.finished_at,
                    (
                        SELECT COUNT(*)
                        FROM execution_targets et
                        WHERE et.execution_id = e.id
                    ) AS target_count,
                    (
                        SELECT COUNT(*)
                        FROM execution_targets et
                        WHERE et.execution_id = e.id
                          AND et.ok = TRUE
                    ) AS target_success,
                    (
                        SELECT et.stdout
                        FROM execution_targets et
                        WHERE et.execution_id = e.id
                        ORDER BY et.id DESC
                        LIMIT 1
                    ) AS latest_stdout,
                    (
                        SELECT et.stderr
                        FROM execution_targets et
                        WHERE et.execution_id = e.id
                        ORDER BY et.id DESC
                        LIMIT 1
                    ) AS latest_stderr
                FROM executions e
                {where_sql}
                ORDER BY e.started_at DESC
                LIMIT :limit
                """
            ),
            params,
        ).fetchall()
        return [_serialize_row(r) for r in rows]
    finally:
        db.close()


@router.post("/{execution_id}/control")
def control_execution(
    execution_id: int,
    payload: dict = Body(default={}),
    user=Depends(require_role("admin")),
):
    command = str((payload or {}).get("command") or (payload or {}).get("action") or "").strip().lower()
    if command in {"stop", "terminate"}:
        command = "kill"
    if command in {"end"}:
        command = "cancel"
    if command not in {"pause", "resume", "cancel", "kill"}:
        raise HTTPException(status_code=400, detail="command must be one of: pause, resume, cancel, kill")
    reason = str((payload or {}).get("reason") or (payload or {}).get("message") or "").strip()

    actor = user.get("sub") if isinstance(user, dict) else str(user)
    now_sql = "NOW()"

    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT id, agent, action, playbook, status
                FROM executions
                WHERE id=:id
                """
            ),
            {"id": execution_id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Execution not found")
        execution = _serialize_row(row)
        current = str(execution.get("status") or "").upper()

        new_status = None
        set_finished = False
        if command == "pause":
            new_status = "PAUSED"
        elif command == "resume":
            new_status = "RUNNING"
        elif command == "cancel":
            new_status = "CANCELLED"
            set_finished = True
        elif command == "kill":
            new_status = "KILLED"
            set_finished = True

        # Update status first so the UI can reflect operator intent immediately.
        if new_status:
            if set_finished:
                db.execute(
                    text(
                        f"""
                        UPDATE executions
                        SET status=:status, finished_at=COALESCE(finished_at, {now_sql})
                        WHERE id=:id
                        """
                    ),
                    {"status": new_status, "id": execution_id},
                )
            else:
                db.execute(
                    text("UPDATE executions SET status=:status WHERE id=:id"),
                    {"status": new_status, "id": execution_id},
                )

        step_stdout = f"operator={actor}; command={command}"
        if reason:
            step_stdout += f"; reason={reason}"
        db.execute(
            text(
                """
                INSERT INTO execution_steps (execution_id, step, stdout, stderr, status)
                VALUES (:execution_id, :step, :stdout, :stderr, :status)
                """
            ),
            {
                "execution_id": execution_id,
                "step": "execution_control",
                "stdout": step_stdout,
                "stderr": "",
                "status": "SUCCESS",
            },
        )
        db.commit()

        publish_event(
            execution_id,
            {
                "type": "execution_control",
                "step": "execution_control",
                "status": "SUCCESS",
                "stdout": step_stdout,
                "stderr": "",
            },
        )

        # Best-effort: signal endpoints (pause/resume/cancel) and/or force-kill WinRM shells for kill.
        endpoint_results: list[dict] = []
        try:
            client = WazuhClient()
            executor = EndpointExecutor(client)
            base_ids, group = _parse_execution_target_ids(execution.get("agent") or "")
            agent_ids = resolve_agent_ids(client, target="group:" + group, group=group) if group else base_ids
            if base_ids == ["all"]:
                agent_ids = resolve_agent_ids(client, target="all", group=None)

            for aid in agent_ids:
                try:
                    target = executor._resolve_agent_target(str(aid))  # noqa: SLF001
                    if str(target.get("platform") or "").lower() != "windows":
                        endpoint_results.append({"agent_id": str(aid), "ok": True, "skipped": "non_windows"})
                        continue
                    if command in {"pause", "resume", "cancel"}:
                        script = _windows_control_flag_script(execution_id, command)
                        code, out, err = executor._run_winrm(target, script, timeout_seconds=30)  # noqa: SLF001
                    else:
                        script = _windows_kill_script(exec_id=execution_id, delay_seconds=3)
                        code, out, err = executor._run_winrm(target, script, timeout_seconds=60)  # noqa: SLF001
                    endpoint_results.append(
                        {
                            "agent_id": str(aid),
                            "ok": int(code) == 0,
                            "stdout": (out or "").strip(),
                            "stderr": (err or "").strip(),
                        }
                    )
                except Exception as exc:
                    endpoint_results.append({"agent_id": str(aid), "ok": False, "stderr": str(exc)})
        except Exception:
            # Never block operator control on connector errors.
            endpoint_results = endpoint_results or []

        return {
            "ok": True,
            "execution_id": execution_id,
            "previous_status": current,
            "status": new_status or current,
            "command": command,
            "endpoint_results": endpoint_results,
        }
    finally:
        db.close()


@router.get("/{execution_id}")
def execution_detail(execution_id: int, user=Depends(current_user)):
    """
    Execution detail with steps + justification + action metadata (when available).
    """
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT
                    id,
                    approval_id,
                    agent,
                    playbook,
                    action,
                    args,
                    status,
                    approved_by,
                    alert_id,
                    started_at,
                    finished_at
                FROM executions
                WHERE id=:id
                """
            ),
            {"id": execution_id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Execution not found")
        execution = _serialize_row(row)

        steps = db.execute(
            text(
                """
                SELECT step, stdout, stderr, status
                FROM execution_steps
                WHERE execution_id=:id
                ORDER BY id ASC
                """
            ),
            {"id": execution_id},
        ).fetchall()

        targets = db.execute(
            text(
                """
                SELECT
                    agent_id,
                    agent_name,
                    target_ip,
                    platform,
                    ok,
                    status_code,
                    stdout,
                    stderr,
                    created_at
                FROM execution_targets
                WHERE execution_id=:id
                ORDER BY id ASC
                """
            ),
            {"id": execution_id},
        ).fetchall()
        target_rows = []
        report_cache: dict[tuple[str, str], dict | None] = {}
        execution_action_id = str(execution.get("action") or "").strip().lower()
        parse_update_report = execution_action_id in _UPDATE_ACTION_IDS
        parse_scan_report = execution_action_id in _SCAN_ACTION_IDS
        parse_health_report = execution_action_id in _HEALTHCHECK_ACTION_IDS

        for target in targets:
            item = _serialize_row(target)
            stdout_text = item.get("stdout") or ""

            if parse_update_report:
                report = _build_update_report(stdout_text)
                if report:
                    item["update_report"] = report

            if parse_scan_report:
                scan_report = _build_scan_report(stdout_text)
                if scan_report:
                    item["scan_report"] = scan_report
                    metrics = scan_report.get("metrics") if isinstance(scan_report, dict) else {}
                    report_path = str((metrics or {}).get("scan_report_path") or "").strip()
                    if report_path:
                        cache_key = (str(item.get("agent_id") or ""), report_path)
                        if cache_key not in report_cache:
                            report_cache[cache_key] = _read_endpoint_report_content(
                                agent_id=str(item.get("agent_id") or ""),
                                platform=str(item.get("platform") or ""),
                                report_path=report_path,
                            )
                        if report_cache.get(cache_key):
                            item["scan_report_content"] = report_cache[cache_key]

            if parse_health_report:
                health_report = _build_healthcheck_report(stdout_text)
                if health_report:
                    item["healthcheck_report"] = health_report
            target_rows.append(item)

        justification = (
            db.execute(
                text(
                    """
                    SELECT justification FROM execution_metadata
                    WHERE execution_id=:id
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                ),
                {"id": execution_id},
            ).scalar()
            or ""
        )

        # Backfill from approval metadata if execution metadata is missing.
        if not justification and execution.get("approval_id"):
            justification = (
                db.execute(
                    text(
                        """
                        SELECT justification FROM approval_metadata
                        WHERE approval_id=:approval_id
                        ORDER BY created_at DESC
                        LIMIT 1
                        """
                    ),
                    {"approval_id": execution.get("approval_id")},
                ).scalar()
                or ""
            )

        action_id = execution.get("action") or ""
        playbook_name = execution.get("playbook") or ""
        action_meta = None
        if action_id:
            try:
                action_meta = get_action(str(action_id))
            except HTTPException:
                action_meta = None

        playbook_meta = None
        if not action_meta and playbook_name:
            base_dir = (
                SETTINGS.get("playbooks_path")
                if isinstance(SETTINGS, dict) and SETTINGS.get("playbooks_path")
                else "./playbooks"
            )
            try:
                path = build_playbook_path(base_dir, str(playbook_name))
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8") as handle:
                        payload = json.load(handle) or {}
                    playbook_meta = {
                        "name": payload.get("name") or os.path.basename(path),
                        "description": payload.get("description") or "",
                        "steps": payload.get("steps") if isinstance(payload.get("steps"), list) else [],
                    }
            except Exception:
                playbook_meta = None

        return {
            "execution": execution,
            "steps": [_serialize_row(s) for s in steps],
            "targets": target_rows,
            "justification": justification,
            "action": action_meta,
            "playbook": playbook_meta,
        }
    finally:
        db.close()

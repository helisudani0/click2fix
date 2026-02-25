import json
import logging
import re
import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text

from core.actions import get_action, list_actions, normalize_args, resolve_action_dispatch
from core.action_capability_resolver import capability_resolver
from core.action_execution import execute_action, orchestration_mode, resolve_agent_ids
from core.audit import log_audit
from core.endpoint_executor import EndpointExecutor
from core.security import require_role
from core.time_utils import utc_now_naive
from core.wazuh_client import WazuhClient
from core.ws_bus import publish_event
from db.database import connect

router = APIRouter(prefix="/actions")
client = WazuhClient()
logger = logging.getLogger(__name__)

_FLEET_TARGETS = {"all", "*", "fleet", "all-active"}
_CONNECTED_STATUSES = {"active", "connected", "online"}
_GLOBAL_SHELL_MAX_COMMAND_CHARS = 20000


def _ps_single_quoted(value: str) -> str:
    raw = str(value or "")
    return "'" + raw.replace("'", "''") + "'"


def _wrap_cmd_for_powershell(raw_command: str) -> str:
    """
    Build a cmd.exe invocation that survives PowerShell parsing.

    We wrap the full command in double-quotes for cmd /c so operators like
    && and || are handled by cmd, not by PowerShell's parser.
    """
    raw = str(raw_command or "").strip()
    if not raw:
        return "cmd.exe /d /s /c \"\""
    normalized = raw.lower()
    if normalized.startswith("cmd ") or normalized.startswith("cmd.exe "):
        # Avoid double-wrapping analyst-provided cmd invocations.
        return raw
    return f"$c={_ps_single_quoted(raw)}; cmd.exe /d /s /c $c"


def _build_windows_discovery_upgrade_command(package_target: str) -> str:
    hint = str(package_target or "").strip()
    if not hint:
        return ""
    needle_literal = _ps_single_quoted(hint)
    return (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        f"$needles=@({needle_literal});"
        "function C2F-ParseWinget([string]$txt,[bool]$isUpgrade){"
        "  $rows=@();"
        "  foreach($line in ($txt -split \"`r?`n\")){"
        "    $trim=[string]$line; if(-not $trim){ continue };"
        "    $parts=[regex]::Split($trim.Trim(), '\\s{2,}') | Where-Object { $_ -ne '' };"
        "    if($isUpgrade){"
        "      if($parts.Count -ge 4 -and $parts[1] -and $parts[1] -ne 'Id'){ $rows += [pscustomobject]@{Name=$parts[0];Id=$parts[1];Installed=$parts[2];Available=$parts[3]} }"
        "    } else {"
        "      if($parts.Count -ge 2 -and $parts[1] -and $parts[1] -ne 'Id'){ $rows += [pscustomobject]@{Name=$parts[0];Id=$parts[1];Installed='';Available=''} }"
        "    }"
        "  };"
        "  return $rows;"
        "};"
        "function C2F-Match([object[]]$rows,[string[]]$needles){"
        "  foreach($needle in $needles){"
        "    if(-not $needle){ continue };"
        "    $k=$needle.ToLower();"
        "    $hit=$rows | Where-Object { ([string]$_.Id).ToLower() -eq $k -or ([string]$_.Name).ToLower() -eq $k -or ([string]$_.Id).ToLower().Contains($k) -or ([string]$_.Name).ToLower().Contains($k) } | Select-Object -First 1;"
        "    if($hit){ return $hit };"
        "  };"
        "  return $null;"
        "};"
        "function C2F-TryWinget([string[]]$needles){"
        "  if(-not (Get-Command winget -ErrorAction SilentlyContinue)){ return $false };"
        "  $upgradeRows=@();"
        "  try { $uo=(& winget upgrade --source winget 2>&1 | Out-String); $upgradeRows=C2F-ParseWinget $uo $true } catch { };"
        "  $hit=C2F-Match $upgradeRows $needles;"
        "  if(-not $hit){"
        "    foreach($needle in $needles){"
        "      if(-not $needle){ continue };"
        "      try { $so=(& winget search --source winget --query $needle 2>&1 | Out-String); $rows=C2F-ParseWinget $so $false; $hit=C2F-Match $rows @($needle) } catch { };"
        "      if($hit){ break };"
        "    };"
        "  };"
        "  if(-not $hit){ return $false };"
        "  $resolvedId=[string]$hit.Id;"
        "  if(-not $resolvedId){ return $false };"
        "  $available=[string]$hit.Available;"
        "  $args=@('upgrade','--id',$resolvedId,'--exact','--silent','--accept-package-agreements','--accept-source-agreements');"
        "  if($available -and $available -notmatch '^(?i)(unknown|n/a|-)$'){ $args += @('--version',$available) };"
        "  & winget @args | Out-Host;"
        "  if($LASTEXITCODE -eq 0){ Write-Output ('C2F_UPGRADE winget id='+$resolvedId+' avail='+$available); return $true };"
        "  if($resolvedId -eq 'Microsoft.AppInstaller'){"
        "    try {"
        "      $appx=Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1;"
        "      if($appx -and $appx.InstallLocation){"
        "        $manifest=Join-Path $appx.InstallLocation 'AppxManifest.xml';"
        "        if(Test-Path $manifest){"
        "          Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction SilentlyContinue | Out-Null;"
        "          Start-Sleep -Seconds 2;"
        "          & winget @args | Out-Host;"
        "          if($LASTEXITCODE -eq 0){ Write-Output ('C2F_UPGRADE winget id='+$resolvedId+' avail='+$available+' fallback=appx-register'); return $true };"
        "        }"
        "      }"
        "    } catch { }"
        "  };"
        "  $installArgs=@('install','--id',$resolvedId,'--exact','--silent','--accept-package-agreements','--accept-source-agreements');"
        "  if($available -and $available -notmatch '^(?i)(unknown|n/a|-)$'){ $installArgs += @('--version',$available) };"
        "  & winget @installArgs | Out-Host;"
        "  if($LASTEXITCODE -eq 0){ Write-Output ('C2F_UPGRADE winget-install id='+$resolvedId+' avail='+$available); return $true };"
        "  return $false;"
        "};"
        "function C2F-TryChoco([string[]]$needles){"
        "  if(-not (Get-Command choco -ErrorAction SilentlyContinue)){ return $false };"
        "  $installed=@();"
        "  try { $local=(& choco list --local-only --limit-output 2>&1 | Out-String) } catch { $local='' };"
        "  foreach($line in ($local -split \"`r?`n\")){"
        "    $trim=[string]$line; if(-not $trim){ continue };"
        "    if($trim -notmatch '\\|'){ continue };"
        "    $name=($trim -split '\\|')[0];"
        "    if($name){ $installed += $name.Trim() };"
        "  };"
        "  $pkg=$null;"
        "  foreach($needle in $needles){"
        "    if(-not $needle){ continue };"
        "    $k=$needle.ToLower();"
        "    $pkg=$installed | Where-Object { $_.ToLower() -eq $k -or $_.ToLower().Contains($k) } | Select-Object -First 1;"
        "    if($pkg){ break };"
        "  };"
        "  if(-not $pkg){ return $false };"
        "  & choco upgrade $pkg -y --no-progress --limit-output | Out-Host;"
        "  if($LASTEXITCODE -eq 0){ Write-Output ('C2F_UPGRADE choco id='+$pkg); return $true };"
        "  return $false;"
        "};"
        "$updated=$false;"
        "if(C2F-TryWinget $needles){ $updated=$true }"
        "elseif(C2F-TryChoco $needles){ $updated=$true };"
        f"if(-not $updated){{ throw ('No supported upgrade path succeeded for '+{needle_literal}) }};"
        "Write-Output ('Package update attempted: '+$needles[0]);"
    )


def _normalize_shell_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _looks_like_simple_winget_upgrade_all(raw_command: str) -> bool:
    raw = str(raw_command or "").strip()
    if not raw:
        return False
    # Only rewrite plain one-liners so analyst-authored scripts stay untouched.
    if any(token in raw for token in (";", "\n", "\r", "&&", "||", "|")):
        return False
    normalized = _normalize_shell_whitespace(raw)
    if not (
        normalized.startswith("winget upgrade --all")
        or normalized.startswith("winget.exe upgrade --all")
    ):
        return False
    if " --id " in f" {normalized} ":
        return False
    return True


def _build_windows_winget_upgrade_all_command(*, include_unknown: bool = False) -> str:
    """
    Fleet-safe winget-all wrapper.

    Goals:
    - Treat "some packages upgraded, some failed" as PARTIAL (non-fatal) instead of hard FAIL.
    - Repair common Microsoft.AppInstaller self-update failure (0x80070002) before deciding skip.
    """
    script = r"""
$ErrorActionPreference='Continue'
$ProgressPreference='SilentlyContinue'
$includeUnknown=__INCLUDE_UNKNOWN__

function C2F-Flat([string]$txt){
  if(-not $txt){ return '' }
  $line = (($txt -replace "`r"," " -replace "`n"," ").Trim())
  if($line.Length -gt 280){ return $line.Substring(0,280) + '...' }
  return $line
}

function C2F-ParseWingetRows([string]$txt){
  $rows=@()
  $seen=@{}
  foreach($line in ($txt -split "`r?`n")){
    $trim=[string]$line
    if(-not $trim){ continue }
    $clean=$trim.Trim()
    if(-not $clean){ continue }
    if($clean -match '^-{3,}$'){ continue }
    if($clean -match '(?i)^\d+\s+upgrades?\s+available'){ continue }
    if($clean -match '(?i)^name\s+id\s+version'){ continue }
    if($clean -match '(?i)^the following packages have'){ continue }
    $parts=[regex]::Split($clean, '\s{2,}') | Where-Object { $_ -ne '' }
    if($parts.Count -lt 2){ continue }
    $name=[string]$parts[0]
    $id=[string]$parts[1]
    if(-not $id -or $id -eq 'Id'){ continue }
    if($seen.ContainsKey($id)){ continue }
    $seen[$id]=$true
    $rows += [pscustomobject]@{ Name=$name; Id=$id }
  }
  return $rows
}

if(-not (Get-Command winget -ErrorAction SilentlyContinue)){
  throw 'winget is not available in this user context'
}

try { & winget source update --name winget 2>&1 | Out-Null } catch { }

$listArgs=@('upgrade','--source','winget')
if($includeUnknown){ $listArgs += '--include-unknown' }
$listRaw = (& winget @listArgs 2>&1 | Out-String)
$rows = C2F-ParseWingetRows $listRaw

if($rows.Count -eq 0){
  Write-Output 'No upgradable packages found.'
  Write-Output 'C2F_SUMMARY outcome=SUCCESS total=0 upgraded=0 failed=0 skipped=0'
  exit 0
}

$upgraded = 0
$failed = 0
$skipped = 0
$issues = New-Object 'System.Collections.Generic.List[string]'

foreach($row in $rows){
  $id = [string]$row.Id
  $name = [string]$row.Name
  if(-not $id){ continue }
  Write-Output ('[RUN] ' + $name + ' [' + $id + ']')

  $upgradeArgs=@('upgrade','--id',$id,'--exact','--silent','--accept-package-agreements','--accept-source-agreements')
  $out = (& winget @upgradeArgs 2>&1 | Out-String)
  $rc = 0
  if($LASTEXITCODE -ne $null){ try { $rc = [int]$LASTEXITCODE } catch { $rc = 1 } }
  if($rc -eq 0){
    $upgraded++
    Write-Output ('[OK] ' + $id)
    continue
  }

  $flat = C2F-Flat $out

  if($id -eq 'Microsoft.AppInstaller' -and $flat -match '(?i)0x80070002'){
    Write-Output '[INFO] Microsoft.AppInstaller fallback: re-register DesktopAppInstaller and retry.'
    try {
      $pkg = Get-AppxPackage -AllUsers Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
      if($pkg -and $pkg.InstallLocation){
        $manifest = Join-Path $pkg.InstallLocation 'AppxManifest.xml'
        if(Test-Path $manifest){
          Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction SilentlyContinue | Out-Null
          Start-Sleep -Seconds 2
          $out2 = (& winget @upgradeArgs 2>&1 | Out-String)
          $rc2 = 0
          if($LASTEXITCODE -ne $null){ try { $rc2 = [int]$LASTEXITCODE } catch { $rc2 = 1 } }
          if($rc2 -eq 0){
            $upgraded++
            Write-Output ('[OK] ' + $id + ' (fallback repaired)')
            continue
          }
          $flat = C2F-Flat $out2
        }
      }
    } catch { }
    $skipped++
    $issues.Add($id + ' skipped: self-update incomplete (' + $flat + ')')
    Write-Output ('[SKIP] ' + $id + ' self-update did not complete; continuing.')
    continue
  }

  $installArgs=@('install','--id',$id,'--exact','--silent','--accept-package-agreements','--accept-source-agreements')
  $outInstall = (& winget @installArgs 2>&1 | Out-String)
  $rcInstall = 0
  if($LASTEXITCODE -ne $null){ try { $rcInstall = [int]$LASTEXITCODE } catch { $rcInstall = 1 } }
  if($rcInstall -eq 0){
    $upgraded++
    Write-Output ('[OK] ' + $id + ' (install fallback)')
    continue
  }

  $failed++
  $issues.Add($id + ' failed: ' + (C2F-Flat $outInstall))
  Write-Output ('[FAIL] ' + $id)
}

$total = [int]$rows.Count
$outcome = 'SUCCESS'
if($failed -gt 0 -and $upgraded -eq 0){
  $outcome = 'FAILED'
} elseif($failed -gt 0 -or $skipped -gt 0){
  $outcome = 'PARTIAL'
}

$summary = ('package upgrade summary: outcome=' + $outcome + ' total=' + $total + ' upgraded=' + $upgraded + ' failed=' + $failed + ' skipped=' + $skipped)
Write-Output $summary
Write-Output ('C2F_SUMMARY outcome=' + $outcome + ' total=' + $total + ' upgraded=' + $upgraded + ' failed=' + $failed + ' skipped=' + $skipped)
if($issues.Count -gt 0){
  Write-Output ('package issues: ' + [string]::Join(' | ', $issues))
}

if($outcome -eq 'FAILED'){
  throw $summary
}
exit 0
"""
    include_literal = "$true" if include_unknown else "$false"
    return script.replace("__INCLUDE_UNKNOWN__", include_literal).strip()


def _legacy_package_hint(raw_command: str) -> str:
    text = str(raw_command or "")
    lowered = text.lower()
    if "$updated=$false" not in lowered:
        return ""
    if "no supported package manager path succeeded for" not in lowered:
        return ""
    if "winget upgrade --id $pkg" not in lowered:
        return ""
    match = re.search(r"\$pkg\s*=\s*'([^']+)'", text, flags=re.IGNORECASE)
    if not match:
        match = re.search(r'\$pkg\s*=\s*"([^"]+)"', text, flags=re.IGNORECASE)
    if not match:
        return ""
    return str(match.group(1) or "").strip()


def _normalize_global_shell_command(shell: str, raw_command: str) -> str:
    if str(shell or "").strip().lower() != "powershell":
        return str(raw_command or "")
    if _looks_like_simple_winget_upgrade_all(raw_command):
        include_unknown = "--include-unknown" in _normalize_shell_whitespace(raw_command)
        wrapped = _build_windows_winget_upgrade_all_command(include_unknown=include_unknown)
        if wrapped:
            return wrapped
    hint = _legacy_package_hint(raw_command)
    if not hint:
        return str(raw_command or "")
    upgraded = _build_windows_discovery_upgrade_command(hint)
    return upgraded or str(raw_command or "")


def _coerce_custom_os_command_arguments(
    arguments: list[str],
    *,
    command: str,
    verify_kb: str = "",
    verify_min_build: str = "",
    verify_stdout_contains: str = "",
    run_as_system: bool = False,
) -> list[str]:
    """
    Enforce the custom-os-command positional schema:
    [command, verify_kb, verify_min_build, verify_stdout_contains, run_as_system]

    This keeps Global Shell stable even if an older container loads a stale action
    schema that does not yet include optional trailing fields.
    """
    existing = [str(v) for v in (arguments or [])]
    command_value = str(command or "").strip()
    if existing:
        existing_cmd = str(existing[0] or "").strip()
        if existing_cmd:
            command_value = existing_cmd

    normalized = [
        command_value,
        str(verify_kb or ""),
        str(verify_min_build or ""),
        str(verify_stdout_contains or ""),
        "true" if bool(run_as_system) else "false",
    ]
    return normalized


def _looks_like_privileged_windows_command(shell: str, command: str) -> bool:
    if str(shell or "").strip().lower() != "powershell":
        return False
    lowered = str(command or "").strip().lower()
    if not lowered:
        return False
    return any(
        marker in lowered
        for marker in (
            "get-windowsupdate",
            "install-windowsupdate",
            "pswindowsupdate",
            "msiexec",
            "wusa",
        )
    )


def _looks_like_user_space_package_manager_command(shell: str, command: str) -> bool:
    if str(shell or "").strip().lower() != "powershell":
        return False
    lowered = str(command or "").strip().lower()
    if not lowered:
        return False
    return any(
        marker in lowered
        for marker in (
            " winget ",
            "winget ",
            " choco ",
            "choco ",
        )
    )


def _first_real_agent_id(values) -> str | None:
    for value in values or []:
        raw = str(value or "").strip()
        if not raw:
            continue
        if raw in {"000", "0"}:
            continue
        return raw
    return None


def _extract_items(data):
    if isinstance(data, dict):
        return (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
    if isinstance(data, list):
        return data
    return []


def _agent_status(agent: dict) -> str:
    if not isinstance(agent, dict):
        return ""
    status = agent.get("status")
    if status is None and isinstance(agent.get("agent"), dict):
        status = agent.get("agent", {}).get("status")
    return str(status or "").strip().lower()


def _normalize_agent_identifier(value: str) -> str:
    raw = str(value or "").strip()
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _normalize_agent_id_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = [str(part).strip() for part in value]
    else:
        items = [str(value).strip()]

    out = []
    seen = set()
    for item in items:
        norm = _normalize_agent_identifier(item)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _agent_groups(agent: dict) -> set[str]:
    if not isinstance(agent, dict):
        return set()

    values = []
    for key in ("group", "groups", "group_name"):
        raw = agent.get(key)
        if raw is None:
            continue
        if isinstance(raw, (list, tuple, set)):
            values.extend([str(item).strip() for item in raw if str(item).strip()])
        else:
            text = str(raw).strip()
            if not text:
                continue
            if "," in text:
                values.extend([part.strip() for part in text.split(",") if part.strip()])
            else:
                values.append(text)

    return {str(item).strip().lower() for item in values if str(item).strip()}


def _agent_platform(agent: dict) -> str:
    if not isinstance(agent, dict):
        return ""
    os_node = agent.get("os")
    if isinstance(os_node, dict):
        name = str(
            os_node.get("name")
            or os_node.get("platform")
            or os_node.get("full")
            or ""
        )
    else:
        name = str(agent.get("os_name") or agent.get("os") or "")
    lowered = name.strip().lower()
    if "windows" in lowered:
        return "windows"
    if any(token in lowered for token in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "suse", "alpine")):
        return "linux"
    return ""


def _determine_agent_os(
    agent_id: str | None = None,
    group: str | None = None,
    agent_ids: list[str] | None = None,
) -> str:
    if agent_ids:
        first = _first_real_agent_id(agent_ids)
        if first:
            executor = EndpointExecutor(client)
            target = executor._resolve_agent_target(first)  # noqa: SLF001 - internal fallback resolver
            platform = str(target.get("platform") or "").strip().lower()
            return "windows" if platform == "windows" else "linux"

    if agent_id:
        agent_val = str(agent_id).strip()
        if agent_val.lower() in _FLEET_TARGETS:
            fleet_ids = client.get_agent_ids()
            first = _first_real_agent_id(fleet_ids)
            if not first:
                raise HTTPException(status_code=404, detail="No agents found in fleet")
            executor = EndpointExecutor(client)
            target = executor._resolve_agent_target(first)  # noqa: SLF001 - internal fallback resolver
            platform = str(target.get("platform") or "").strip().lower()
            return "windows" if platform == "windows" else "linux"
        executor = EndpointExecutor(client)
        target = executor._resolve_agent_target(agent_id)  # noqa: SLF001 - internal fallback resolver
        platform = str(target.get("platform") or "").strip().lower()
        return "windows" if platform == "windows" else "linux"

    if not group:
        raise HTTPException(status_code=400, detail="agent_id or group is required")

    agents = client.get_agent_ids(group=group)
    first = _first_real_agent_id(agents)
    if not first:
        raise HTTPException(status_code=404, detail=f"No agents found in group {group}")
    executor = EndpointExecutor(client)
    target = executor._resolve_agent_target(first)  # noqa: SLF001 - internal fallback resolver
    platform = str(target.get("platform") or "").strip().lower()
    return "windows" if platform == "windows" else "linux"


def _to_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _store_execution_targets(conn, execution_id: int, rows) -> None:
    if not execution_id or not rows or not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        conn.execute(
            text(
                """
                INSERT INTO execution_targets
                (execution_id, agent_id, agent_name, target_ip, platform, ok, status_code, stdout, stderr)
                VALUES (:execution_id, :agent_id, :agent_name, :target_ip, :platform, :ok, :status_code, :stdout, :stderr)
                """
            ),
            {
                "execution_id": int(execution_id),
                "agent_id": str(row.get("agent_id") or ""),
                "agent_name": str(row.get("agent_name") or ""),
                "target_ip": str(row.get("target_ip") or row.get("ip") or ""),
                "platform": str(row.get("platform") or ""),
                "ok": bool(row.get("ok")),
                "status_code": int(row.get("status_code") or 0),
                "stdout": _to_text(row.get("stdout")),
                "stderr": _to_text(row.get("stderr")),
            },
        )


def _trigger_sca_rescan_best_effort(agent_ids: list[str]) -> dict:
    ordered: list[str] = []
    seen: set[str] = set()
    for aid in agent_ids or []:
        raw = _normalize_agent_identifier(aid)
        if not raw or raw in seen:
            continue
        seen.add(raw)
        ordered.append(raw)
    if not ordered:
        return {
            "ok": False,
            "triggered": [],
            "failed": [],
            "error": "no_agents",
            "attempted": 0,
        }

    try:
        client.restart_agents(ordered)
        return {
            "ok": True,
            "triggered": ordered,
            "failed": [],
            "error": "",
            "attempted": len(ordered),
        }
    except Exception as batch_exc:
        triggered: list[str] = []
        failed: list[dict] = []
        for aid in ordered:
            try:
                client.restart_agents([aid])
                triggered.append(aid)
            except Exception as single_exc:
                failed.append({"agent_id": aid, "error": str(single_exc)})
        return {
            "ok": len(failed) == 0,
            "triggered": triggered,
            "failed": failed,
            "error": str(batch_exc),
            "attempted": len(ordered),
        }


def _run_global_shell_async_job(
    execution_id: int,
    action_id: str,
    dispatch: dict,
    selected_ids: list[str],
) -> None:
    db = connect()
    execution = None
    target_rows = None
    step_name = "orchestration"
    step_stdout = ""
    step_stderr = ""
    execution_status = "SUCCESS"
    step_status = "SUCCESS"
    try:
        db.execute(
            text("UPDATE executions SET status=:status WHERE id=:id"),
            {"status": "RUNNING", "id": execution_id},
        )
        db.commit()
        publish_event(
            int(execution_id),
            {
                "type": "execution_started",
                "step": "orchestration",
                "status": "RUNNING",
                "stdout": f"action={action_id}; targets={len(selected_ids)}",
                "stderr": "",
            },
        )
        try:
            execution = execute_action(
                client,
                action_id,
                dispatch,
                selected_ids,
                execution_id=int(execution_id),
            )
            step_name = execution.get("channel") or "orchestration"
            detail = f"channel={execution.get('channel')}; command={execution.get('command_used')}"
            attempts = execution.get("attempts") or []
            if attempts:
                detail += f"; attempts={','.join(attempts)}"
            step_stdout = f"{detail}\n{json.dumps(execution.get('result'), default=str)}"
            result_payload = execution.get("result")
            if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                target_rows = result_payload.get("results")
        except HTTPException as exc:
            execution_status = "FAILED"
            step_status = "FAILED"
            if isinstance(exc.detail, dict):
                step_name = "endpoint"
                step_stderr = _to_text(exc.detail.get("message") or exc.detail)
                result_payload = exc.detail.get("result")
                if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                    target_rows = result_payload.get("results")
            else:
                step_name = "orchestration"
                step_stderr = _to_text(exc.detail)
        except Exception as exc:
            execution_status = "FAILED"
            step_status = "FAILED"
            step_stderr = _to_text(exc)

        db.execute(
            text(
                """
                INSERT INTO execution_steps
                (execution_id, step, stdout, stderr, status)
                VALUES (:execution_id, :step, :stdout, :stderr, :status)
                """
            ),
            {
                "execution_id": execution_id,
                "step": step_name,
                "stdout": step_stdout,
                "stderr": step_stderr,
                "status": step_status,
            },
        )
        current_status = db.execute(
            text("SELECT status FROM executions WHERE id=:id"),
            {"id": execution_id},
        ).scalar()
        current_upper = str(current_status or "").strip().upper()
        if current_upper in {"KILLED", "CANCELLED"}:
            execution_status = current_upper
        db.execute(
            text(
                """
                UPDATE executions
                SET status=:status, finished_at=COALESCE(finished_at, :finished_at)
                WHERE id=:id
                """
            ),
            {"status": execution_status, "finished_at": utc_now_naive(), "id": execution_id},
        )
        if target_rows:
            _store_execution_targets(db, int(execution_id), target_rows)
            successful_agent_ids = [
                str(row.get("agent_id") or "").strip()
                for row in target_rows
                if isinstance(row, dict) and row.get("ok")
            ]
            if successful_agent_ids:
                rescan = _trigger_sca_rescan_best_effort(successful_agent_ids)
                db.execute(
                    text(
                        """
                        INSERT INTO execution_steps
                        (execution_id, step, stdout, stderr, status)
                        VALUES (:execution_id, :step, :stdout, :stderr, :status)
                        """
                    ),
                    {
                        "execution_id": execution_id,
                        "step": "sca-rescan",
                        "stdout": (
                            f"triggered={len(rescan.get('triggered') or [])}; "
                            f"failed={len(rescan.get('failed') or [])}; "
                            f"attempted={int(rescan.get('attempted') or 0)}"
                        ),
                        "stderr": _to_text(rescan.get("error"))
                        if not rescan.get("ok")
                        else "",
                        "status": "SUCCESS" if rescan.get("ok") else "FAILED",
                    },
                )
        db.commit()

        publish_event(
            int(execution_id),
            {
                "type": "execution_finished",
                "step": step_name,
                "status": execution_status,
                "stdout": "",
                "stderr": step_stderr if step_status == "FAILED" else "",
            },
        )
    finally:
        db.close()


@router.get("")
def actions(user=Depends(require_role("analyst"))):
    return list_actions()


@router.get("/connector-status")
def connector_status(user=Depends(require_role("admin"))):
    executor = EndpointExecutor(client)
    return {
        "orchestration_mode": orchestration_mode(),
        "connectors": executor.connector_status(),
    }


@router.get("/capabilities/{action_id}")
def action_capabilities(action_id: str, user=Depends(require_role("analyst"))):
    """Get capabilities for a specific action."""
    try:
        capabilities = capability_resolver.get_action_capability_summary(action_id)
        return {
            "action_id": action_id,
            "capabilities": capabilities
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get capabilities: {str(e)}")


@router.post("/validate")
async def validate_action(request: Request, user=Depends(require_role("analyst"))):
    """Validate action prerequisites before execution."""
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    action_id = body.get("action_id")
    agent_id = body.get("agent_id")
    agent_ids = body.get("agent_ids") or body.get("agents")
    group = body.get("group")
    args = body.get("args", [])

    if not action_id:
        raise HTTPException(status_code=400, detail="action_id is required")

    try:
        agent_os = _determine_agent_os(agent_id=agent_id, group=group, agent_ids=agent_ids)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent information: {str(e)}")

    # Get connector status
    executor = EndpointExecutor(client)
    connector_status = executor.connector_status()
    if agent_os == "windows":
        probe_agent = str(agent_id or "").strip()
        if probe_agent.lower() in _FLEET_TARGETS:
            probe_agent = ""
        if not probe_agent and agent_ids:
            probe_agent = str(_first_real_agent_id(agent_ids) or "").strip()
        if not probe_agent and group:
            group_ids = client.get_agent_ids(group=group)
            probe_agent = str(_first_real_agent_id(group_ids) or "").strip()
        connector_status.setdefault("connectors", {}).setdefault("windows", {})[
            "credentials_configured"
        ] = executor.has_windows_credentials(probe_agent or None)
    elif agent_os == "linux":
        connector_status.setdefault("connectors", {}).setdefault("linux", {})[
            "credentials_configured"
        ] = bool(
            connector_status.get("connectors", {})
            .get("linux", {})
            .get("credentials_configured", False)
        )

    action = get_action(action_id)
    normalized_args = normalize_args(action, args)

    # Validate prerequisites using normalized positional args (matches action.inputs ordering).
    is_valid, errors = capability_resolver.validate_action_prerequisites(
        action_id, agent_os, normalized_args, connector_status
    )

    # Get preferred channel
    preferred_channel = capability_resolver.resolve_preferred_channel(
        action_id, agent_os, connector_status
    )

    # Get timeout
    timeout_seconds = capability_resolver.get_timeout_seconds(action_id)

    return {
        "action_id": action_id,
        "agent_id": agent_id,
        "agent_os": agent_os,
        "is_valid": is_valid,
        "errors": errors,
        "preferred_channel": preferred_channel,
        "timeout_seconds": timeout_seconds,
        "connector_status": connector_status
    }


@router.post("/test-capability")
async def test_action_capability(request: Request, user=Depends(require_role("admin"))):
    """Test action capability with validation and execution."""
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    action_id = body.get("action_id") or "endpoint-healthcheck"
    agent_id = body.get("agent_id")
    agent_ids = body.get("agent_ids") or body.get("agents")
    group = body.get("group")
    exclude_agent_ids = body.get("exclude_agent_ids") or body.get("exclude_agents") or []
    args = body.get("args", [])

    if not agent_id and not group and not agent_ids:
        raise HTTPException(status_code=400, detail="agent_id, agent_ids or group is required")

    try:
        agent_os = _determine_agent_os(agent_id=agent_id, group=group, agent_ids=agent_ids)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent information: {str(e)}")

    # Get connector status
    executor = EndpointExecutor(client)
    connector_status = executor.connector_status()
    if agent_os == "windows":
        probe_agent = str(agent_id or "").strip()
        if probe_agent.lower() in _FLEET_TARGETS:
            probe_agent = ""
        if not probe_agent and agent_ids:
            probe_agent = str(_first_real_agent_id(agent_ids) or "").strip()
        if not probe_agent and group:
            group_ids = client.get_agent_ids(group=group)
            probe_agent = str(_first_real_agent_id(group_ids) or "").strip()
        connector_status.setdefault("connectors", {}).setdefault("windows", {})[
            "credentials_configured"
        ] = executor.has_windows_credentials(probe_agent or None)

    action = get_action(action_id)
    normalized_args = normalize_args(action, args)

    # Validate prerequisites using normalized positional args (matches action.inputs ordering).
    is_valid, validation_errors = capability_resolver.validate_action_prerequisites(
        action_id, agent_os, normalized_args, connector_status
    )

    result = {
        "action_id": action_id,
        "agent_id": agent_id,
        "agent_os": agent_os,
        "validation_passed": is_valid,
        "validation_errors": validation_errors,
        "preferred_channel": capability_resolver.resolve_preferred_channel(action_id, agent_os, connector_status),
        "timeout_seconds": capability_resolver.get_timeout_seconds(action_id),
        "connector_status": connector_status
    }

    # If validation passes, attempt execution
    if is_valid:
        try:
            arguments = normalized_args
            dispatch = resolve_action_dispatch(action, arguments)

            resolved_agent_ids = []
            if agent_ids:
                resolved_agent_ids = [str(a).strip() for a in agent_ids if str(a).strip()]
            else:
                resolved_agent_ids = resolve_agent_ids(client, target=agent_id, group=group)
            if exclude_agent_ids:
                exclude_norm = {str(a).strip() for a in exclude_agent_ids if str(a).strip()}
                resolved_agent_ids = [
                    aid for aid in resolved_agent_ids if str(aid).strip() not in exclude_norm
                ]
            if not resolved_agent_ids:
                raise HTTPException(status_code=404, detail="No agents resolved for target")

            execution = execute_action(client, action_id, dispatch, resolved_agent_ids)
            
            result.update({
                "execution_status": "success",
                "execution_channel": execution.get("channel"),
                "execution_mode": execution.get("mode"),
                "execution_result": execution.get("result"),
                "resolved_agents": resolved_agent_ids,
            })
            
            log_audit(
                "action_capability_tested",
                actor=user.get("sub"),
                entity_type="action",
                entity_id=action_id,
                detail=f"target={group or agent_id}; channel={execution.get('channel')}; validation_passed=true",
                org_id=user.get("org_id"),
                ip_address=request.client.host if request.client else None,
            )
            
        except Exception as e:
            result.update({
                "execution_status": "failed",
                "execution_error": str(e)
            })
            
            log_audit(
                "action_capability_test_failed",
                actor=user.get("sub"),
                entity_type="action",
                entity_id=action_id,
                detail=f"target={group or agent_id}; validation_passed=true; execution_error={str(e)}",
                org_id=user.get("org_id"),
                ip_address=request.client.host if request.client else None,
            )
    else:
        log_audit(
            "action_capability_test_failed",
            actor=user.get("sub"),
            entity_type="action",
            entity_id=action_id,
            detail=f"target={group or agent_id}; validation_passed=false; errors={','.join(validation_errors)}",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )

    return result


@router.post("/test")
async def test_action_path(request: Request, user=Depends(require_role("admin"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    target = body.get("agent_id")
    group = body.get("group")
    action_id = body.get("action_id") or "endpoint-healthcheck"

    if not target and not group:
        raise HTTPException(status_code=400, detail="agent_id or group is required")

    action = get_action(action_id)
    dispatch = resolve_action_dispatch(action, [])
    agent_ids = resolve_agent_ids(client, target=target, group=group)
    execution = execute_action(client, action_id, dispatch, agent_ids)

    log_audit(
        "action_tested",
        actor=user.get("sub"),
        entity_type="action",
        entity_id=action_id,
        detail=f"target={group or target}; agents={len(agent_ids)}; mode={execution.get('mode')}",
        org_id=user.get("org_id"),
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "action_id": action_id,
        "target": group or target,
        "agents": agent_ids,
        "channel": execution.get("channel"),
        "mode": execution.get("mode"),
        "command_used": execution.get("command_used"),
        "attempts": execution.get("attempts"),
        "result": execution.get("result"),
    }


@router.post("/run")
async def run_action(request: Request, user=Depends(require_role("admin"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    agent_id = body.get("agent_id")
    group = body.get("group")
    action_id = body.get("action_id")
    args = body.get("args")

    if not action_id or (not agent_id and not group):
        raise HTTPException(status_code=400, detail="action_id and agent_id or group are required")

    action = get_action(action_id)
    arguments = normalize_args(action, args)
    dispatch = resolve_action_dispatch(action, arguments)
    agent_ids = resolve_agent_ids(client, target=agent_id, group=group)
    execution = execute_action(client, action_id, dispatch, agent_ids)

    log_audit(
        "action_executed",
        actor=user.get("sub"),
        entity_type="action",
        entity_id=action_id,
        detail=f"target={group or agent_id}; channel={execution.get('channel')}",
        org_id=user.get("org_id"),
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "executed",
        "channel": execution.get("channel"),
        "mode": execution.get("mode"),
        "command_used": execution.get("command_used"),
        "attempts": execution.get("attempts"),
        "result": execution.get("result"),
    }


@router.post("/global-shell")
async def run_global_shell(request: Request, user=Depends(require_role("admin"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    shell = str(body.get("shell") or "powershell").strip().lower()
    if shell not in {"powershell", "cmd"}:
        logger.warning("global-shell rejected: invalid shell=%s", shell)
        raise HTTPException(status_code=400, detail="shell must be 'powershell' or 'cmd'")
    async_raw = body.get("async")
    if async_raw is None:
        async_mode = True
    elif isinstance(async_raw, bool):
        async_mode = async_raw
    elif isinstance(async_raw, str):
        async_mode = async_raw.strip().lower() in {"1", "true", "yes", "on"}
    else:
        async_mode = bool(async_raw)

    raw_command = str(body.get("command") or "").strip()
    if not raw_command:
        logger.warning("global-shell rejected: empty command")
        raise HTTPException(status_code=400, detail="command is required")
    if len(raw_command) > _GLOBAL_SHELL_MAX_COMMAND_CHARS:
        logger.warning(
            "global-shell rejected: command too long len=%s max=%s",
            len(raw_command),
            _GLOBAL_SHELL_MAX_COMMAND_CHARS,
        )
        raise HTTPException(
            status_code=400,
            detail=f"command is too long (max {_GLOBAL_SHELL_MAX_COMMAND_CHARS} chars)",
        )
    run_as_system_raw = body.get("run_as_system")
    if run_as_system_raw is None:
        run_as_system = False
    elif isinstance(run_as_system_raw, bool):
        run_as_system = run_as_system_raw
    elif isinstance(run_as_system_raw, str):
        run_as_system = run_as_system_raw.strip().lower() in {"1", "true", "yes", "on"}
    else:
        run_as_system = bool(run_as_system_raw)
    raw_justification = str(body.get("justification") or body.get("reason") or "").strip()
    justification_provided = len(raw_justification) >= 12
    justification = (
        raw_justification
        if justification_provided
        else "Global shell execution requested by analyst."
    )

    target_agent_id = _normalize_agent_identifier(body.get("agent_id") or "")
    target_group = str(body.get("group") or "").strip()
    target_group_key = target_group.lower()
    target_agent_ids = _normalize_agent_id_list(body.get("agent_ids") or body.get("agents"))
    if target_agent_ids:
        target_mode = "multi"
    elif target_group:
        target_mode = "group"
    elif target_agent_id and target_agent_id.lower() not in _FLEET_TARGETS:
        target_mode = "agent"
    else:
        target_mode = "fleet"

    requested_set = set(target_agent_ids)
    if target_mode == "agent" and target_agent_id:
        requested_set.add(target_agent_id)

    exclude_set = set(_normalize_agent_id_list(body.get("exclude_agent_ids") or body.get("exclude_agents")))

    agents_data = client.get_agents(use_cache=True)
    agents = [item for item in _extract_items(agents_data) if isinstance(item, dict)]
    connected_total = 0
    connected_windows = 0
    skipped_non_windows = 0
    excluded_count = 0
    selected_ids = []
    seen = set()

    for agent in agents:
        agent_id = _normalize_agent_identifier(agent.get("id") or agent.get("agent_id") or "")
        if not agent_id or agent_id in {"000", "0"}:
            continue

        in_scope = False
        if target_mode == "fleet":
            in_scope = True
        elif target_mode == "group":
            in_scope = bool(target_group_key and target_group_key in _agent_groups(agent))
        elif target_mode == "multi":
            in_scope = agent_id in requested_set
        else:
            in_scope = bool(target_agent_id and agent_id == target_agent_id)
        if not in_scope:
            continue

        status = _agent_status(agent)
        if status not in _CONNECTED_STATUSES:
            continue
        connected_total += 1

        platform = _agent_platform(agent)
        if platform != "windows":
            skipped_non_windows += 1
            continue
        connected_windows += 1

        if agent_id in exclude_set:
            excluded_count += 1
            continue
        if agent_id in seen:
            continue
        seen.add(agent_id)
        selected_ids.append(agent_id)

    if not selected_ids:
        detail = "No connected Windows agents available after filtering"
        if target_mode == "agent":
            detail = "Requested agent is not connected as a Windows endpoint or was excluded"
        elif target_mode == "multi":
            detail = "No requested agents are connected Windows endpoints after exclusions"
        elif target_mode == "group":
            detail = f"No connected Windows agents found in group '{target_group}' after exclusions"
        raise HTTPException(
            status_code=404,
            detail=detail,
        )

    # Global Shell must execute analyst-authored commands verbatim.
    command_to_run = raw_command
    if shell == "cmd":
        command_to_run = _wrap_cmd_for_powershell(raw_command)

    # Respect explicit analyst selection from request body.
    effective_run_as_system = bool(run_as_system)
    verify_kb = str(body.get("verify_kb") or "").strip()
    verify_min_build = str(body.get("verify_min_build") or "").strip()
    verify_stdout_contains = str(body.get("verify_stdout_contains") or "").strip()

    execution_action_id = "global-shell"
    transport_action_id = "custom-os-command"
    action = get_action(transport_action_id)
    arguments = _coerce_custom_os_command_arguments(
        normalize_args(
            action,
            {
                "command": command_to_run,
                "verify_kb": verify_kb,
                "verify_min_build": verify_min_build,
                "verify_stdout_contains": verify_stdout_contains,
                "run_as_system": "true" if effective_run_as_system else "false",
            },
        ),
        command=command_to_run,
        verify_kb=verify_kb,
        verify_min_build=verify_min_build,
        verify_stdout_contains=verify_stdout_contains,
        run_as_system=effective_run_as_system,
    )
    dispatch = resolve_action_dispatch(action, arguments)
    actor = user.get("sub") if isinstance(user, dict) else str(user)
    org_id = user.get("org_id") if isinstance(user, dict) else None

    # Run async by default so large fleet shell requests return immediately and stream via execution history.
    if async_mode:
        db = connect()
        try:
            started_at = utc_now_naive()
            target = "multi:" + ",".join(selected_ids)
            inserted = db.execute(
                text(
                    """
                    INSERT INTO executions
                    (approval_id, agent, playbook, action, args, status, approved_by, started_at, alert_id, org_id)
                    VALUES (:approval_id, :agent, :playbook, :action, :args, :status, :approved_by, :started_at, :alert_id, :org_id)
                    RETURNING id
                    """
                ),
                {
                    "approval_id": None,
                    "agent": target,
                    "playbook": execution_action_id,
                    "action": execution_action_id,
                    "args": json.dumps(arguments, default=str),
                    "status": "QUEUED",
                    "approved_by": actor,
                    "started_at": started_at,
                    "alert_id": None,
                    "org_id": org_id,
                },
            )
            execution_id = int(inserted.scalar())
            if justification:
                db.execute(
                    text(
                        """
                        INSERT INTO execution_metadata (execution_id, justification)
                        VALUES (:execution_id, :justification)
                        """
                    ),
                    {"execution_id": execution_id, "justification": justification},
                )
            db.commit()
        finally:
            db.close()

        worker = threading.Thread(
            target=_run_global_shell_async_job,
            args=(execution_id, execution_action_id, dispatch, selected_ids),
            daemon=True,
        )
        worker.start()

        summary = {
            "target_mode": target_mode,
            "requested_agents": len(requested_set) if requested_set else None,
            "connected_agents_seen": connected_total,
            "connected_windows_seen": connected_windows,
            "targeted_agents": len(selected_ids),
            "excluded_agents": excluded_count,
            "skipped_non_windows": skipped_non_windows,
            "success": 0,
            "failed": 0,
        }

        log_audit(
            "global_shell_queued",
            actor=actor,
            entity_type="execution",
            entity_id=str(execution_id),
            detail=(
                f"shell={shell}; targeted={summary['targeted_agents']}; "
                f"target_mode={target_mode}; "
                f"connected_seen={summary['connected_agents_seen']}; "
                f"skipped_non_windows={summary['skipped_non_windows']}; "
                f"run_as_system={'yes' if effective_run_as_system else 'no'}; "
                f"justification_provided={'yes' if justification_provided else 'no'}"
            ),
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
        )

        return {
            "status": "queued",
            "action_id": execution_action_id,
            "transport_action_id": transport_action_id,
            "shell": shell,
            "command": raw_command,
            "command_used": command_to_run,
            "run_as_system": effective_run_as_system,
            "execution_id": execution_id,
            "agent_ids": selected_ids,
            "summary": summary,
            "justification_provided": bool(justification_provided),
            "history_available": True,
        }

    execution = execute_action(client, execution_action_id, dispatch, selected_ids)
    result = execution.get("result") if isinstance(execution, dict) else {}
    summary = {
        "target_mode": target_mode,
        "requested_agents": len(requested_set) if requested_set else None,
        "connected_agents_seen": connected_total,
        "connected_windows_seen": connected_windows,
        "targeted_agents": len(selected_ids),
        "excluded_agents": excluded_count,
        "skipped_non_windows": skipped_non_windows,
        "success": int(result.get("success") or 0) if isinstance(result, dict) else 0,
        "failed": int(result.get("failed") or 0) if isinstance(result, dict) else 0,
    }
    return {
        "status": "executed" if summary["failed"] == 0 else "executed_with_failures",
        "action_id": execution_action_id,
        "transport_action_id": transport_action_id,
        "shell": shell,
        "command": raw_command,
        "command_used": command_to_run,
        "run_as_system": effective_run_as_system,
        "channel": execution.get("channel"),
        "mode": execution.get("mode"),
        "attempts": execution.get("attempts"),
        "agent_ids": selected_ids,
        "summary": summary,
        "justification_provided": bool(justification_provided),
        "result": result,
    }

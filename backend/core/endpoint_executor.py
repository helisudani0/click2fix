import base64
import hashlib
import json
import os
import re
import shlex
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from fastapi import HTTPException
from sqlalchemy import text

from core.indexer_client import IndexerClient
from core.settings import SETTINGS


def _cfg(path: str, default: Any = None) -> Any:
    node = SETTINGS if isinstance(SETTINGS, dict) else {}
    for key in path.split("."):
        if not isinstance(node, dict):
            return default
        node = node.get(key)
        if node is None:
            return default
    return node


def _read_secret(value: Optional[str], env_key: Optional[str]) -> str:
    if env_key:
        env_value = os.getenv(env_key)
        if env_value:
            return env_value
    return value or ""


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _sh_quote(value: str) -> str:
    return shlex.quote(str(value))


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


class EndpointExecutor:
    _target_cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, wazuh_client):
        self.client = wazuh_client
        self.max_workers = int(_cfg("orchestration.bulk_max_workers", 10))
        self.stop_on_error = _bool(_cfg("orchestration.stop_on_error", False), False)
        self.default_timeout = int(_cfg("orchestration.timeout_seconds", 120))
        self.windows_patch_stagger_seconds = max(0, int(_cfg("orchestration.windows_patch_stagger_seconds", 0) or 0))
        self.windows_patch_stagger_min_targets = max(2, int(_cfg("orchestration.windows_patch_stagger_min_targets", 5) or 5))
        self.windows_os_update_profile_fallback = _bool(
            _cfg("orchestration.windows_os_update_profile_fallback_on_missing_target", True),
            True,
        )
        self.windows_os_update_force_kb_fallback_enabled = _bool(
            _cfg("orchestration.windows_os_update_force_kb_fallback_enabled", True),
            True,
        )
        self.windows_os_update_force_kb_fallback_timeout_seconds = max(
            120,
            _to_int(
                _cfg("orchestration.windows_os_update_force_kb_fallback_timeout_seconds", 1200),
                1200,
            ),
        )
        self.indexer = IndexerClient()
        self.circuit_breaker_enabled = _bool(
            os.getenv(
                "C2F_CIRCUIT_BREAKER_ENABLED",
                _cfg("orchestration.circuit_breaker_enabled", True),
            ),
            True,
        )
        self.circuit_breaker_threshold_percent = max(
            10,
            min(
                99,
                _to_int(
                    os.getenv(
                        "C2F_CIRCUIT_BREAKER_THRESHOLD_PERCENT",
                        _cfg("orchestration.circuit_breaker_threshold_percent", 90),
                    ),
                    90,
                ),
            ),
        )
        self.circuit_breaker_poll_seconds = max(
            1,
            _to_int(
                os.getenv(
                    "C2F_CIRCUIT_BREAKER_POLL_SECONDS",
                    _cfg("orchestration.circuit_breaker_poll_seconds", 2),
                ),
                2,
            ),
        )
        self.circuit_breaker_max_pause_seconds = max(
            self.circuit_breaker_poll_seconds,
            _to_int(
                os.getenv(
                    "C2F_CIRCUIT_BREAKER_MAX_PAUSE_SECONDS",
                    _cfg("orchestration.circuit_breaker_max_pause_seconds", 120),
                ),
                120,
            ),
        )
        self.circuit_breaker_memory_limit_bytes = self._resolve_memory_limit_bytes()

        self.windows_cfg = {
            "enabled": _bool(
                os.getenv(
                    "C2F_WINDOWS_CONNECTOR_ENABLED",
                    _cfg("endpoint_connectors.windows.enabled", True),
                ),
                True,
            ),
            "transport": str(_cfg("endpoint_connectors.windows.transport", "ntlm")).strip() or "ntlm",
            "use_https": _bool(_cfg("endpoint_connectors.windows.use_https", False), False),
            "port": int(_cfg("endpoint_connectors.windows.port", 5985)),
            "verify_tls": _bool(_cfg("endpoint_connectors.windows.verify_tls", False), False),
            "username": _read_secret(
                _cfg("endpoint_connectors.windows.username", ""),
                _cfg("endpoint_connectors.windows.username_env", "C2F_WINRM_USERNAME"),
            ),
            "password": _read_secret(
                _cfg("endpoint_connectors.windows.password", ""),
                _cfg("endpoint_connectors.windows.password_env", "C2F_WINRM_PASSWORD"),
            ),
        }
        raw_windows_agent_credentials = _cfg("endpoint_connectors.windows.agent_credentials", {})
        self.windows_agent_credentials: Dict[str, Dict[str, str]] = {}
        if isinstance(raw_windows_agent_credentials, dict):
            for key, value in raw_windows_agent_credentials.items():
                if not isinstance(value, dict):
                    continue
                aid = self._normalize_agent_id(str(key))
                if not aid:
                    continue
                self.windows_agent_credentials[aid] = {
                    "username": _read_secret(
                        value.get("username", ""),
                        value.get("username_env"),
                    ),
                    "password": _read_secret(
                        value.get("password", ""),
                        value.get("password_env"),
                    ),
                }

        self.linux_cfg = {
            "enabled": _bool(
                os.getenv(
                    "C2F_LINUX_CONNECTOR_ENABLED",
                    _cfg("endpoint_connectors.linux.enabled", False),
                ),
                False,
            ),
            "port": int(_cfg("endpoint_connectors.linux.port", 22)),
            "username": _read_secret(
                _cfg("endpoint_connectors.linux.username", ""),
                _cfg("endpoint_connectors.linux.username_env", "C2F_SSH_USERNAME"),
            ),
            "password": _read_secret(
                _cfg("endpoint_connectors.linux.password", ""),
                _cfg("endpoint_connectors.linux.password_env", "C2F_SSH_PASSWORD"),
            ),
            "key_file": _cfg("endpoint_connectors.linux.key_file", ""),
        }

    def connector_status(self) -> Dict[str, Any]:
        per_agent_ready = sorted(
            aid
            for aid, creds in self.windows_agent_credentials.items()
            if creds.get("username") and creds.get("password")
        )
        global_ready = bool(self.windows_cfg["username"] and self.windows_cfg["password"])
        return {
            "windows": {
                "enabled": self.windows_cfg["enabled"],
                "transport": self.windows_cfg["transport"],
                "use_https": self.windows_cfg["use_https"],
                "port": self.windows_cfg["port"],
                "verify_tls": self.windows_cfg["verify_tls"],
                "credentials_configured": global_ready or bool(per_agent_ready),
                "global_credentials_configured": global_ready,
                "per_agent_credentials_configured": per_agent_ready,
            },
            "linux": {
                "enabled": self.linux_cfg["enabled"],
                "port": self.linux_cfg["port"],
                "credentials_configured": bool(
                    self.linux_cfg["username"]
                    and (self.linux_cfg["password"] or self.linux_cfg["key_file"])
                ),
                "key_file_configured": bool(self.linux_cfg["key_file"]),
            },
            "limits": {
                "bulk_max_workers": self.max_workers,
                "timeout_seconds": self.default_timeout,
                "stop_on_error": self.stop_on_error,
                "windows_patch_stagger_seconds": self.windows_patch_stagger_seconds,
                "windows_patch_stagger_min_targets": self.windows_patch_stagger_min_targets,
                "windows_os_update_force_kb_fallback_enabled": self.windows_os_update_force_kb_fallback_enabled,
                "windows_os_update_force_kb_fallback_timeout_seconds": self.windows_os_update_force_kb_fallback_timeout_seconds,
                "circuit_breaker_enabled": self.circuit_breaker_enabled,
                "circuit_breaker_threshold_percent": self.circuit_breaker_threshold_percent,
                "circuit_breaker_poll_seconds": self.circuit_breaker_poll_seconds,
                "circuit_breaker_max_pause_seconds": self.circuit_breaker_max_pause_seconds,
                "circuit_breaker_memory_limit_bytes": self.circuit_breaker_memory_limit_bytes,
            },
        }

    def _action_timeout_seconds(self, action_id: str) -> int:
        """
        Action-specific timeout budget (seconds).

        We read this from settings.yaml (active_response.commands[].capabilities.timeout_seconds) so
        long-running actions (patching, forensics) don't get killed by connector defaults.
        """
        fallback = int(self.default_timeout or 120)
        aid = str(action_id or "").strip().lower()
        if not aid:
            return fallback
        commands = _cfg("active_response.commands", [])
        if not isinstance(commands, list):
            return fallback
        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            cmd_id = str(cmd.get("id") or "").strip().lower()
            cmd_name = str(cmd.get("command") or "").strip().lower()
            if aid not in {cmd_id, cmd_name}:
                continue
            caps = cmd.get("capabilities") or {}
            if not isinstance(caps, dict):
                return fallback
            value = caps.get("timeout_seconds")
            try:
                parsed = int(value)
            except Exception:
                return fallback
            return parsed if parsed > 0 else fallback
        return fallback

    def _execution_tag(self, context: Optional[Dict[str, Any]]) -> str:
        if not isinstance(context, dict):
            return f"adhoc-{int(time.time() * 1000)}"
        exec_id = context.get("execution_id")
        if exec_id is not None:
            return str(exec_id)
        key = "_adhoc_exec_tag"
        tag = str(context.get(key) or "").strip()
        if not tag:
            tag = f"adhoc-{int(time.time() * 1000)}"
            context[key] = tag
        return tag

    def _read_int_file(self, path: str) -> Optional[int]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
        except Exception:
            return None
        if not raw or raw.lower() == "max":
            return None
        if not raw.isdigit():
            return None
        try:
            return int(raw)
        except Exception:
            return None

    def _read_cgroup_memory_limit_bytes(self) -> Optional[int]:
        paths = [
            "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        ]
        for path in paths:
            value = self._read_int_file(path)
            if value is None:
                continue
            # cgroup "unlimited" sentinel values should not be treated as limits.
            if value <= 0 or value >= (1 << 60):
                continue
            return value
        return None

    def _read_cgroup_memory_usage_bytes(self) -> Optional[int]:
        paths = [
            "/sys/fs/cgroup/memory.current",
            "/sys/fs/cgroup/memory/memory.usage_in_bytes",
        ]
        for path in paths:
            value = self._read_int_file(path)
            if value is not None and value >= 0:
                return value
        return None

    def _read_proc_meminfo_snapshot_bytes(self) -> Optional[Dict[str, int]]:
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except Exception:
            return None
        values: Dict[str, int] = {}
        for line in lines:
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            parts = raw.strip().split()
            if not parts:
                continue
            if not parts[0].isdigit():
                continue
            values[key.strip()] = int(parts[0]) * 1024
        total = values.get("MemTotal")
        available = values.get("MemAvailable")
        if total is None or available is None:
            return None
        used = max(0, total - available)
        return {
            "total_bytes": int(total),
            "used_bytes": int(used),
        }

    def _read_windows_memory_snapshot_bytes(self) -> Optional[Dict[str, int]]:
        if os.name != "nt":
            return None
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return None
            total = int(stat.ullTotalPhys)
            available = int(stat.ullAvailPhys)
            if total <= 0:
                return None
            used = max(0, total - available)
            return {
                "total_bytes": total,
                "used_bytes": used,
            }
        except Exception:
            return None

    def _read_sysconf_memory_snapshot_bytes(self) -> Optional[Dict[str, int]]:
        if not hasattr(os, "sysconf"):
            return None
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            total_pages = int(os.sysconf("SC_PHYS_PAGES"))
            available_pages = int(os.sysconf("SC_AVPHYS_PAGES"))
        except Exception:
            return None
        if page_size <= 0 or total_pages <= 0:
            return None
        total = page_size * total_pages
        available = max(0, page_size * max(0, available_pages))
        used = max(0, total - min(available, total))
        return {
            "total_bytes": int(total),
            "used_bytes": int(used),
        }

    def _read_host_memory_snapshot_bytes(self) -> Optional[Dict[str, int]]:
        readers = (
            self._read_proc_meminfo_snapshot_bytes,
            self._read_windows_memory_snapshot_bytes,
            self._read_sysconf_memory_snapshot_bytes,
        )
        for reader in readers:
            snapshot = reader()
            if not isinstance(snapshot, dict):
                continue
            total = _to_int(snapshot.get("total_bytes"), 0)
            used = _to_int(snapshot.get("used_bytes"), -1)
            if total <= 0 or used < 0:
                continue
            if used > total:
                used = total
            return {"total_bytes": total, "used_bytes": used}
        return None

    def _resolve_memory_limit_bytes(self) -> int:
        env_limit_mb = _to_int(
            os.getenv(
                "C2F_CIRCUIT_BREAKER_MEMORY_LIMIT_MB",
                _cfg("orchestration.circuit_breaker_memory_limit_mb", 0),
            ),
            0,
        )
        if env_limit_mb > 0:
            return env_limit_mb * 1024 * 1024
        cgroup_limit = self._read_cgroup_memory_limit_bytes()
        if cgroup_limit and cgroup_limit > 0:
            return cgroup_limit
        host_snapshot = self._read_host_memory_snapshot_bytes()
        if host_snapshot is not None:
            host_total = _to_int(host_snapshot.get("total_bytes"), 0)
            if host_total > 0:
                return host_total
        return 0

    def _current_memory_usage_bytes(self) -> Optional[int]:
        cgroup_usage = self._read_cgroup_memory_usage_bytes()
        if cgroup_usage is not None:
            return cgroup_usage
        host_snapshot = self._read_host_memory_snapshot_bytes()
        if host_snapshot is None:
            return None
        used = _to_int(host_snapshot.get("used_bytes"), -1)
        return used if used >= 0 else None

    def _memory_pressure_snapshot(self) -> Optional[Dict[str, float]]:
        limit = int(self.circuit_breaker_memory_limit_bytes or self._resolve_memory_limit_bytes())
        if limit <= 0:
            return None
        usage = self._current_memory_usage_bytes()
        if usage is None or usage < 0:
            return None
        usage_percent = (float(usage) / float(limit)) * 100.0
        return {
            "usage_bytes": float(usage),
            "limit_bytes": float(limit),
            "usage_percent": usage_percent,
        }

    def _guard_task_ingestion_for_memory(self, action_id: str, event_sink=None) -> None:
        if not self.circuit_breaker_enabled:
            return
        snapshot = self._memory_pressure_snapshot()
        if snapshot is None:
            return
        threshold = float(self.circuit_breaker_threshold_percent)
        if snapshot["usage_percent"] < threshold:
            return

        started = time.time()
        pause_emitted = False
        while snapshot["usage_percent"] >= threshold:
            if not pause_emitted and event_sink:
                try:
                    event_sink(
                        {
                            "type": "circuit_breaker",
                            "step": "endpoint",
                            "status": "PAUSED",
                            "stdout": (
                                f"Pausing new target ingestion for action={action_id}: "
                                f"memory usage {snapshot['usage_percent']:.1f}% "
                                f"(threshold {threshold:.1f}%)"
                            ),
                            "stderr": "",
                        }
                    )
                except Exception:
                    pass
                pause_emitted = True

            if (time.time() - started) >= float(self.circuit_breaker_max_pause_seconds):
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Circuit breaker open: memory usage "
                        f"{snapshot['usage_percent']:.1f}% exceeded threshold "
                        f"{threshold:.1f}% for more than {self.circuit_breaker_max_pause_seconds}s"
                    ),
                )

            time.sleep(float(self.circuit_breaker_poll_seconds))
            snapshot = self._memory_pressure_snapshot()
            if snapshot is None:
                break

        if pause_emitted and event_sink:
            try:
                event_sink(
                    {
                        "type": "circuit_breaker",
                        "step": "endpoint",
                        "status": "RESUMED",
                        "stdout": f"Resumed target ingestion for action={action_id}",
                        "stderr": "",
                    }
                )
            except Exception:
                pass

    def _windows_action_script_path(self, action_id: str) -> str:
        safe = str(action_id or "action").strip().lower().replace("/", "-").replace("\\", "-")
        safe = "".join(ch for ch in safe if ch.isalnum() or ch in {"-", "_"})
        if not safe:
            safe = "action"
        return rf"C:\Click2Fix\scripts\{safe}.ps1"

    def _windows_action_script_content(self, action_id: str) -> Optional[str]:
        aid = str(action_id or "").strip().lower()
        if aid not in {
            "patch-windows",
            "package-update",
            "custom-os-command",
            "malware-scan",
            "threat-hunt-persistence",
            "ioc-scan",
            "toc-scan",
            "yara-scan",
            "collect-forensics",
            "collect-memory",
            "hash-blocklist",
        }:
            return None

        if aid == "package-update":
            return r"""
	param(
	  [string]$ExecId = "adhoc",
	  [string]$AgentId = "",
	  [string]$ActionId = "package-update",
	  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
	  [string]$PackageSpec = "all",
	  [string]$Version = "",
	  [int]$MaxRuntimeSeconds = 1800
	)

	$ErrorActionPreference = "Stop"
	$ProgressPreference = "SilentlyContinue"

	function Write-C2FLogLine {
	  param([string]$Line)
	  try {
	    $dir = Split-Path -Parent $LogFile
	    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
	    Add-Content -Path $LogFile -Value $Line
	  } catch { }
	}

	if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
	  function C2F-Evidence {
	    param([string]$Message)
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
	    } catch { }
	  }
	}

		if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
		  function C2F-Status {
	    param([string]$Status, [string]$Message = "")
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
	      if ($Message) {
	        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
	        $line = $line + " message=" + $clean
	      }
	      Write-C2FLogLine $line
	    } catch { }
		  }
		}

		function Quote-C2FCmdArg {
		  param([string]$Value)
		  if ($null -eq $Value) { return '""' }
		  $v = [string]$Value
		  if ($v -notmatch '[\s"]') { return $v }
		  return '"' + $v.Replace('"', '""') + '"'
		}

		function Invoke-C2FProcess {
		  param(
		    [string]$FilePath,
		    [string]$ArgLine,
		    [int]$TimeoutSeconds = 120
		  )
		  $base = Join-Path $env:TEMP ("c2f_" + [guid]::NewGuid().ToString())
		  $outFile = $base + ".out"
		  $errFile = $base + ".err"
		  try { Remove-Item -Path $outFile, $errFile -Force -ErrorAction SilentlyContinue } catch { }

		  $proc = $null
		  $usedFile = $FilePath
		  $usedArgs = $ArgLine
		  try {
		    $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgLine -NoNewWindow -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
		  } catch {
		    # WindowsApps winget.exe can fail to start directly. Fall back to cmd.exe /c.
		    $usedFile = $env:ComSpec
		    $usedArgs = "/d /c " + (Quote-C2FCmdArg $FilePath) + " " + $ArgLine
		    $proc = Start-Process -FilePath $env:ComSpec -ArgumentList $usedArgs -NoNewWindow -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
		  }

		  $deadline = (Get-Date).AddSeconds([Math]::Max(5, [int]$TimeoutSeconds))
		  while ($proc -and (-not $proc.HasExited)) {
		    if ((Get-Date) -ge $deadline) {
		      try { & taskkill.exe /PID $proc.Id /T /F | Out-Null } catch { }
		      break
		    }
		    Start-Sleep -Seconds 1
		  }

		  $timedOut = $false
		  $rc = 1
		  if ($proc -and (-not $proc.HasExited)) {
		    $timedOut = $true
		    $rc = 124
		  } elseif ($proc) {
		    try { $rc = [int]$proc.ExitCode } catch { $rc = 1 }
		  }

		  $stdout = ""
		  $stderr = ""
		  try { $stdout = Get-Content -Path $outFile -Raw -ErrorAction SilentlyContinue } catch { }
		  try { $stderr = Get-Content -Path $errFile -Raw -ErrorAction SilentlyContinue } catch { }
		  try { Remove-Item -Path $outFile, $errFile -Force -ErrorAction SilentlyContinue } catch { }

		  $combined = (($stdout + "`n" + $stderr).Replace("`r", "")).Trim()
		  return @{
		    "file" = [string]$usedFile
		    "args" = [string]$usedArgs
		    "output" = [string]$combined
		    "exit_code" = [int]$rc
		    "timed_out" = [bool]$timedOut
		  }
		}

			function Invoke-C2FWinget {
			  # NOTE: Do not name this parameter $Args - that's an automatic PowerShell variable
			  # holding *unbound* arguments, and it will be empty when using named parameters.
			  param([string[]]$WingetArgs, [int]$TimeoutSeconds = 120)
			  $argArray = @()
			  if ($null -ne $WingetArgs) { $argArray = @($WingetArgs) }
			  $methods = @()
			  $windowsShim = ""
			  try {
			    $pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
			    if (-not $pkg) {
			      $pkg = Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
			    }
			    if ($pkg -and $pkg.InstallLocation) {
			      $appxWinget = Join-Path $pkg.InstallLocation 'winget.exe'
			      if (Test-Path $appxWinget) { $methods += $appxWinget }
			    }
			  } catch { }
			  try {
			    $whereRaw = (& where.exe winget 2>$null | Out-String)
			    foreach ($line in ($whereRaw -split "`r?`n")) {
			      $p = [string]$line
			      if (-not $p) { continue }
			      $p = $p.Trim()
			      if (-not $p) { continue }
			      if ($p.ToLower().EndsWith('winget.exe') -and (Test-Path $p)) {
			        if ($p.ToLower() -eq 'c:\windows\winget.exe') {
			          $windowsShim = $p
			        } else {
			          $methods += $p
			        }
			      }
			    }
			  } catch { }
			  try {
			    $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
			    if ($cmd -and $cmd.Source) {
			      $source = [string]$cmd.Source
			      if ($source.ToLower() -eq 'c:\windows\winget.exe') {
			        $windowsShim = $source
			      } else {
			        $methods += $source
			      }
			    }
			  } catch { }
			  $localAlias = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
			  if (Test-Path $localAlias) { $methods += $localAlias }
		  try {
		    $waRoot = Join-Path $env:ProgramFiles 'WindowsApps'
		    if (Test-Path $waRoot) {
		      $dir = Get-ChildItem -Path $waRoot -Directory -Filter 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
			      if ($dir) {
			        $exe = Join-Path $dir.FullName 'winget.exe'
			        if (Test-Path $exe) { $methods += $exe }
			      }
			    }
			  } catch { }
			  $methods += 'winget'
			  if ($windowsShim) { $methods += $windowsShim }
			  $methods = $methods | Where-Object { $_ } | Select-Object -Unique
			  if (-not $script:C2FWingetMethodsLogged) {
			    try {
			      C2F-Evidence ("winget_methods=" + ([string]::Join(";", @($methods))).Replace("|", "/"))
			    } catch { }
			    $script:C2FWingetMethodsLogged = $true
			  }

		  $argLine = [string]::Join(' ', @($argArray | ForEach-Object { Quote-C2FCmdArg $_ }))
		  $lastError = ""
		  foreach ($m in $methods) {
		    try {
		      if ($m -eq 'winget') {
		        $res = Invoke-C2FProcess -FilePath $env:ComSpec -ArgLine ("/d /c winget " + $argLine) -TimeoutSeconds $TimeoutSeconds
		        $raw = [string]$res.output
		        $rc = [int]$res.exit_code
		      } else {
		        $res = Invoke-C2FProcess -FilePath $m -ArgLine $argLine -TimeoutSeconds $TimeoutSeconds
		        $raw = [string]$res.output
		        $rc = [int]$res.exit_code
		        if ($raw -match 'file cannot be accessed by the system') {
		          $res = Invoke-C2FProcess -FilePath $env:ComSpec -ArgLine ("/d /c " + (Quote-C2FCmdArg $m) + " " + $argLine) -TimeoutSeconds $TimeoutSeconds
		          $raw = [string]$res.output
		          $rc = [int]$res.exit_code
		        }
		      }
		      if ($res -and $res.timed_out) {
		        try { C2F-Evidence ("warning=winget_timeout method=" + $m + "|seconds=" + $TimeoutSeconds) } catch { }
		      }
			      $isUsage = (
			        ($raw -match '(?im)^\s*usage:\s*winget\b') -or
			        ($raw -match 'The following commands are available:') -or
			        ($raw -match 'The winget command line utility enables installing applications')
			      )
		      $isHelpCall = $false
		      foreach ($a in $argArray) {
		        $t = ([string]$a).ToLower()
		        if (@('help', '--help', '-?', '/?') -contains $t) { $isHelpCall = $true; break }
		      }
		      # Some environments resolve winget to a shim that only prints usage.
		      # If args were provided and we got generic usage output, try next method.
		      if ($isUsage -and -not $isHelpCall -and $argArray.Count -gt 0) {
		        $lastError = "winget method returned usage output"
		        continue
		      }
		      return @{
		        "method" = $m
		        "output" = [string]$raw
		        "exit_code" = $rc
		      }
		    } catch {
		      $lastError = $_.Exception.Message
		    }
		  }
		  if ($lastError) { throw ("winget unavailable/inaccessible: " + $lastError) }
		  throw "winget unavailable/inaccessible"
		}

			$script:C2FWingetSupportsForce = $null
			function Test-C2FWingetSupportsForce {
			  if ($script:C2FWingetSupportsForce -ne $null) { return [bool]$script:C2FWingetSupportsForce }
		  $txt = ""
		  try {
		    $helpRes = Invoke-C2FWinget -WingetArgs @('install', '--help') -TimeoutSeconds 60
		    $txt = [string]$helpRes.output
		  } catch {
		    $txt = ""
		  }
			  if ($txt -match '(?im)\s--force\b') { $script:C2FWingetSupportsForce = $true } else { $script:C2FWingetSupportsForce = $false }
			  return [bool]$script:C2FWingetSupportsForce
			}

			function Normalize-C2FToken {
			  param([string]$Value)
			  $text = [string]$Value
			  if (-not $text) { return "" }
			  $text = [regex]::Replace($text, '\x1B\[[0-9;]*[A-Za-z]', '')
			  $text = [regex]::Replace($text, '[\x00-\x1F\x7F]', '')
			  return $text.Trim()
			}

			function Test-C2FNoiseLine {
			  param([string]$Line)
			  $line = Normalize-C2FToken $Line
			  if (-not $line) { return $true }
			  if ($line -match '^\d+\s+upgrades?\s+available$') { return $true }
			  if ($line -match 'No installed package found' -or $line -match 'No applicable update found' -or $line -match 'No available upgrade found') { return $true }
			  if ($line -match '^\s*[-\\/\|]+\s*$') { return $true }
			  if ($line -match '\d+(?:\.\d+)?\s*(KB|MB|GB)\s*/\s*\d+(?:\.\d+)?\s*(KB|MB|GB)') { return $true }
			  return $false
			}

			function Test-C2FValidWingetId {
			  param([string]$Value)
			  $id = Normalize-C2FToken $Value
			  if (-not $id) { return $false }
			  if ($id -match '^[\\/\-|]+$') { return $false }
			  if ($id -match '^(?i)(name|id|version|available|source)$') { return $false }
			  if ($id -match '^\d+(?:\.\d+){1,6}$') { return $false }
				  if ($id -match '^(?i)ARP\\[A-Za-z0-9._\-{}]+(\\[A-Za-z0-9._\-{}]+)*$') { return $true }
			  if ($id -match '^[A-Za-z0-9]+([._-][A-Za-z0-9]+)+$') { return $true }
			  return $false
			}

				function Test-C2FValidDisplayName {
				  param([string]$Value)
				  $name = Normalize-C2FToken $Value
				  if (-not $name) { return $false }
				  if ($name -match '^(?i)(name|id|version|available|source)$') { return $false }
				  if ($name -match '^[\\/\-|]+$') { return $false }
				  if ($name -match '\d+(?:\.\d+)?\s*(KB|MB|GB)\s*/\s*\d+(?:\.\d+)?\s*(KB|MB|GB)') { return $false }
				  return ($name.Length -ge 2)
				}

				function Test-C2FValidTargetNeedle {
				  param([string]$Value)
				  $needle = Normalize-C2FToken $Value
				  if (-not $needle) { return $false }
				  if ($needle -match '^(?i)(name|id|version|available|source)$') { return $false }
				  if ($needle -match '^[\\/\-|]+$') { return $false }
				  if ($needle -match '^[A-Za-z]:\\') { return $false }
				  if (($needle -match '\\') -and ($needle -notmatch '^(?i)ARP\\[A-Za-z0-9._\-{}]+(\\[A-Za-z0-9._\-{}]+)*$')) { return $false }
				  if ($needle -match '\d+(?:\.\d+)?\s*(KB|MB|GB)\s*/\s*\d+(?:\.\d+)?\s*(KB|MB|GB)') { return $false }
				  if ($needle.Length -lt 2) { return $false }
				  return $true
				}

			$script:C2FWingetSourcesHealthy = $null
			function Repair-C2FWingetSources {
			  param([switch]$Force)
			  if (($script:C2FWingetSourcesHealthy -eq $true) -and (-not $Force)) { return $true }
			  $ok = $false
			  try {
			    $upd = Invoke-C2FWinget -WingetArgs @('source', 'update', '--disable-interactivity') -TimeoutSeconds 120
			    if ([int]$upd.exit_code -eq 0) {
			      C2F-Evidence "winget_source_update=ok"
			      $ok = $true
			    } else {
			      $msg = ([string]$upd.output -replace '\r?\n', ' ' -replace '\|', '/').Trim()
			      C2F-Evidence ("winget_source_update=rc_" + [string]$upd.exit_code + "|" + $msg)
			    }
			  } catch {
			    $m = ($_.Exception.Message -replace '\r?\n', ' ' -replace '\|', '/').Trim()
			    C2F-Evidence ("winget_source_update=error|" + $m)
			  }
			  if (-not $ok) {
			    try {
			      $rst = Invoke-C2FWinget -WingetArgs @('source', 'reset', '--force', '--disable-interactivity') -TimeoutSeconds 180
			      if ([int]$rst.exit_code -eq 0) {
			        C2F-Evidence "winget_source_reset=ok"
			      } else {
			        $msg2 = ([string]$rst.output -replace '\r?\n', ' ' -replace '\|', '/').Trim()
			        C2F-Evidence ("winget_source_reset=rc_" + [string]$rst.exit_code + "|" + $msg2)
			      }
			    } catch {
			      $m2 = ($_.Exception.Message -replace '\r?\n', ' ' -replace '\|', '/').Trim()
			      C2F-Evidence ("winget_source_reset=error|" + $m2)
			    }
			    try {
			      $upd2 = Invoke-C2FWinget -WingetArgs @('source', 'update', '--disable-interactivity') -TimeoutSeconds 120
			      if ([int]$upd2.exit_code -eq 0) {
			        C2F-Evidence "winget_source_update_after_reset=ok"
			        $ok = $true
			      } else {
			        $msg3 = ([string]$upd2.output -replace '\r?\n', ' ' -replace '\|', '/').Trim()
			        C2F-Evidence ("winget_source_update_after_reset=rc_" + [string]$upd2.exit_code + "|" + $msg3)
			      }
			    } catch {
			      $m3 = ($_.Exception.Message -replace '\r?\n', ' ' -replace '\|', '/').Trim()
			      C2F-Evidence ("winget_source_update_after_reset=error|" + $m3)
			    }
			  }
			  $script:C2FWingetSourcesHealthy = [bool]$ok
			  return [bool]$ok
			}

				function Get-C2FWingetUpgrades {
				  $rows = @()
			  $attempts = @(
			    @('upgrade', '--include-unknown', '--disable-interactivity'),
			    @('upgrade', '--include-unknown'),
			    @('upgrade', '--disable-interactivity'),
			    @('upgrade'),
			    @('list', '--upgrade-available', '--include-unknown', '--disable-interactivity'),
			    @('list', '--upgrade-available', '--include-unknown'),
			    @('list', '--upgrade-available', '--disable-interactivity'),
			    @('list', '--upgrade-available'),
			    @('upgrade', '--include-unknown', '--scope', 'machine'),
			    @('list', '--upgrade-available', '--include-unknown', '--scope', 'machine')
			  )
			  $raw = ""
			  $rc = 1
			  $used = ""
		  $lastErrorText = ""
		  foreach ($a in $attempts) {
		    $used = [string]::Join(" ", $a)
		    try {
		      $res = Invoke-C2FWinget -WingetArgs $a
		      $raw = [string]$res.output
		      $rc = [int]$res.exit_code
		    } catch {
		      $raw = $_.Exception.Message
		      $rc = 1
		    }
			    $isHelp = (
			      ($raw -match '(?im)^\s*usage:\s*winget\b') -or
			      ($raw -match 'The following commands are available:') -or
			      ($raw -match 'The winget command line utility enables installing applications')
			    )
		    $isListLike = (($raw -match '(?im)^Name\s+Id\s+Version\s+Available') -or ($raw -match '(?im)^\d+\s+upgrades?\s+available') -or ($raw -match 'No installed package found') -or ($raw -match 'No applicable update found') -or ($raw -match 'No available upgrade found'))
		    if (-not $isHelp) {
		      try {
		        $previewLines = @($raw -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 6)
		        $preview = [string]::Join(" / ", $previewLines)
		        if ($preview.Length -gt 600) { $preview = $preview.Substring(0, 600) }
		        if ($preview) { C2F-Evidence ("winget_list_preview=" + $used + " :: " + $preview.Replace("|", "/")) }
		      } catch { }
		    }
		    if ($isHelp) {
		      $lastErrorText = "winget returned help/usage"
		      continue
		    }
		    if (($rc -eq 0) -or $isListLike) {
		      break
		    }
		    $lastErrorText = $raw
		  }
		  if (($rc -ne 0) -and ($raw -notmatch 'No installed package found') -and ($raw -notmatch 'No applicable update found') -and ($raw -notmatch 'No available upgrade found')) {
		    throw ("winget upgrade list failed (" + $rc + ") via [" + $used + "]: " + ($lastErrorText -or $raw))
		  }
			  $parsedAny = $false
			  foreach ($lineRaw in ($raw -split "`r?`n")) {
		    $line = Normalize-C2FToken $lineRaw
		    if (-not $line) { continue }
		    if ($line -match '^Name\s+Id\s+Version\s+Available(?:\s+Source)?$') { continue }
		    if ($line -match '^-{3,}$') { continue }
		    if (Test-C2FNoiseLine $line) { continue }
		    $parts = ($line -replace '\s{2,}', '|').Split('|')
		    if ($parts.Count -lt 4) {
		      $m = [regex]::Match($line, '^(?<name>.+?)\s{2,}(?<id>\S+)\s{2,}(?<installed>\S+)\s{2,}(?<available>\S+)(?:\s{2,}(?<source>\S+))?$')
		      if (-not $m.Success) { continue }
		      $name = Normalize-C2FToken $m.Groups['name'].Value
		      $id = Normalize-C2FToken $m.Groups['id'].Value
		      $installed = Normalize-C2FToken $m.Groups['installed'].Value
		      $available = Normalize-C2FToken $m.Groups['available'].Value
		      $source = Normalize-C2FToken $m.Groups['source'].Value
		    } else {
		      $name = Normalize-C2FToken $parts[0]
		      $id = Normalize-C2FToken $parts[1]
		      $installed = Normalize-C2FToken $parts[2]
		      $available = Normalize-C2FToken $parts[3]
		      $source = ""
		      if ($parts.Count -ge 5) { $source = Normalize-C2FToken $parts[4] }
		    }
		    if (-not (Test-C2FValidWingetId $id)) { $id = "" }
		    if (-not (Test-C2FValidDisplayName $name)) { $name = "" }
		    if (-not $installed -or $installed -match '^[\\/\-|]+$') { continue }
		    if (-not $available -or $available -match '^[\\/\-|]+$') { continue }
		    $key = if ($id) { $id } else { $name }
		    if (-not $key) { continue }
		    $rows += @{
	      "key" = $key
	      "name" = $name
	      "id" = $id
	      "installed" = $installed
	      "available" = $available
	      "source" = $source
	    }
	    $parsedAny = $true
	  }
				  if (-not $parsedAny) {
					    if ($raw -match '(?im)^\s*usage:\s*winget\b' -or $raw -match 'The following commands are available:' -or $raw -match 'The winget command line utility enables installing applications') {
				      C2F-Evidence "warning=winget_list_usage_output"
				    } elseif ($raw -match 'Name\s+Id\s+Version\s+Available') {
				      C2F-Evidence "warning=winget_list_parse_zero_rows"
				    }
				  }
				  return $rows
				}

				function Get-C2FWingetInstalledRows {
				  param([string]$PackageId)
				  $rows = @()
				  if (-not $PackageId) { return $rows }
				  $attempts = @(
				    @('list', '--id', $PackageId, '--exact', '--disable-interactivity'),
				    @('list', '--id', $PackageId, '--exact'),
				    @('list', '--name', $PackageId, '--exact', '--disable-interactivity'),
				    @('list', '--name', $PackageId, '--exact'),
				    @('list', $PackageId, '--disable-interactivity'),
				    @('list', $PackageId),
				    @('list', '--id', $PackageId, '--exact', '--scope', 'machine'),
				    @('list', '--name', $PackageId, '--exact', '--scope', 'machine'),
				    @('list', $PackageId, '--scope', 'machine')
				  )
				  $raw = ""
				  $rc = 1
					  foreach ($a in $attempts) {
					    try {
					      $res = Invoke-C2FWinget -WingetArgs $a -TimeoutSeconds 25
					      $raw = [string]$res.output
					      $rc = [int]$res.exit_code
				    } catch {
				      $raw = $_.Exception.Message
				      $rc = 1
				    }
					    if ($raw -match 'No installed package found' -or $raw -match 'No package found matching input criteria') {
					      continue
					    }
					    if ($raw -match '(?im)^Name\s+Id\s+Version') { break }
					  }
					  foreach ($lineRaw in ($raw -split "`r?`n")) {
					    $line = Normalize-C2FToken $lineRaw
					    if (-not $line) { continue }
					    if ($line -match '^Name\s+Id\s+Version') { continue }
					    if ($line -match '^-{3,}$') { continue }
					    if (Test-C2FNoiseLine $line -or $line -match 'No package found matching input criteria') { continue }
					    $parts = ($line -replace '\s{2,}', '|').Split('|')
					    if ($parts.Count -lt 3) {
					      $m = [regex]::Match($line, '^(?<name>.+?)\s+(?<id>(?:ARP\\[^\s]+|[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)+))\s+(?<version>\S+)(?:\s+(?<source>\S+))?$')
					      if (-not $m.Success) {
					        $m = [regex]::Match($line, '^(?<name>.+?)\s{2,}(?<id>\S+)\s{2,}(?<version>\S+)(?:\s{2,}(?<source>\S+))?$')
					      }
					      if (-not $m.Success) { continue }
					      $name = Normalize-C2FToken $m.Groups['name'].Value
					      $id = Normalize-C2FToken $m.Groups['id'].Value
					      $version = Normalize-C2FToken $m.Groups['version'].Value
					      $source = Normalize-C2FToken $m.Groups['source'].Value
					    } else {
					      $name = Normalize-C2FToken $parts[0]
					      $id = Normalize-C2FToken $parts[1]
					      $version = Normalize-C2FToken $parts[2]
					      $source = ''
					      if ($parts.Count -ge 4) { $source = Normalize-C2FToken $parts[3] }
					    }
					    if (-not (Test-C2FValidWingetId $id)) { continue }
					    if (-not (Test-C2FValidDisplayName $name)) { $name = $id }
					    if (-not $version -or $version -match '^[\\/\-|]+$') { continue }
					    $rows += @{
					      "name" = $name
					      "id" = $id
					      "version" = $version
				      "source" = $source
				    }
				  }
				  return $rows
				}

					function Test-C2FWingetPendingUpgrade {
					  param([string]$PackageId)
					  if (-not $PackageId) { return $null }
					  $needle = [string]$PackageId
					  $needleLower = $needle.ToLower()
					  try {
					    $rows = Get-C2FWingetUpgrades
					  } catch {
					    return $null
					  }
					  if (-not $rows -or $rows.Count -eq 0) { return $false }
					  foreach ($row in $rows) {
					    $rid = [string]$row.id
					    $rkey = [string]$row.key
					    $rname = [string]$row.name
					    if (($rid -and $rid.ToLower() -eq $needleLower) -or ($rkey -and $rkey.ToLower() -eq $needleLower)) {
					      return $true
					    }
					    if (($rid -and $rid.ToLower().Contains($needleLower)) -or ($rkey -and $rkey.ToLower().Contains($needleLower)) -or ($rname -and $rname.ToLower().Contains($needleLower))) {
					      return $true
					    }
					  }
					  return $false
					}
						function Resolve-C2FWingetTarget {
					  param([string]$InputSpec, [object[]]$Catalog)
				  $needle = [string]$InputSpec
				  if (-not $needle) { return $null }
				  $needle = $needle.Trim()
				  if (-not $needle) { return $null }
				  $needleLower = $needle.ToLower()
				  if ($needle -match '^[A-Za-z0-9]+([._-][A-Za-z0-9]+)+$' -and $needle -notmatch '\s') {
				    return @{
				      "key" = $needle
				      "name" = $needle
				      "id" = $needle
				      "installed" = ""
				      "available" = ""
				      "source" = ""
					  }
					}
				  if (-not $Catalog) { $Catalog = @() }
				  foreach ($row in $Catalog) {
			    $id = [string]$row.id
			    $key = [string]$row.key
			    $name = [string]$row.name
			    if ($id.ToLower() -eq $needleLower -or $key.ToLower() -eq $needleLower -or $name.ToLower() -eq $needleLower) {
			      return $row
			    }
			  }
			  foreach ($row in $Catalog) {
			    $id = [string]$row.id
			    $key = [string]$row.key
			    $name = [string]$row.name
			    if (($id -and $id.ToLower().Contains($needleLower)) -or ($key -and $key.ToLower().Contains($needleLower)) -or ($name -and $name.ToLower().Contains($needleLower))) {
			      return $row
			    }
			  }
			  return @{
			    "key" = $needle
			    "name" = $needle
			    "id" = $needle
			    "installed" = ""
			    "available" = ""
			    "source" = ""
				  }
				}

				function Resolve-C2FWingetCandidate {
				  param([string]$Needle)
				  $needleText = [string]$Needle
				  if (-not $needleText) { return $null }
				  $needleText = $needleText.Trim()
				  if (-not $needleText) { return $null }
				  $attempts = @(
				    @('search', '--id', $needleText, '--exact', '--source', 'winget'),
				    @('search', '--name', $needleText, '--exact', '--source', 'winget'),
				    @('search', $needleText, '--source', 'winget')
				  )
				  foreach ($a in $attempts) {
				    $raw = ""
				    try {
				      $res = Invoke-C2FWinget -WingetArgs $a -TimeoutSeconds 45
				      $raw = [string]$res.output
				    } catch {
				      continue
				    }
				    if (-not $raw) { continue }
				    if ($raw -match 'No package found matching input criteria' -or $raw -match 'No package found with this query') { continue }
					    foreach ($lineRaw in ($raw -split "`r?`n")) {
					      $line = Normalize-C2FToken $lineRaw
					      if (-not $line) { continue }
					      if ($line -match '^Name\s+Id\s+Version') { continue }
					      if ($line -match '^-{3,}$') { continue }
					      if ($line -match '^Found\s') { continue }
					      if (Test-C2FNoiseLine $line) { continue }
					      $parts = ($line -replace '\s{2,}', '|').Split('|')
					      if ($parts.Count -lt 2) { continue }
					      $name = Normalize-C2FToken $parts[0]
					      $id = Normalize-C2FToken $parts[1]
					      if (-not (Test-C2FValidWingetId $id)) { continue }
					      if (-not (Test-C2FValidDisplayName $name)) { $name = $id }
					      return @{
					        "name" = $name
					        "id" = $id
				      }
				    }
				  }
				  return $null
				}

				function Get-C2FServiceDisplayName {
				  param([string]$ServiceName)
				  $name = Normalize-C2FToken $ServiceName
				  if (-not $name) { return "" }
				  try {
				    $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $name.Replace("'", "''") + "'") -ErrorAction SilentlyContinue | Select-Object -First 1
				    if ($svc -and $svc.DisplayName) {
				      $disp = Normalize-C2FToken $svc.DisplayName
				      if ($disp) { return $disp }
				    }
				  } catch { }
				  try {
				    $svc2 = Get-Service -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
				    if ($svc2 -and $svc2.DisplayName) {
				      $disp2 = Normalize-C2FToken $svc2.DisplayName
				      if ($disp2) { return $disp2 }
				    }
				  } catch { }
				  return ""
				}

				function Add-C2FNeedle {
				  param(
				    [System.Collections.Generic.List[string]]$List,
				    [string]$Value
				  )
				  if (-not $List) { return }
				  $v = Normalize-C2FToken $Value
				  if (-not $v) { return }
				  if ($v -match '^[\\/\-|]+$') { return }
				  if ($v.Length -lt 2) { return }
				  if (-not $List.Contains($v)) { [void]$List.Add($v) }
				}

				function Get-C2FAlternateNeedles {
				  param(
				    [string]$Primary,
				    [string]$ResolvedName,
				    [string]$OriginalInput
				  )
				  $out = New-Object 'System.Collections.Generic.List[string]'
				  Add-C2FNeedle -List $out -Value $Primary
				  Add-C2FNeedle -List $out -Value $ResolvedName
				  Add-C2FNeedle -List $out -Value $OriginalInput

				  $primaryNorm = Normalize-C2FToken $Primary
				  if ($primaryNorm -and ($primaryNorm -match '^[A-Za-z0-9._-]+$') -and ($primaryNorm -notmatch '\s')) {
				    $serviceLike = ($primaryNorm -match '(?i)(svc|service)$' -or $primaryNorm -match '^[A-Za-z]{3,}[A-Z][A-Za-z0-9]+$')
				    if ($serviceLike) {
				      $displayName = Get-C2FServiceDisplayName -ServiceName $primaryNorm
				      if ($displayName) {
				        Add-C2FNeedle -List $out -Value $displayName
				      }
					    if ($primaryNorm -match '(?i)^mfe') {
					      Add-C2FNeedle -List $out -Value 'McAfee'
					      Add-C2FNeedle -List $out -Value 'McAfee Endpoint Security'
					      Add-C2FNeedle -List $out -Value 'WebAdvisor by McAfee'
					      Add-C2FNeedle -List $out -Value 'McAfee WebAdvisor'
					      Add-C2FNeedle -List $out -Value 'WebAdvisor'
					    }
					  }
					  if ($primaryNorm -match '(?i)svc$') {
					    Add-C2FNeedle -List $out -Value ($primaryNorm -replace '(?i)svc$', '')
					  }
				  }
					  return @($out.ToArray())
					}

						function Resolve-C2FInstalledOrSearchCandidate {
						  param([string]$Needle)
						  $n = Normalize-C2FToken $Needle
						  if (-not $n) { return $null }
				  try {
				    $searchHit = Resolve-C2FWingetCandidate -Needle $n
				    if ($searchHit -and (Test-C2FValidWingetId ([string]$searchHit.id))) {
				      $nm = Normalize-C2FToken ([string]$searchHit.name)
				      if (-not (Test-C2FValidDisplayName $nm)) { $nm = [string]$searchHit.id }
				      return @{
				        "id" = [string]$searchHit.id
				        "name" = $nm
				        "source" = "search"
				      }
				    }
				  } catch { }
				  $arpHit = $null
				  try { $arpHit = Resolve-C2FArpCandidateFromNeedle -Needle $n } catch { $arpHit = $null }
				  if ($arpHit -and (Test-C2FValidWingetId ([string]$arpHit.id))) {
				    return $arpHit
				  }
				  $rows = @()
				  try { $rows = Get-C2FWingetInstalledRows -PackageId $n } catch { $rows = @() }
				  if ($rows -and $rows.Count -gt 0) {
				    $installedHit = $rows | Where-Object { Test-C2FValidWingetId ([string]$_.id) } | Select-Object -First 1
				    if ($installedHit) {
				      $hitName = Normalize-C2FToken ([string]$installedHit.name)
				      if (-not (Test-C2FValidDisplayName $hitName)) { $hitName = [string]$installedHit.id }
				      return @{
				        "id" = [string]$installedHit.id
				        "name" = $hitName
				        "source" = "installed"
				      }
				    }
				  }
					  return $null
					}

					function Get-C2FArpRegistryPaths {
					  param(
					    [string]$LookupId,
					    [string]$DisplayName = ""
					  )
					  $pkg = Normalize-C2FToken $LookupId
					  $paths = @()
					  if ($pkg -and $pkg -match '^(?i)ARP\\') {
					    $parts = $pkg -split '\\'
					    if ($parts -and $parts.Count -ge 2) {
					      $token = Normalize-C2FToken ($parts[$parts.Count - 1])
					      if ($token) {
					        $paths += @(
					          ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + $token),
					          ("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + $token),
					          ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + $token)
					        )
					      }
					    }
					  }
					  $dispNeedle = Normalize-C2FToken $DisplayName
					  if ($dispNeedle) {
					    $roots = @(
					      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
					      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
					      'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
					    )
					    foreach ($root in $roots) {
					      try {
					        $keys = Get-ChildItem -Path $root -ErrorAction SilentlyContinue
					        foreach ($k in $keys) {
					          $dname = ""
					          try { $dname = Normalize-C2FToken ([string](Get-ItemProperty -LiteralPath $k.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName) } catch { $dname = "" }
					          if ($dname -and $dname.ToLower().Contains($dispNeedle.ToLower())) {
					            $paths += [string]$k.PSPath
					          }
					        }
					      } catch { }
					    }
					  }
					  return @($paths | Where-Object { $_ } | Select-Object -Unique)
					}

					function Resolve-C2FArpCandidateFromNeedle {
					  param([string]$Needle)
					  $n = Normalize-C2FToken $Needle
					  if (-not $n) { return $null }
					  $paths = @(Get-C2FArpRegistryPaths -LookupId "" -DisplayName $n)
					  foreach ($rp in $paths) {
					    try {
					      if (-not (Test-Path -LiteralPath $rp)) { continue }
					      $item = Get-Item -LiteralPath $rp -ErrorAction SilentlyContinue
					      if (-not $item) { continue }
					      $leaf = Normalize-C2FToken ([string]$item.PSChildName)
					      if (-not $leaf) { continue }
					      if ($leaf -match '[\\/]') { continue }
					      $candidateId = "ARP\" + $leaf
					      if (-not (Test-C2FValidWingetId $candidateId)) { continue }
					      $props = Get-ItemProperty -LiteralPath $rp -ErrorAction SilentlyContinue
					      $dname = ""
					      try { $dname = Normalize-C2FToken ([string]$props.DisplayName) } catch { $dname = "" }
					      if (-not (Test-C2FValidDisplayName $dname)) { $dname = $leaf }
					      return @{
					        "id" = $candidateId
					        "name" = $dname
					        "source" = "arp_display"
					      }
					    } catch {
					      continue
					    }
					  }
					  return $null
					}

					function Test-C2FArpEntryPresent {
					  param(
					    [string]$LookupId,
					    [string]$DisplayName = ""
					  )
					  $paths = @(Get-C2FArpRegistryPaths -LookupId $LookupId -DisplayName $DisplayName)
					  foreach ($p in $paths) {
					    try { if (Test-Path -LiteralPath $p) { return $true } } catch { }
					  }
					  return $false
					}

					function Get-C2FArpUninstallMeta {
					  param(
					    [string]$LookupId,
					    [string]$DisplayName = ""
					  )
					  $paths = @(Get-C2FArpRegistryPaths -LookupId $LookupId -DisplayName $DisplayName)
					  foreach ($p in $paths) {
					    try {
					      if (-not (Test-Path -LiteralPath $p)) { continue }
					      $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
					      if (-not $props) { continue }
					      $quiet = Normalize-C2FToken ([string]$props.QuietUninstallString)
					      $uninstall = Normalize-C2FToken ([string]$props.UninstallString)
					      $cmd = $quiet
					      if (-not $cmd) { $cmd = $uninstall }
					      if (-not $cmd) { continue }
					      $isExe = ($cmd -match '(?i)\.exe')
					      $hasSilent = ($cmd -match '(?i)(/quiet|/qn|/silent|/verysilent|--silent)')
					      return @{
					        "found" = $true
					        "path" = [string]$p
					        "command" = [string]$cmd
					        "interactive_only" = [bool]($isExe -and (-not $hasSilent) -and (-not $quiet))
					      }
					    } catch {
					      continue
					    }
					  }
					  return @{
					    "found" = $false
					    "path" = ""
					    "command" = ""
					    "interactive_only" = $false
					  }
					}

					function Invoke-C2FArpRemovalFallback {
					  param(
					    [string]$LookupId,
					    [string]$DisplayName,
					    [int]$TimeoutSeconds = 240
					  )
					  $pkg = Normalize-C2FToken $LookupId
					  if (-not $pkg) {
					    return @{
					      "ok" = $false
					      "method" = "none"
					      "message" = "lookup_id_empty"
					    }
					  }
					  if ($pkg -notmatch '^(?i)ARP\\') {
					    return @{
					      "ok" = $false
					      "method" = "none"
					      "message" = "not_arp_identifier"
					    }
					  }

					  # Path 1: product-code uninstall via msiexec when ARP token contains a GUID.
					  $msiNotInstalled = $false
					  $guidMatch = [regex]::Match($pkg, '\{[0-9A-Fa-f\-]{32,40}\}')
					  if ($guidMatch.Success) {
					    $productCode = [string]$guidMatch.Value
					    $args = "/x " + $productCode + " /qn /norestart"
					    try {
					      $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -PassThru -WindowStyle Hidden
					      if ($proc) {
					        $waitOk = $true
					        try {
					          Wait-Process -Id $proc.Id -Timeout ([Math]::Max(30, [int]$TimeoutSeconds)) -ErrorAction Stop
					        } catch {
					          $waitOk = $false
					        }
					        if (-not $waitOk) {
					          try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
					        } else {
					          $rc = 1
					          try { $rc = [int]$proc.ExitCode } catch { $rc = 1 }
					          if ($rc -eq 0 -or $rc -eq 3010 -or $rc -eq 1641) {
					            return @{
					              "ok" = $true
					              "method" = "msiexec_guid"
					              "message" = ("rc=" + $rc)
					            }
					          }
					          if ($rc -eq 1605) {
					            $msiNotInstalled = $true
					          }
					        }
					      }
					    } catch { }
					  }

					  # Path 2: run ARP QuietUninstallString/UninstallString directly.
					  $paths = @(Get-C2FArpRegistryPaths -LookupId $pkg -DisplayName $DisplayName)
					  foreach ($rp in $paths) {
					    try {
					      if (-not (Test-Path -LiteralPath $rp)) { continue }
					      $props = Get-ItemProperty -LiteralPath $rp -ErrorAction SilentlyContinue
					      if (-not $props) { continue }
					      $cmd = Normalize-C2FToken ([string]$props.QuietUninstallString)
					      if (-not $cmd) { $cmd = Normalize-C2FToken ([string]$props.UninstallString) }
					      if (-not $cmd) { continue }
					      $exePath = ""
					      $baseArgs = ""
					      if ($cmd -match '^\s*"(?<exe>[^"]+)"\s*(?<rest>.*)$') {
					        $exePath = Normalize-C2FToken ([string]$Matches['exe'])
					        $baseArgs = Normalize-C2FToken ([string]$Matches['rest'])
					      } elseif ($cmd -match '^\s*(?<exe>[A-Za-z]:\\.+?\.exe)\s*(?<rest>.*)$') {
					        $exePath = Normalize-C2FToken ([string]$Matches['exe'])
					        $baseArgs = Normalize-C2FToken ([string]$Matches['rest'])
					      }
					      if (-not $exePath) {
					        # Fallback: leave shell parsing to cmd when command shape is unknown.
					        $exePath = $env:ComSpec
					        $baseArgs = ("/d /c " + $cmd)
					      } elseif ($exePath -match '(?i)\bmsiexec(\.exe)?$') {
					        if ($baseArgs -match '(?i)\s/I\s*\{') {
					          $baseArgs = [regex]::Replace($baseArgs, '(?i)\s/I(\s*\{)', ' /X$1')
					        }
					        if ($baseArgs -notmatch '(?i)\s/qn\b' -and $baseArgs -notmatch '(?i)\s/quiet\b') {
					          $baseArgs = ($baseArgs + " /qn").Trim()
					        }
					        if ($baseArgs -notmatch '(?i)\s/norestart\b') {
					          $baseArgs = ($baseArgs + " /norestart").Trim()
					        }
					      }

					      if ($exePath -ne $env:ComSpec -and $exePath -match '(?i)\.exe$' -and (-not $baseArgs)) {
					        return @{
					          "ok" = $false
					          "method" = "arp_uninstall_string"
					          "message" = "interactive_uninstaller_no_silent_flags"
					        }
					      }
					      $runArgs = Normalize-C2FToken ([string]$baseArgs)
					      $proc2 = $null
					      if ($runArgs) {
					        $proc2 = Start-Process -FilePath $exePath -ArgumentList $runArgs -PassThru -WindowStyle Hidden
					      } else {
					        $proc2 = Start-Process -FilePath $exePath -PassThru -WindowStyle Hidden
					      }
					      if (-not $proc2) {
					        return @{
					          "ok" = $false
					          "method" = "arp_uninstall_string"
					          "message" = "start_failed"
					        }
					      }
					      $waitOk2 = $true
					      try {
					        Wait-Process -Id $proc2.Id -Timeout ([Math]::Max(20, [int]$TimeoutSeconds)) -ErrorAction Stop
					      } catch {
					        $waitOk2 = $false
					      }
					      if (-not $waitOk2) {
					        try { Stop-Process -Id $proc2.Id -Force -ErrorAction SilentlyContinue } catch { }
					        return @{
					          "ok" = $false
					          "method" = "arp_uninstall_string"
					          "message" = "timeout"
					        }
					      }
					      $rc2 = 1
					      try { $rc2 = [int]$proc2.ExitCode } catch { $rc2 = 1 }
					      if ($rc2 -eq 0 -or $rc2 -eq 1605 -or $rc2 -eq 3010 -or $rc2 -eq 1641) {
					        return @{
					          "ok" = $true
					          "method" = "arp_uninstall_string"
					          "message" = ("rc=" + $rc2 + "|args=" + $runArgs)
					        }
					      }
					      return @{
					        "ok" = $false
					        "method" = "arp_uninstall_string"
					        "message" = ("rc=" + $rc2)
					      }
					    } catch {
					      continue
					    }
					  }

					  if ($msiNotInstalled -and (-not (Test-C2FArpEntryPresent -LookupId $pkg -DisplayName $DisplayName))) {
					    return @{
					      "ok" = $true
					      "method" = "msiexec_guid"
					      "message" = "rc=1605"
					    }
					  }
					  return @{
					    "ok" = $false
					    "method" = "arp_uninstall_fallback"
					    "message" = "no_fallback_path"
					  }
					}

			try {
			  C2F-Status "START"
			  C2F-Evidence "package_manager=winget"

		  $targets = @()
		  $meta = @{}
		  $requested = @()
			  foreach ($p in ($PackageSpec -split '[,;\r\n]+')) {
			    $x = $p.Trim()
			    if ($x) { $requested += $x }
			  }
			  $allMode = ($requested.Count -eq 0 -or ($requested.Count -eq 1 -and (@('all', '*') -contains $requested[0].ToLower())))

			  # Execution control flags (best-effort): allow pause/resume/cancel for long runs.
			  $controlDir = "C:\Click2Fix\control"
			  try { New-Item -ItemType Directory -Path $controlDir -Force | Out-Null } catch { }
			  $pauseFlag = Join-Path $controlDir ("pause-" + $ExecId + ".flag")
			  $cancelFlag = Join-Path $controlDir ("cancel-" + $ExecId + ".flag")
			  $scriptStarted = Get-Date
			  $maxRuntime = [Math]::Max(120, [int]$MaxRuntimeSeconds)
			  $deadline = $scriptStarted.AddSeconds($maxRuntime)

			  function Assert-C2FWithinBudget {
			    if ((Get-Date) -ge $deadline) {
			      $elapsed = [int]((Get-Date) - $scriptStarted).TotalSeconds
			      throw ("package-update timed out after " + [string]$elapsed + "s")
			    }
			  }

			  function Assert-C2FNotCancelled {
			    if (Test-Path $cancelFlag) {
			      try { C2F-Evidence "control=cancel_requested" } catch { }
			      throw "Execution cancelled by operator"
			    }
			  }

			  function Wait-C2FPause {
			    Assert-C2FWithinBudget
			    if (-not (Test-Path $pauseFlag)) { return }
			    try { C2F-Evidence "control=pause_requested" } catch { }
			    while (Test-Path $pauseFlag) {
			      Assert-C2FWithinBudget
			      Assert-C2FNotCancelled
			      Start-Sleep -Seconds 2
			    }
			    try { C2F-Evidence "control=pause_released" } catch { }
			  }

			  $wingetReady = $true
			  $wingetError = ""
			  try {
			    $probe = Invoke-C2FWinget -WingetArgs @('--version') -TimeoutSeconds 30
			    if ([int]$probe.exit_code -ne 0) {
			      $wingetReady = $false
			      $wingetError = [string]$probe.output
			    }
			  } catch {
		    $wingetReady = $false
		    $wingetError = $_.Exception.Message
		  }

		  if (-not $wingetReady) {
		    # Try a one-time App Installer registration for the current user (c2fsvc) in case
		    # winget exists on the machine but is not registered in this user context.
		    try {
		      $appInstaller = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
		      if (-not $appInstaller) {
		        $appInstaller = Get-AppxPackage -AllUsers -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
		      }
		      if ($appInstaller -and $appInstaller.InstallLocation) {
		        $manifest = Join-Path $appInstaller.InstallLocation "AppxManifest.xml"
		        if (Test-Path $manifest) {
			          Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction Stop | Out-Null
			          Start-Sleep -Seconds 2
			          $probe2 = Invoke-C2FWinget -WingetArgs @('--version') -TimeoutSeconds 30
			          if ([int]$probe2.exit_code -eq 0) {
			            $wingetReady = $true
			            $wingetError = ""
			            C2F-Evidence "winget_bootstrap=desktopappinstaller_registered"
		          } else {
		            $wingetError = [string]$probe2.output
		          }
		        }
		      }
		    } catch {
		      C2F-Evidence ("winget_bootstrap_error=" + $_.Exception.Message)
		    }
		  }

			  if (-not $wingetReady) {
			    $wu = whoami
			    throw ("winget unavailable/inaccessible for account " + $wu + ": " + $wingetError + ". Use endpoint credentials for a user profile where winget is installed (or run windows-os-update for OS vulnerabilities).")
			  }
			  try { [void](Repair-C2FWingetSources) } catch { }

			  $installed = 0
			  $failed = 0
		  $remaining = 0
		  $skipped = 0
		  $unresolved = 0
		  $noChangeHits = 0
		  $idx = 0

			  if ($allMode) {
			    $allRows = Get-C2FWingetUpgrades
			    foreach ($row in $allRows) {
			      $key = [string]$row.key
			      if (-not $key) { continue }
			      if (-not ($targets -contains $key)) { $targets += $key }
			      $meta[$key] = $row
			    }
			  } else {
			    # For explicit targets, avoid global catalog enumeration.
			    # It adds latency and can ingest noisy spinner/progress rows.
			    $catalog = @()
					    foreach ($p in $requested) {
				      $resolved = Resolve-C2FWingetTarget -InputSpec $p -Catalog $catalog
				      if (-not $resolved) { continue }
				      $key = Normalize-C2FToken ([string]$resolved.key)
				      if (-not $key) { $key = Normalize-C2FToken ([string]$p) }
				      $resolvedName = Normalize-C2FToken ([string]$resolved.name)
				      if (-not $resolvedName) { $resolvedName = Normalize-C2FToken ([string]$p) }

				      # Try to resolve to a concrete winget id from the catalog/search results.
				      try {
				        $candidate = Resolve-C2FWingetCandidate -Needle $key
				        if ($candidate -and $candidate.id) {
			          $cid = [string]$candidate.id
			          if ($cid) {
			            if ($cid -ne $key) {
			              C2F-Evidence ("package_target_map=" + $key + "->" + $cid)
			            }
			            $key = $cid
			            if ($candidate.name) {
			              $resolvedName = [string]$candidate.name
			            }
			          }
				        }
				      } catch { }
				      if (-not (Test-C2FValidTargetNeedle $key)) {
				        $skipped++
				        $unresolved++
				        C2F-Evidence ("skipped_update_" + $idx + "=" + [string]$p + "|" + $resolvedName + "|reason=invalid_target_identifier")
				        if ($key -and $key -ne $p) {
				          C2F-Evidence ("package_target_map=" + $p + "->" + $key)
				        }
				        $idx++
				        continue
				      }
				      $targetBlob = (([string]$key) + " " + ([string]$resolvedName) + " " + ([string]$p)).ToLowerInvariant()
				      if ($targetBlob -like "*microsoft windows*" -or $targetBlob -match '\bwindows\s+(10|11)\b') {
				        $skipped++
				        $unresolved++
				        C2F-Evidence ("skipped_update_" + $idx + "=" + [string]$p + "|" + $resolvedName + "|reason=windows_os_requires_windows_os_update")
				        $idx++
				        continue
				      }
				      
						      # Pre-flight intelligence: search for exact package first.
						      # If no match, try installed inventory fallback, then mark unresolved early.
					      $preflight = ""
				      $preflightNoMatch = $false
				      try {
				        $preflightRes = Invoke-C2FWinget -WingetArgs @('search', '--exact', $key, '--source', 'winget') -TimeoutSeconds 30
				        $preflight = [string]$preflightRes.output
				      } catch { }
				      
				      if ($preflight -match 'No package found with this query' -or $preflight -match 'No package found matching input criteria') {
				        $preflightNoMatch = $true
				        C2F-Evidence ("preflight_" + $idx + "=" + $key + "|NO_MATCH|search_exact")
				      }
				      
						      if ($preflightNoMatch) {
						        # Some installed apps (notably ARP entries) are not present in winget search.
						        # Try direct installed/search discovery with alternate needles before declaring unmapped.
						        $mapped = $null
						        try { $mapped = Resolve-C2FArpCandidateFromNeedle -Needle $key } catch { $mapped = $null }
						        if ($mapped -and (Test-C2FValidWingetId ([string]$mapped.id))) {
						          C2F-Evidence ("package_target_map_arp=" + $key + "|" + $key + "->" + [string]$mapped.id + "|source=" + [string]$mapped.source)
						        }
						        if (-not $mapped) {
						          try { $mapped = Resolve-C2FInstalledOrSearchCandidate -Needle $key } catch { $mapped = $null }
						        }
						        if (-not $mapped) {
						          $altSet = New-Object 'System.Collections.Generic.List[string]'
						          Add-C2FNeedle -List $altSet -Value $key
						          Add-C2FNeedle -List $altSet -Value $resolvedName
						          Add-C2FNeedle -List $altSet -Value $p
						          $svcDisplay = ""
						          try { $svcDisplay = Get-C2FServiceDisplayName -ServiceName $key } catch { $svcDisplay = "" }
						          if ($svcDisplay) { Add-C2FNeedle -List $altSet -Value $svcDisplay }
						          if ($key -match '(?i)^mfe') {
						            Add-C2FNeedle -List $altSet -Value 'McAfee'
						            Add-C2FNeedle -List $altSet -Value 'McAfee Endpoint Security'
						            Add-C2FNeedle -List $altSet -Value 'WebAdvisor by McAfee'
						            Add-C2FNeedle -List $altSet -Value 'McAfee WebAdvisor'
						            Add-C2FNeedle -List $altSet -Value 'WebAdvisor'
						          }
						          if ($key -match '(?i)svc$') {
						            Add-C2FNeedle -List $altSet -Value ($key -replace '(?i)svc$', '')
						          }
						          $altNeedles = @($altSet.ToArray())
						          C2F-Evidence ("preflight_alias_count_" + $idx + "=" + [string]$altNeedles.Count)
						          foreach ($needle in $altNeedles) {
						            $needleNorm = Normalize-C2FToken $needle
						            if (-not $needleNorm) { continue }
						            if ($needleNorm.ToLower() -eq ([string]$key).ToLower()) { continue }
						            $arpPathCount = 0
						            try { $arpPathCount = @((Get-C2FArpRegistryPaths -LookupId "" -DisplayName $needleNorm)).Count } catch { $arpPathCount = 0 }
						            if ($arpPathCount -gt 0) {
						              C2F-Evidence ("preflight_arp_match_" + $idx + "=" + $needleNorm + "|count=" + [string]$arpPathCount)
						            }
						            $arpCand = $null
						            try { $arpCand = Resolve-C2FArpCandidateFromNeedle -Needle $needleNorm } catch { $arpCand = $null }
						            if ($arpCand -and (Test-C2FValidWingetId ([string]$arpCand.id))) {
						              $mapped = $arpCand
						              C2F-Evidence ("package_target_map_arp=" + $key + "|" + $needleNorm + "->" + [string]$arpCand.id + "|source=" + [string]$arpCand.source)
						              break
						            }
						            $cand = $null
						            try { $cand = Resolve-C2FInstalledOrSearchCandidate -Needle $needleNorm } catch { $cand = $null }
						            if ($cand -and (Test-C2FValidWingetId ([string]$cand.id))) {
						              $mapped = $cand
						              C2F-Evidence ("package_target_map_alias=" + $key + "|" + $needleNorm + "->" + [string]$cand.id + "|source=" + [string]$cand.source)
					              break
					            }
					          }
					        }
					        if ($mapped -and (Test-C2FValidWingetId ([string]$mapped.id))) {
					          $mappedId = [string]$mapped.id
					          $key = $mappedId
					          $preflightNoMatch = $false
					          if ($mapped.name) {
					            $resolvedName = [string]$mapped.name
					          }
					        }
					      }
						      if ($preflightNoMatch) {
						        # Source repair helps only for true winget IDs; skip for service/app aliases.
						        $isLikelyWingetId = ($key -match '^[A-Za-z0-9]+([._-][A-Za-z0-9]+)+$' -and $key -notmatch '\s')
						        if ($isLikelyWingetId) {
						          $repaired = $false
						          try { $repaired = Repair-C2FWingetSources -Force } catch { $repaired = $false }
						          if ($repaired) {
						            C2F-Evidence ("preflight_repair_" + $idx + "=" + $key + "|source_refresh_ok")
						            $mappedAfterRepair = $null
						            try { $mappedAfterRepair = Resolve-C2FInstalledOrSearchCandidate -Needle $key } catch { $mappedAfterRepair = $null }
						            if (-not $mappedAfterRepair) {
						              $altNeedles2 = @(Get-C2FAlternateNeedles -Primary $key -ResolvedName $resolvedName -OriginalInput $p)
						              foreach ($needle2 in $altNeedles2) {
						                $needleNorm2 = Normalize-C2FToken $needle2
						                if (-not $needleNorm2) { continue }
						                if ($needleNorm2.ToLower() -eq ([string]$key).ToLower()) { continue }
						                $cand2 = $null
						                try { $cand2 = Resolve-C2FInstalledOrSearchCandidate -Needle $needleNorm2 } catch { $cand2 = $null }
						                if ($cand2 -and (Test-C2FValidWingetId ([string]$cand2.id))) {
						                  $mappedAfterRepair = $cand2
						                  C2F-Evidence ("package_target_map_alias_after_repair=" + $key + "|" + $needleNorm2 + "->" + [string]$cand2.id + "|source=" + [string]$cand2.source)
						                  break
						                }
						              }
						            }
						            if ($mappedAfterRepair -and (Test-C2FValidWingetId ([string]$mappedAfterRepair.id))) {
						              $key = [string]$mappedAfterRepair.id
						              $preflightNoMatch = $false
						              if ($mappedAfterRepair.name) {
						                $resolvedName = [string]$mappedAfterRepair.name
						              }
						            }
						          } else {
						            C2F-Evidence ("preflight_repair_" + $idx + "=" + $key + "|source_refresh_failed")
						          }
						        }
						      }
					      if ($preflightNoMatch) {
					        $skipped++
					        $unresolved++
				        C2F-Evidence ("skipped_update_" + $idx + "=" + $key + "|" + $resolvedName + "|reason=package_not_found_preflight")
				        if ($key -ne $p) {
				          C2F-Evidence ("package_target_map=" + $p + "->" + $key)
				        }
				        $idx++
				        continue
				      }
				      
				      if (-not ($targets -contains $key)) { $targets += $key }
				      $meta[$key] = @{
				        "key" = $key
				        "name" = $resolvedName
			        "id" = $key
			        "installed" = [string]$resolved.installed
			        "available" = [string]$resolved.available
			        "source" = [string]$resolved.source
			      }
			      if ($key -ne $p) {
			        C2F-Evidence ("package_target_map=" + $p + "->" + $key)
			      }
			    }
			  }

			  $applicable = [int]$targets.Count + [int]$failed
			  $installable = [int]$targets.Count
			  C2F-Evidence ("updates_applicable=" + $applicable)
			  C2F-Evidence ("updates_installable=" + $installable)

				  if ($applicable -eq 0) {
				    C2F-Evidence ("updates_installed=" + $installed)
				    C2F-Evidence ("updates_failed=" + $failed)
				    C2F-Evidence ("updates_remaining=" + $remaining)
				    C2F-Evidence ("updates_skipped=" + $skipped)
				    C2F-Evidence ("updates_unresolved=" + $unresolved)
				    C2F-Evidence ("updates_no_change=" + $noChangeHits)
				    $zeroOutcome = "SUCCESS"
				    if ((-not $allMode) -and ($unresolved -gt 0 -or $skipped -gt 0)) {
				      $zeroOutcome = "FAILED"
				    }
				    C2F-Evidence ("outcome=" + $zeroOutcome)
				    Write-Output ("package update complete: outcome=" + $zeroOutcome + " applicable=0 installable=0 installed=" + $installed + " failed=" + $failed + " remaining=" + $remaining + " skipped=" + $skipped + " unresolved=" + $unresolved)
				    if ($zeroOutcome -eq "FAILED") {
				      throw ("Package update verification failed: no installable mapping for requested package(s); skipped=" + $skipped + " unresolved=" + $unresolved)
				    }
				    C2F-Status "SUCCESS"
				    exit 0
				  }

					  $perPackageTimeoutSeconds = 300
					  if ($allMode) {
					    $perPackageTimeoutSeconds = 180
					  }
				  if ($Version -and $Version -ne "") {
				    $perPackageTimeoutSeconds = [Math]::Max($perPackageTimeoutSeconds, 480)
				  }

		  foreach ($pkgId in $targets) {
		    Assert-C2FWithinBudget
		    Wait-C2FPause
		    Assert-C2FNotCancelled
		    C2F-Evidence ("progress=package_index_" + $idx + "_of_" + [Math]::Max($targets.Count, 1))
		    $m = $null
		    if ($meta.ContainsKey($pkgId)) { $m = $meta[$pkgId] }
		    $disp = $pkgId
			    $installedBefore = ""
			    $availableVer = ""
			    $source = ""
			    $lookupId = $pkgId
			    $isRemovalMode = $false
			    if ($m) {
		      if ($m.name) { $disp = [string]$m.name }
		      if ($m.id) {
		        $candidateId = [string]$m.id
		        if ($candidateId -match '^[A-Za-z0-9]+([._-][A-Za-z0-9]+)+$' -and $candidateId -notmatch '\s') {
		          $lookupId = $candidateId
		        }
		      }
		      if ($m.installed) { $installedBefore = [string]$m.installed }
		      if ($m.available) { $availableVer = [string]$m.available }
		      if ($m.source) { $source = [string]$m.source }
		    }
		    $forceInstall = $false
		    if ($lookupId -and $lookupId.ToLower() -eq 'intel.haxm') {
		      # Intel.HAXM frequently fails `upgrade`; bypass with install/force.
		      $forceInstall = $true
		    }
			    $beforeRows = @()
			    try { $beforeRows = Get-C2FWingetInstalledRows -PackageId $lookupId } catch { $beforeRows = @() }
			    $beforeVersions = @($beforeRows | ForEach-Object { $_.version } | Where-Object { $_ } | Select-Object -Unique)
			    $beforeVersionSummary = [string]::Join(",", $beforeVersions)
			    if (-not $installedBefore -and $beforeVersionSummary) { $installedBefore = $beforeVersionSummary }
			    if ($isRemovalMode) {
			      $arpMeta = $null
			      try { $arpMeta = Get-C2FArpUninstallMeta -LookupId $lookupId -DisplayName $disp } catch { $arpMeta = $null }
			      if ($arpMeta -and $arpMeta.found -and $arpMeta.interactive_only) {
			        $failed++
			        $remaining++
			        C2F-Evidence ("attempt_fallback_" + $idx + "=" + $lookupId + "|" + $disp + "|method=arp_precheck|message=interactive_uninstaller_required")
			        C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=interactive_uninstaller_required|attempts=0")
			        C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|message=interactive_uninstaller_required|attempts=0")
			        $idx++
			        continue
			      }
			    }

					    if ($Version -and $Version -ne "") {
				      C2F-Evidence ("available_update_" + $idx + "=" + $lookupId + "|" + $disp + "|installed_before=" + $installedBefore + "|available=" + $availableVer + "|source=" + $source + "|requested_version=" + $Version)
				      $isWingetId = ($lookupId -match '^[A-Za-z0-9]+([._-][A-Za-z0-9]+)+$' -and $lookupId -notmatch '\s')
				      $selector = @('--name', $lookupId, '--exact')
				      if ($isWingetId) { $selector = @('--id', $lookupId, '--exact') }
				      $installWithVersionArgs = @('--version', $Version, '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
				      $installByIdWithVersion = @('install', $lookupId, '--version', $Version, '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
				      if ($forceInstall -and (Test-C2FWingetSupportsForce)) {
				        $installWithVersionArgs += '--force'
				        $installByIdWithVersion += '--force'
				      }
				      $cmdAttempts = @(
				        @(@('install') + $selector + $installWithVersionArgs),
				        $installByIdWithVersion
				      )
					    } else {
					      C2F-Evidence ("available_update_" + $idx + "=" + $lookupId + "|" + $disp + "|installed_before=" + $installedBefore + "|available=" + $availableVer + "|source=" + $source)
						      $isWingetId = ($lookupId -match '^[A-Za-z0-9]+([._-][A-Za-z0-9]+)+$' -and $lookupId -notmatch '\s')
						      $selector = @('--name', $lookupId, '--exact')
					      if ($isWingetId) { $selector = @('--id', $lookupId, '--exact') }
					      $resolvedAvailableVersion = Normalize-C2FToken $availableVer
					      $hasResolvedAvailableVersion = (
					        $resolvedAvailableVersion -and
					        $resolvedAvailableVersion -notmatch '^(?i)(unknown|n/a|-)$'
					      )
					      $upgradeSilent = @(@('upgrade') + $selector + @('--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity', '--include-unknown'))
					      $installArgs = @('--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
					      if ($forceInstall -and (Test-C2FWingetSupportsForce)) { $installArgs += '--force' }
					      $installFallbackExact = @(@('install') + $selector + $installArgs)
					      $installFallbackById = @(@('install', $lookupId) + $installArgs)
					      $installFallbackByName = @(@('install', '--name', $lookupId) + $installArgs)
					      $installResolvedVersionExact = @()
					      $installResolvedVersionById = @()
					      if ($hasResolvedAvailableVersion) {
					        $installResolvedVersionArgs = @('--version', $resolvedAvailableVersion, '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
					        if ($forceInstall -and (Test-C2FWingetSupportsForce)) { $installResolvedVersionArgs += '--force' }
					        $installResolvedVersionExact = @(@('install') + $selector + $installResolvedVersionArgs)
					        $installResolvedVersionById = @(@('install', '--id', $lookupId, '--exact') + $installResolvedVersionArgs)
					        C2F-Evidence ("resolved_available_version_" + $idx + "=" + $lookupId + "|" + $resolvedAvailableVersion)
					      }
					      if ($lookupId -match '^(?i)ARP\\') {
					        # ARP packages often have no winget source listing; remediate by removing the vulnerable app.
					        $isRemovalMode = $true
					        $uninstallArgs = @('--silent', '--disable-interactivity')
					        $uninstallById = @(@('uninstall', '--id', $lookupId, '--exact') + $uninstallArgs)
					        $uninstallByName = @(@('uninstall', '--name', $disp, '--exact') + $uninstallArgs)
					        $cmdAttempts = @($uninstallById, $uninstallByName)
					      } elseif ($forceInstall) {
					        # Force-install bypass for Intel.HAXM-like package IDs.
					        if ($hasResolvedAvailableVersion) {
					          $cmdAttempts = @($installResolvedVersionExact, $installResolvedVersionById, $installFallbackExact, $installFallbackById, $installFallbackByName)
					        } else {
					          $cmdAttempts = @($installFallbackExact, $installFallbackById, $installFallbackByName)
					        }
					      } else {
					        # Deterministic flow: upgrade, then broaden install fallbacks for names/IDs.
					        if ($hasResolvedAvailableVersion) {
					          $cmdAttempts = @($installResolvedVersionExact, $installResolvedVersionById, $upgradeSilent, $installFallbackExact, $installFallbackById, $installFallbackByName)
					        } else {
					          $cmdAttempts = @($upgradeSilent, $installFallbackExact, $installFallbackById, $installFallbackByName)
					        }
						      }
						    }

					    $maxAttempts = [Math]::Min(3, [Math]::Max(1, [int]$cmdAttempts.Count))
					    if ($isRemovalMode) {
					      # Keep ARP removal deterministic and fast: one winget attempt, then explicit fallback.
					      $maxAttempts = 1
					    }
				    $finalized = $false
					    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
					      Assert-C2FWithinBudget
					      Wait-C2FPause
					      Assert-C2FNotCancelled
					      $cmdAttemptIndex = [Math]::Min(($attempt - 1), ($cmdAttempts.Count - 1))
					      $cmdArgs = @($cmdAttempts[$cmdAttemptIndex])
					      C2F-Evidence ("attempt_update_" + $idx + "=" + $lookupId + "|" + $disp + "|attempt=" + $attempt + "|cmd=" + ([string]::Join(" ", $cmdArgs)).Replace("|", "/"))
					      $run = $null
					      $out = ""
					      $rc = 1
					      $attemptTimeoutSeconds = $perPackageTimeoutSeconds
					      if ($isRemovalMode) {
					        $attemptTimeoutSeconds = [Math]::Min($perPackageTimeoutSeconds, 45)
					      }
					      try {
					        $run = Invoke-C2FWinget -WingetArgs $cmdArgs -TimeoutSeconds $attemptTimeoutSeconds
					        C2F-Evidence ("attempt_method_" + $idx + "=" + $lookupId + "|" + $disp + "|attempt=" + $attempt + "|method=" + [string]$run.method)
					        $out = [string]$run.output
					        $rc = [int]$run.exit_code
				      } catch {
				        $out = [string]$_.Exception.Message
				        $rc = 1
				      }
				      $flat = $out.Replace("`r", " ").Replace("`n", " ").Replace("|", "/").Trim()
				      $isHelpRun = (
				        ($out -match '(?im)^\s*usage:\s*winget\b') -or
				        ($out -match 'The following commands are available:') -or
				        ($out -match 'The winget command line utility enables installing applications')
				      )
				      if ($isHelpRun) {
				        if ($attempt -lt $maxAttempts) {
				          continue
				        }
				        $failed++
				        $remaining++
				        C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=winget_usage_output")
				        C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|message=winget_usage_output|attempts=" + $maxAttempts)
				        $finalized = $true
				        break
				      }
				      if ($rc -eq 0) {
				        if ($isRemovalMode) {
				          $afterRowsRemoved = @()
				          try { $afterRowsRemoved = Get-C2FWingetInstalledRows -PackageId $lookupId } catch { $afterRowsRemoved = @() }
				          if (-not $afterRowsRemoved -or $afterRowsRemoved.Count -eq 0) {
				            $installed++
				            C2F-Evidence ("installed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|attempt=" + $attempt + "|mode=removed")
				            $finalized = $true
				            break
				          }
					          if ($attempt -lt $maxAttempts) {
					            continue
					          }
					          $fallback = Invoke-C2FArpRemovalFallback -LookupId $lookupId -DisplayName $disp -TimeoutSeconds 240
					          $fallbackMethod = [string]$fallback.method
					          $fallbackMessage = ([string]$fallback.message).Replace("|", "/")
					          C2F-Evidence ("attempt_fallback_" + $idx + "=" + $lookupId + "|" + $disp + "|method=" + $fallbackMethod + "|message=" + $fallbackMessage)
					          if ($fallback.ok) {
					            Start-Sleep -Seconds 2
					            $afterRowsRemovedFallback = @()
					            try { $afterRowsRemovedFallback = Get-C2FWingetInstalledRows -PackageId $lookupId } catch { $afterRowsRemovedFallback = @() }
					            $arpPresentAfterFallback = $true
					            try { $arpPresentAfterFallback = Test-C2FArpEntryPresent -LookupId $lookupId -DisplayName $disp } catch { $arpPresentAfterFallback = $true }
					            if ((-not $afterRowsRemovedFallback -or $afterRowsRemovedFallback.Count -eq 0) -or (-not $arpPresentAfterFallback)) {
					              $installed++
					              C2F-Evidence ("installed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|attempt=" + $attempt + "|mode=removed_fallback|method=" + $fallbackMethod)
					              $finalized = $true
					              break
					            }
					          }
					          $remaining++
					          $failed++
					          C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=uninstall_incomplete|attempts=" + $maxAttempts)
				          C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|message=uninstall_incomplete|attempts=" + $maxAttempts)
				          $finalized = $true
				          break
				        }
				        $pending = Test-C2FWingetPendingUpgrade -PackageId $lookupId
				        $noChange = $false
				        if ($out -match 'No applicable update found' -or $out -match 'No available upgrade found' -or $out -match 'No installed package found' -or $out -match 'No package found matching input criteria') { $noChange = $true }
				        if ($noChange) {
				          $notFound = ($out -match 'No package found matching input criteria')
				          $notInstalled = ($out -match 'No installed package found')
				          # Always try every fallback command before concluding no-change/not-found.
				          if ($attempt -lt $maxAttempts) {
				            continue
				          }
					          $afterRowsNoChange = @()
					          try { $afterRowsNoChange = Get-C2FWingetInstalledRows -PackageId $lookupId } catch { $afterRowsNoChange = @() }
				          $afterVersionsNoChange = @($afterRowsNoChange | ForEach-Object { $_.version } | Where-Object { $_ } | Select-Object -Unique)
				          $afterVersionSummaryNoChange = [string]::Join(",", $afterVersionsNoChange)
				          $afterCleanNoChange = $afterVersionSummaryNoChange.Replace("`r", " ").Replace("`n", " ").Replace("|", "/").Trim()
				          if ($forceInstall -and $pending -eq $false -and $afterVersionsNoChange.Count -gt 0) {
				            $installed++
				            C2F-Evidence ("installed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|attempt=" + $attempt + "|installed_before=" + $installedBefore + "|installed_after=" + $afterCleanNoChange + "|message=no_applicable_update")
				            $finalized = $true
				            break
				          }
				          if ($notFound -or $notInstalled) {
				            $skipped++
				            $unresolved++
				            $reason = "package_not_found"
				            if ($notInstalled) { $reason = "package_not_installed" }
				            C2F-Evidence ("skipped_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=" + $reason)
				            $finalized = $true
				            break
				          }
				          $skipped++
				          $noChangeHits++
				          C2F-Evidence ("skipped_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=no_applicable_update")
				          $finalized = $true
				          break
				        }
				        if ($pending -eq $false) {
				          $afterRows = @()
				          try { $afterRows = Get-C2FWingetInstalledRows -PackageId $lookupId } catch { $afterRows = @() }
				          $afterVersions = @($afterRows | ForEach-Object { $_.version } | Where-Object { $_ } | Select-Object -Unique)
				          $afterVersionSummary = [string]::Join(",", $afterVersions)
				          $afterClean = $afterVersionSummary.Replace("`r", " ").Replace("`n", " ").Replace("|", "/").Trim()

				          $norm = { param([string]$v) if (-not $v) { return "" }; return $v.Trim() }
				          $comparable = { param([string]$v)
				            $x = & $norm $v
				            if (-not $x) { return $false }
				            if ($x -match '^(?i)(unknown|-)$') { return $false }
				            return $true
				          }

				          $beforeComparable = @($beforeVersions | Where-Object { & $comparable $_ } | ForEach-Object { (& $norm $_) } | Select-Object -Unique)
				          if ($beforeComparable.Count -eq 0 -and (& $comparable $installedBefore)) {
				            $beforeComparable = @($installedBefore -split ',' | ForEach-Object { (& $norm $_) } | Where-Object { & $comparable $_ } | Select-Object -Unique)
				          }
				          $afterComparable = @($afterVersions | Where-Object { & $comparable $_ } | ForEach-Object { (& $norm $_) } | Select-Object -Unique)

				          $expectedComparable = ""
				          if (& $comparable $availableVer) { $expectedComparable = (& $norm $availableVer) }

				          $versionOk = $null
				          $versionReason = ""

				          if ($afterComparable.Count -eq 0) {
				            $versionOk = $null
				            $versionReason = "post_verify_after_version_unknown"
				          } elseif ($expectedComparable) {
				            $exp = $expectedComparable.ToLower()
				            $match = $false
				            foreach ($v in $afterComparable) {
				              $vl = ([string]$v).ToLower()
				              if ($vl -eq $exp -or $vl.StartsWith($exp) -or $exp.StartsWith($vl)) { $match = $true; break }
				            }
				            if ($match) {
				              $versionOk = $true
				            } else {
				              $versionOk = $false
				              $versionReason = "post_verify_after_version_mismatch"
				            }
				          } elseif ($beforeComparable.Count -eq 0) {
				            $versionOk = $null
				            $versionReason = "post_verify_before_version_unknown"
				          } else {
				            $intersection = @($beforeComparable | Where-Object { $afterComparable -contains $_ })
				            if ($intersection.Count -gt 0) {
				              $newOnes = @($afterComparable | Where-Object { -not ($beforeComparable -contains $_) })
				              if ($newOnes.Count -gt 0) {
				                $versionOk = $false
				                $versionReason = "post_verify_old_version_still_present"
				              } else {
				                $versionOk = $false
				                $versionReason = "post_verify_no_version_change"
				              }
				            } else {
				              $versionOk = $true
				            }
				          }
				          if (-not $versionReason) { $versionReason = "post_verify_version_unknown" }

				          if ($versionOk -eq $true) {
				            $installed++
				            C2F-Evidence ("installed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|attempt=" + $attempt + "|installed_before=" + $installedBefore + "|installed_after=" + $afterClean + "|available_before=" + $availableVer)
				            $finalized = $true
				            break
				          }

				          if ($attempt -lt $maxAttempts) {
				            continue
				          }

				          $remaining++
				          $failed++
				          C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=" + $versionReason + "|attempts=" + $maxAttempts)
				          C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|message=" + $versionReason + "|attempts=" + $maxAttempts + "|installed_before=" + $installedBefore + "|installed_after=" + $afterClean + "|available_before=" + $availableVer)
				          $finalized = $true
				          break
				        }
				        if ($attempt -lt $maxAttempts) {
				          continue
				        }
				        $remaining++
				        $failed++
				        if ($pending -eq $true) {
				          C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=post_verify_pending_upgrade|attempts=" + $maxAttempts)
				          C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|message=post_verify_pending_upgrade|attempts=" + $maxAttempts)
				        } else {
				          # Strict mode: if we cannot verify that the package left the upgradable set,
				          # do not mark it installed.
				          C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=post_verify_inconclusive|attempts=" + $maxAttempts)
				          C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=0|message=post_verify_inconclusive|attempts=" + $maxAttempts)
				        }
				        $finalized = $true
				        break
				      }

				      if ($attempt -lt $maxAttempts) {
				        continue
				      }

				      $failed++
				      $remaining++
				      C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=winget_rc_" + $rc)
				      C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=" + $rc + "|message=" + $flat + "|attempts=" + $maxAttempts)
				      $finalized = $true
				      break
				    }
				    if (-not $finalized) {
				      $failed++
				      $remaining++
				      C2F-Evidence ("remaining_update_" + $idx + "=" + $lookupId + "|" + $disp + "|reason=verification_loop_unfinished")
				      C2F-Evidence ("failed_update_" + $idx + "=" + $lookupId + "|" + $disp + "|rc=-1|message=verification_loop_unfinished")
				    }
		    $idx++
		  }

		  if ($allMode) {
		    $postRows = Get-C2FWingetUpgrades
		    $remaining = [int]$postRows.Count
		    for ($j = 0; $j -lt $postRows.Count; $j++) {
		      $r = $postRows[$j]
		      # Reserved PowerShell automatic variables are avoided here.
		      $pkgKey = if ($r.id) { [string]$r.id } else { [string]$r.key }
		      $pkgName = if ($r.name) { [string]$r.name } else { $pkgKey }
		      $pavail = [string]$r.available
		      C2F-Evidence ("remaining_update_" + $j + "=" + $pkgKey + "|" + $pkgName + "|available=" + $pavail)
		    }
		    $installed = [Math]::Max($applicable - $failed - $remaining, 0)
		  }

	  C2F-Evidence ("updates_installed=" + $installed)
		  C2F-Evidence ("updates_failed=" + $failed)
		  C2F-Evidence ("updates_remaining=" + $remaining)
		  C2F-Evidence ("updates_skipped=" + $skipped)
		  C2F-Evidence ("updates_unresolved=" + $unresolved)
		  C2F-Evidence ("updates_no_change=" + $noChangeHits)

		  $outcome = "SUCCESS"
		  if ($failed -gt 0 -or $remaining -gt 0) {
		    if ($allMode) {
		      $outcome = "PARTIAL"
		    } else {
		      $outcome = "FAILED"
		    }
		  } elseif ($unresolved -gt 0 -or ($skipped -gt 0 -and $installed -eq 0)) {
		    $outcome = "PARTIAL"
		  }
			  C2F-Evidence ("outcome=" + $outcome)

			  Write-Output ("package update complete: outcome=" + $outcome + " applicable=" + $applicable + " installable=" + $installable + " installed=" + $installed + " failed=" + $failed + " remaining=" + $remaining + " skipped=" + $skipped + " unresolved=" + $unresolved)
			  $treatPartialAsFailure = (-not $allMode)
			  if ($outcome -eq "FAILED" -or ($treatPartialAsFailure -and $outcome -eq "PARTIAL")) {
			    throw ("Package update verification failed: installed=" + $installed + " failed=" + $failed + " remaining=" + $remaining + " skipped=" + $skipped + " unresolved=" + $unresolved)
			  }
			  C2F-Status "SUCCESS"
		  exit 0
		}
			catch {
			  $err = $_.Exception.Message
			  $cmdText = [string]$cmd
			  $runAsSystemText = [string]$RunAsSystem
			  if (
			    $cmdText -match '(?i)^\s*winget(?:\.exe)?\b'
			    -and $runAsSystemText -match '^(?i:true|1|yes|on)$'
			    -and $err -match '(?i)file cannot be accessed by the system'
			  ) {
			    $err = $err + " | winget is not accessible under SYSTEM on this endpoint; disable Run as SYSTEM for winget commands."
			  }
			  C2F-Evidence ("error=" + $err)
			  C2F-Status "FAILED" $err
			  throw $err
			}
			""".strip()

        if aid == "custom-os-command":
            return r"""
		param(
		  [string]$ExecId = "adhoc",
		  [string]$AgentId = "",
		  [string]$ActionId = "custom-os-command",
		  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
		  [string]$CommandFile = "",
		  [string]$VerifyKb = "",
		  [string]$VerifyMinBuild = "",
		  [string]$VerifyStdoutContains = "",
		  [string]$RunAsSystem = "false",
		  [int]$MaxRuntimeSeconds = 1800
		)

		$ErrorActionPreference = "Stop"
		$ProgressPreference = "SilentlyContinue"

		function Write-C2FLogLine {
		  param([string]$Line)
		  try {
		    $dir = Split-Path -Parent $LogFile
		    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
		    Add-Content -Path $LogFile -Value $Line
		  } catch { }
		}

		if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
		  function C2F-Evidence {
		    param([string]$Message)
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
		    } catch { }
		  }
		}

		if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
		  function C2F-Status {
		    param([string]$Status, [string]$Message = "")
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
		      if ($Message) {
		        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
		        $line = $line + " message=" + $clean
		      }
		      Write-C2FLogLine $line
		    } catch { }
		  }
		}

			function C2F-CompareBuild {
			  param([string]$Current, [string]$Required)
		  $cParts = @()
		  foreach ($part in ($Current -split '\.')) {
		    if ($part -match '^\d+$') { $cParts += [int]$part }
		  }
		  $rParts = @()
		  foreach ($part in ($Required -split '\.')) {
		    if ($part -match '^\d+$') { $rParts += [int]$part }
		  }
		  if ($cParts.Count -eq 0 -or $rParts.Count -eq 0) { return -1 }
		  $max = [Math]::Max($cParts.Count, $rParts.Count)
		  for ($i = 0; $i -lt $max; $i++) {
		    $cv = 0
		    if ($i -lt $cParts.Count) { $cv = [int]$cParts[$i] }
		    $rv = 0
		    if ($i -lt $rParts.Count) { $rv = [int]$rParts[$i] }
		    if ($cv -gt $rv) { return 1 }
		    if ($cv -lt $rv) { return -1 }
		  }
			  return 0
			}

			function C2F-RunCommand {
			  param([string]$CommandText)
			  $global:LASTEXITCODE = 0
			  $rawOut = (& ([ScriptBlock]::Create($CommandText)) 2>&1 | Out-String)
			  $code = 0
			  if ($LASTEXITCODE -ne $null) {
			    try { $code = [int]$LASTEXITCODE } catch { $code = 1 }
			  }
			  return @{
			    rc = $code
			    output = [string]$rawOut
			  }
			}

			function C2F-GetPendingWindowsUpdates {
			  try {
			    $session = New-Object -ComObject Microsoft.Update.Session
			    $searcher = $session.CreateUpdateSearcher()
			    $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
			    $titles = @()
			    for ($i = 0; $i -lt [Math]::Min([int]$res.Updates.Count, 6); $i++) {
			      $titles += [string]$res.Updates.Item($i).Title
			    }
			    return @{
			      count = [int]$res.Updates.Count
			      titles = @($titles)
			      error = ""
			    }
			  } catch {
			    return @{
			      count = -1
			      titles = @()
			      error = [string]$_.Exception.Message
			    }
			  }
			}

			function C2F-TestRebootPending {
			  try {
			    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { return $true }
			    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { return $true }
			    $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
			    if ($pfro) { return $true }
			  } catch { }
			  return $false
			}

			function C2F-DiagnoseFirstPendingWindowsUpdate {
			  try {
			    $session = New-Object -ComObject Microsoft.Update.Session
			    $searcher = $session.CreateUpdateSearcher()
			    $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
			    if ([int]$res.Updates.Count -le 0) {
			      return @{ found = $false; error = "no_pending_updates" }
			    }
			    $target = $res.Updates.Item(0)
			    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
			    [void]$coll.Add($target)
			    $installer = $session.CreateUpdateInstaller()
			    $installer.Updates = $coll
			    $installer.ForceQuiet = $true
			    $result = $installer.Install()
			    $uResult = $result.GetUpdateResult(0)
			    $hr = 0
			    try { $hr = [int]$uResult.HResult } catch { $hr = 0 }
			    $hrHex = ""
			    try {
			      if ($hr -lt 0) {
			        $hrHex = ('0x{0:X8}' -f ([uint32]([int64]$hr + 0x100000000)))
			      } else {
			        $hrHex = ('0x{0:X8}' -f ([uint32]$hr))
			      }
			    } catch { $hrHex = "" }
			    return @{
			      found = $true
			      title = [string]$target.Title
			      result_code = [int]$result.ResultCode
			      update_result = [int]$uResult.ResultCode
			      hresult = [int]$hr
			      hresult_hex = [string]$hrHex
			      reboot_required = [bool]$result.RebootRequired
			      error = ""
			    }
			  } catch {
			    return @{
			      found = $false
			      error = [string]$_.Exception.Message
			    }
			  }
			}

		try {
		  C2F-Status "START"
		  if (-not $CommandFile -or -not $CommandFile.Trim()) {
		    throw "custom-os-command requires command argument"
		  }
		  if (-not (Test-Path $CommandFile)) {
		    throw ("custom-os-command command file missing: " + $CommandFile)
		  }

		  $cmd = [string](Get-Content -Path $CommandFile -Raw -ErrorAction Stop)
		  if (-not $cmd -or -not $cmd.Trim()) {
		    throw "custom-os-command requires command argument"
		  }

			  $safe = $cmd.Replace("|", "/").Replace("`r", " ").Replace("`n", " ")
			  if ($safe.Length -gt 220) { $safe = $safe.Substring(0, 220) + "..." }
			  C2F-Evidence ("custom_command=" + $safe)
			  C2F-Evidence ("run_as_system=" + [string]$RunAsSystem)

				  $run = C2F-RunCommand $cmd
				  $out = [string]$run.output
				  # Some native tools emit UTF-16/UTF-8 mixed output with embedded nulls.
				  # Normalize early so history/output previews remain readable.
				  $out = ($out -replace "`0", "")
				  $rc = [int]$run.rc
			  if ($rc -ne 0) {
			    throw ("custom-os-command failed rc=" + $rc + " output=" + $out)
			  }

		  $verifyKbRaw = [string]$VerifyKb
		  $verifyKbRaw = ($verifyKbRaw -replace '(?i)^\s*kb', 'KB').Trim()
		  if ($verifyKbRaw) {
		    $kbDigits = ($verifyKbRaw -replace '(?i)^KB', '').Trim()
		    if (-not $kbDigits -or $kbDigits -notmatch '^\d+$') {
		      throw "custom-os-command verify_kb must be KB followed by digits"
		    }
		    $requiredKb = "KB" + $kbDigits
		    C2F-Evidence ("verify_kb_required=" + $requiredKb)
		    $kbMatch = Get-HotFix -Id $requiredKb -ErrorAction SilentlyContinue
		    if (-not $kbMatch) {
		      $kbMatch = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -eq $requiredKb } | Select-Object -First 1
		    }
		    $kbPresent = $false
		    if ($kbMatch) { $kbPresent = $true }
		    C2F-Evidence ("verify_kb_present=" + $kbPresent)
		    if (-not $kbPresent) {
		      throw ("custom-os-command verification failed: required KB not found: " + $requiredKb)
		    }
		  }

		  $verifyBuild = [string]$VerifyMinBuild
		  $verifyBuild = $verifyBuild.Trim()
		  if ($verifyBuild) {
		    if ($verifyBuild -notmatch '^\d+(?:\.\d+){1,3}$') {
		      throw "custom-os-command verify_min_build must be numeric (example: 19045.6937)"
		    }
		    $cv = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
		    $build = [string]$cv.CurrentBuildNumber
		    if (-not $build) { $build = [string]$cv.CurrentBuild }
		    $ubr = [string]$cv.UBR
		    if (-not $ubr) { $ubr = "0" }
		    $currentBuild = $build + "." + $ubr
		    C2F-Evidence ("verify_min_build_required=" + $verifyBuild)
		    C2F-Evidence ("verify_min_build_current=" + $currentBuild)
		    $cmp = C2F-CompareBuild -Current $currentBuild -Required $verifyBuild
		    $buildMet = ($cmp -ge 0)
		    C2F-Evidence ("verify_min_build_met=" + $buildMet)
		    if (-not $buildMet) {
		      throw ("custom-os-command verification failed: minimum build " + $verifyBuild + " required, observed " + $currentBuild)
		    }
		  }

		  $verifyContains = [string]$VerifyStdoutContains
		  $verifyContains = $verifyContains.Trim()
			  if ($verifyContains) {
			    $safeNeedle = $verifyContains.Replace("|", "/").Replace("`r", " ").Replace("`n", " ")
			    if ($safeNeedle.Length -gt 220) { $safeNeedle = $safeNeedle.Substring(0, 220) + "..." }
			    C2F-Evidence ("verify_stdout_contains_required=" + $safeNeedle)
		    $contains = ([string]$out).IndexOf($verifyContains, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
		    C2F-Evidence ("verify_stdout_contains_met=" + $contains)
		    if (-not $contains) {
		      throw ("custom-os-command verification failed: stdout missing required text: " + $verifyContains)
			    }
			  }
	
			  $launchWithoutWait = (
			    ($cmd -match '(?i)\bStart-Process\b') -and
			    (-not ($cmd -match '(?i)\bStart-Process\b[^;\r\n]*\s-Wait\b'))
			  )
			  $outText = [string]$out
			  $outPreview = $outText.Replace("|", "/").Replace("`r", " ").Replace("`n", " ").Trim()
			  if ($outPreview.Length -gt 400) { $outPreview = $outPreview.Substring(0, 400) + "..." }
			  if ($outPreview) {
			    C2F-Evidence ("stdout_preview=" + $outPreview)
			    C2F-Status "SUCCESS" $outPreview
			  } else {
			    C2F-Evidence "stdout_preview=<empty>"
			    if ($launchWithoutWait) {
			      C2F-Evidence "command_mode=launch_without_wait"
			      C2F-Status "SUCCESS" "process launched (no stdout); child process completion is not tracked without -Wait"
			    } else {
			      C2F-Status "SUCCESS" "command completed (no stdout)"
			    }
			  }
			  Write-Output $outText
			  exit 0
			}
		catch {
		  $err = $_.Exception.Message
		  C2F-Evidence ("error=" + $err)
		  C2F-Status "FAILED" $err
		  throw
		}
		""".strip()

        if aid == "malware-scan":
            return r"""
		param(
		  [string]$ExecId = "adhoc",
		  [string]$AgentId = "",
		  [string]$ActionId = "malware-scan",
		  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
		  [string]$Scope = "quick",
		  [int]$MaxRuntimeSeconds = 600
		)

		$ErrorActionPreference = "Stop"
		$ProgressPreference = "SilentlyContinue"

		function Write-C2FLogLine {
		  param([string]$Line)
		  try {
		    $dir = Split-Path -Parent $LogFile
		    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
		    Add-Content -Path $LogFile -Value $Line
		  } catch { }
		}

		if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
		  function C2F-Evidence {
		    param([string]$Message)
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
		    } catch { }
		  }
		}

		if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
		  function C2F-Status {
		    param([string]$Status, [string]$Message = "")
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
		      if ($Message) {
		        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
		        $line = $line + " message=" + $clean
		      }
		      Write-C2FLogLine $line
		    } catch { }
		  }
		}

		try {
		  C2F-Status "START"

		  if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
		    throw "Defender cmdlets unavailable (Start-MpScan not found)"
		  }

		  $controlDir = "C:\Click2Fix\control"
		  try { New-Item -ItemType Directory -Path $controlDir -Force | Out-Null } catch { }
		  $pauseFlag = Join-Path $controlDir ("pause-" + $ExecId + ".flag")
		  $cancelFlag = Join-Path $controlDir ("cancel-" + $ExecId + ".flag")

		  function Assert-C2FNotCancelled {
		    if (Test-Path $cancelFlag) {
		      C2F-Evidence "control=cancel_requested"
		      throw "Execution cancelled by operator"
		    }
		  }

		  function Wait-C2FPause {
		    if (-not (Test-Path $pauseFlag)) { return }
		    C2F-Evidence "control=pause_requested"
		    while (Test-Path $pauseFlag) {
		      Assert-C2FNotCancelled
		      Start-Sleep -Seconds 2
		    }
		    C2F-Evidence "control=pause_released"
		  }

		  $scopeValue = [string]$Scope
		  if (-not $scopeValue) { $scopeValue = "quick" }
		  $scopeNorm = $scopeValue.Trim().ToLower()
		  if (-not $scopeNorm) { $scopeNorm = "quick" }

		  $scanType = "QuickScan"
		  $scopeDetail = "quick"
		  $customPath = ""
		  if ($scopeNorm -eq "full") {
		    $scanType = "FullScan"
		    $scopeDetail = "full"
		  } elseif ($scopeNorm -eq "quick") {
		    $scanType = "QuickScan"
		    $scopeDetail = "quick"
		  } else {
		    $scanType = "CustomScan"
		    $customPath = [string]$scopeValue
		    if (-not (Test-Path $customPath)) {
		      throw ("custom scan path not found: " + $customPath)
		    }
		    $scopeDetail = $customPath
		  }

		  $maxSeconds = [Math]::Max(120, [int]$MaxRuntimeSeconds)
		  $reportDir = "C:\Click2Fix\reports"
		  New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
		  $reportPath = Join-Path $reportDir ("malware-scan-" + $ExecId + ".txt")
		  $scanStarted = Get-Date

		  C2F-Evidence "scan_type=malware"
		  C2F-Evidence ("scan_scope=" + $scopeDetail)
		  C2F-Evidence "scan_engine=windows-defender"
		  C2F-Evidence ("scan_timeout_seconds=" + $maxSeconds)

		  $command = ""
		  if ($scanType -eq "CustomScan") {
		    $p = $customPath.Replace("'", "''")
		    $command = "Start-MpScan -ScanType CustomScan -ScanPath '" + $p + "'"
		  } else {
		    $command = "Start-MpScan -ScanType " + $scanType
		  }
		  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
		  $proc = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-EncodedCommand", $encoded) -PassThru -WindowStyle Hidden
		  C2F-Evidence ("scan_process_pid=" + [string]$proc.Id)

		  $nextHeartbeat = Get-Date
		  while ($proc -and (-not $proc.HasExited)) {
		    Wait-C2FPause
		    Assert-C2FNotCancelled
		    $elapsed = [int]((Get-Date) - $scanStarted).TotalSeconds
		    if ((Get-Date) -ge $nextHeartbeat) {
		      C2F-Evidence ("progress=running|elapsed_seconds=" + [string]$elapsed + "|pid=" + [string]$proc.Id)
		      $nextHeartbeat = (Get-Date).AddSeconds(15)
		    }
		    if ($elapsed -ge $maxSeconds) {
		      try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
		      throw ("malware-scan timed out after " + [string]$elapsed + "s")
		    }
		    Start-Sleep -Seconds 2
		  }

		  $scanRc = 0
		  try { $scanRc = [int]$proc.ExitCode } catch { $scanRc = 1 }
		  if ($scanRc -ne 0) {
		    throw ("malware-scan process failed rc=" + [string]$scanRc)
		  }

		  $detections = @()
		  try {
		    $since = (Get-Date).AddHours(-6)
		    $detections = @(
		      Get-MpThreatDetection -ErrorAction SilentlyContinue |
		      Where-Object { (-not $_.InitialDetectionTime) -or ($_.InitialDetectionTime -ge $since) } |
		      Select-Object -First 50 ThreatName,Resources,ActionSuccess,InitialDetectionTime
		    )
		  } catch {
		    $detections = @()
		  }

		  $scanFinished = Get-Date
		  $status = if ($detections.Count -gt 0) { "MATCH" } else { "CLEAN" }
		  $summary = ("Malware scan complete: status=" + $status + " scope=" + $scopeDetail + " detections=" + [string]$detections.Count)

		  $reportLines = New-Object System.Collections.Generic.List[string]
		  $reportLines.Add("Click2Fix Malware Scan Report")
		  $reportLines.Add("Execution ID: " + $ExecId)
		  $reportLines.Add("Agent ID: " + $AgentId)
		  $reportLines.Add("Started: " + $scanStarted.ToString("o"))
		  $reportLines.Add("Finished: " + $scanFinished.ToString("o"))
		  $reportLines.Add("Scope: " + $scopeDetail)
		  $reportLines.Add("Engine: windows-defender")
		  $reportLines.Add("Status: " + $status)
		  $reportLines.Add("Detections: " + [string]$detections.Count)
		  $reportLines.Add("")
		  if ($detections.Count -gt 0) {
		    $reportLines.Add("Findings")
		    for ($i = 0; $i -lt $detections.Count; $i++) {
		      $d = $detections[$i]
		      $threat = [string]$d.ThreatName
		      $resource = [string]$d.Resources
		      $actionSuccess = [string]$d.ActionSuccess
		      $when = ""
		      try { $when = [string]$d.InitialDetectionTime } catch { $when = "" }
		      $recommendation = "Isolate endpoint, remove/quarantine affected file(s), and perform credential hygiene if execution occurred."
		      if ($threat -match '(?i)mimikatz|credential|lsass') {
		        $recommendation = "Potential credential theft: isolate host immediately, reset privileged credentials, and investigate lateral movement."
		      }
		      $reportLines.Add(("#" + [string]($i + 1)))
		      $reportLines.Add(("Threat: " + $threat))
		      $reportLines.Add(("Resource: " + $resource))
		      if ($when) { $reportLines.Add(("Detected At: " + $when)) }
		      $reportLines.Add(("Action Success: " + $actionSuccess))
		      $reportLines.Add(("Recommendation: " + $recommendation))
		      $reportLines.Add("")

		      $safeResource = ($resource -replace '\|','/' -replace '\r?\n',' ')
		      if ($safeResource.Length -gt 220) { $safeResource = $safeResource.Substring(0, 220) + "..." }
		      $safeRecommendation = ($recommendation -replace '\|','/' -replace '\r?\n',' ')
		      C2F-Evidence ("scan_hit_" + [string]$i + "=malware|" + $threat + "|detail=" + $safeResource + "|recommendation=" + $safeRecommendation)
		    }
		  } else {
		    $reportLines.Add("No malware detections were reported by Defender in this scan window.")
		  }
		  $reportLines.Add("")
		  $reportLines.Add("Summary: " + $summary)
		  Set-Content -Path $reportPath -Value $reportLines -Encoding UTF8

		  C2F-Evidence ("scan_report_path=" + $reportPath)
		  C2F-Evidence ("scan_total_examined=" + [string][Math]::Max($detections.Count, 1))
		  C2F-Evidence ("scan_matches=" + [string]$detections.Count)
		  C2F-Evidence ("scan_status=" + $status)
		  C2F-Evidence ("artifact_0=report|" + $reportPath + "|format=txt")
		  C2F-Evidence ("scan_summary=" + ($summary -replace '\|','/' -replace '\r?\n',' '))
		  C2F-Status "SUCCESS"
		  Write-Output $summary
		  Write-Output ("report=" + $reportPath)
		  exit 0
		}
		catch {
		  $err = $_.Exception.Message
		  C2F-Evidence ("error=" + $err)
		  C2F-Status "FAILED" $err
		  throw
		}
			""".strip()

        if aid == "threat-hunt-persistence":
            return r"""
		param(
		  [string]$ExecId = "adhoc",
		  [string]$AgentId = "",
		  [string]$ActionId = "threat-hunt-persistence",
		  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
		  [int]$MaxRuntimeSeconds = 900
		)

		$ErrorActionPreference = "Stop"
		$ProgressPreference = "SilentlyContinue"

		function Write-C2FLogLine {
		  param([string]$Line)
		  try {
		    $dir = Split-Path -Parent $LogFile
		    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
		    Add-Content -Path $LogFile -Value $Line
		  } catch { }
		}

		if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
		  function C2F-Evidence {
		    param([string]$Message)
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
		    } catch { }
		  }
		}

		if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
		  function C2F-Status {
		    param([string]$Status, [string]$Message = "")
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
		      if ($Message) {
		        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
		        $line = $line + " message=" + $clean
		      }
		      Write-C2FLogLine $line
		    } catch { }
		  }
		}

		try {
		  C2F-Status "START"
		  $started = Get-Date
		  $reportDir = "C:\Click2Fix\reports"
		  New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
		  $reportPath = Join-Path $reportDir ("persistence-hunt-" + $ExecId + ".txt")
		  $hits = @()
		  $totalExamined = 0
		  $maxHits = 120
		  $maxRuntime = [Math]::Max(180, [int]$MaxRuntimeSeconds)

		  function Assert-C2FWithinBudget {
		    $elapsed = [int]((Get-Date) - $started).TotalSeconds
		    if ($elapsed -ge $maxRuntime) {
		      throw ("threat-hunt-persistence timed out after " + [string]$elapsed + "s")
		    }
		  }

		  function Add-C2FHit {
		    param([string]$Source, [string]$Name, [string]$Detail, [string]$Recommendation)
		    if ($hits.Count -ge $maxHits) { return }
		    $hits += @{
		      "source" = [string]$Source
		      "name" = [string]$Name
		      "detail" = [string]$Detail
		      "recommendation" = [string]$Recommendation
		    }
		  }

		  function Inspect-C2FEntry {
		    param([string]$Source, [string]$Name, [string]$Detail)
		    Assert-C2FWithinBudget
		    $script:totalExamined++
		    $text = [string]$Detail
		    if (-not $text) { return }
		    $low = $text.ToLower()
		    $patterns = @(
		      "powershell -enc", "cmd.exe /c", "rundll32", "regsvr32", "mshta",
		      "wscript", "cscript", "certutil -urlcache", "bitsadmin", "\appdata\", "\temp\", " -nop "
		    )
		    foreach ($p in $patterns) {
		      if ($low.Contains($p)) {
		        $rec = "Review startup entry ownership and disable/quarantine unauthorized persistence."
		        switch -Regex ($p) {
		          "powershell -enc|wscript|cscript|mshta" { $rec = "Likely script-based persistence: decode payload, block script host abuse, and remove startup trigger."; break }
		          "rundll32|regsvr32" { $rec = "Potential LOLBin persistence: validate binary path/signature and remove suspicious autorun registration."; break }
		          "certutil -urlcache|bitsadmin" { $rec = "Potential staged payload retrieval: isolate endpoint and investigate outbound destinations."; break }
		          "\\appdata\\|\\temp\\" { $rec = "Startup points to user/temp path: validate legitimacy and quarantine unknown binaries/scripts."; break }
		        }
		        Add-C2FHit -Source $Source -Name $Name -Detail $Detail -Recommendation $rec
		        break
		      }
		    }
		  }

		  $runKeys = @(
		    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
		    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
		    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
		    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
		  )
		  foreach ($rk in $runKeys) {
		    if (-not (Test-Path $rk)) { continue }
		    try {
		      $props = Get-ItemProperty -Path $rk -ErrorAction Stop
		      $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
		        $entryName = $rk + "::" + [string]$_.Name
		        $entryDetail = [string]$_.Value
		        Inspect-C2FEntry -Source "registry_run" -Name $entryName -Detail $entryDetail
		      }
		    } catch { }
		  }

		  $startupPaths = @(
		    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
		    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
		  )
		  foreach ($sp in $startupPaths) {
		    if (-not (Test-Path $sp)) { continue }
		    try {
		      Get-ChildItem -Path $sp -Force -ErrorAction SilentlyContinue | ForEach-Object {
		        $entryName = [string]$_.Name
		        $entryDetail = [string]$_.FullName
		        Inspect-C2FEntry -Source "startup_folder" -Name $entryName -Detail $entryDetail
		      }
		    } catch { }
		  }

		  $tasks = @()
		  try { $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue } catch { $tasks = @() }
		  foreach ($task in $tasks) {
		    Assert-C2FWithinBudget
		    $name = [string]$task.TaskName
		    $detail = [string]$task.TaskPath + "|" + [string]$task.State
		    try {
		      if ($task.Actions) {
		        foreach ($act in $task.Actions) {
		          $detail = $detail + "|" + ([string]$act.Execute + " " + [string]$act.Arguments)
		        }
		      }
		    } catch { }
		    Inspect-C2FEntry -Source "scheduled_task" -Name $name -Detail $detail
		  }

		  $services = @()
		  try { $services = Get-CimInstance Win32_Service -Filter "StartMode='Auto'" -ErrorAction SilentlyContinue } catch { $services = @() }
		  foreach ($svc in $services) {
		    Assert-C2FWithinBudget
		    $svcName = [string]$svc.Name
		    $svcPath = [string]$svc.PathName
		    Inspect-C2FEntry -Source "service_auto" -Name $svcName -Detail $svcPath
		  }

		  $scanStatus = if ($hits.Count -gt 0) { "MATCH" } else { "CLEAN" }
		  $summary = "Persistence hunt complete: status=" + $scanStatus + " hits=" + $hits.Count + " examined=" + $totalExamined
		  $finished = Get-Date

		  $lines = New-Object System.Collections.Generic.List[string]
		  $lines.Add("Click2Fix Persistence Hunt Report")
		  $lines.Add("Execution ID: " + $ExecId)
		  $lines.Add("Agent ID: " + $AgentId)
		  $lines.Add("Started: " + $started.ToString("o"))
		  $lines.Add("Finished: " + $finished.ToString("o"))
		  $lines.Add("Status: " + $scanStatus)
		  $lines.Add("Total Examined: " + $totalExamined)
		  $lines.Add("Matches: " + $hits.Count)
		  $lines.Add("")
		  if ($hits.Count -gt 0) {
		    $lines.Add("Findings")
		    for ($i = 0; $i -lt $hits.Count; $i++) {
		      $h = $hits[$i]
		      $lines.Add(("#" + [string]($i + 1)))
		      $lines.Add(("Source: " + [string]$h.source))
		      $lines.Add(("Name: " + [string]$h.name))
		      $lines.Add(("Detail: " + [string]$h.detail))
		      $lines.Add(("Recommendation: " + [string]$h.recommendation))
		      $lines.Add("")
		    }
		  } else {
		    $lines.Add("No suspicious persistence indicators were detected.")
		  }
		  $lines.Add("")
		  $lines.Add("Summary: " + $summary)
		  Set-Content -Path $reportPath -Value $lines -Encoding UTF8

		  C2F-Evidence "scan_type=persistence"
		  C2F-Evidence "scan_scope=startup+runkeys+tasks+services"
		  C2F-Evidence "scan_engine=builtin-heuristics"
		  C2F-Evidence ("scan_report_path=" + $reportPath)
		  C2F-Evidence ("scan_total_examined=" + $totalExamined)
		  C2F-Evidence ("scan_matches=" + $hits.Count)
		  C2F-Evidence ("scan_status=" + $scanStatus)
		  C2F-Evidence ("artifact_0=report|" + $reportPath + "|format=txt")
		  for ($i = 0; $i -lt $hits.Count; $i++) {
		    $h = $hits[$i]
		    $safeName = ([string]$h.name -replace '\|','/' -replace '\r?\n',' ')
		    $safeDetail = ([string]$h.detail -replace '\|','/' -replace '\r?\n',' ')
		    if ($safeDetail.Length -gt 220) { $safeDetail = $safeDetail.Substring(0, 220) + "..." }
		    $safeRec = ([string]$h.recommendation -replace '\|','/' -replace '\r?\n',' ')
		    C2F-Evidence ("scan_hit_" + $i + "=persistence|" + $safeName + "|detail=" + $safeDetail + "|recommendation=" + $safeRec)
		  }
		  C2F-Evidence ("scan_summary=" + ($summary -replace '\|','/' -replace '\r?\n',' '))
		  C2F-Status "SUCCESS"
		  Write-Output $summary
		  Write-Output ("report=" + $reportPath)
		  exit 0
		}
		catch {
		  $err = $_.Exception.Message
		  C2F-Evidence ("error=" + $err)
		  C2F-Status "FAILED" $err
		  throw
		}
		""".strip()

        if aid in {"ioc-scan", "toc-scan"}:
            return r"""
	param(
	  [string]$ExecId = "adhoc",
	  [string]$AgentId = "",
	  [string]$ActionId = "ioc-scan",
	  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
	  [string]$IocSet = "default"
	)

	$ErrorActionPreference = "Stop"
	$ProgressPreference = "SilentlyContinue"

	function Write-C2FLogLine {
	  param([string]$Line)
	  try {
	    $dir = Split-Path -Parent $LogFile
	    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
	    Add-Content -Path $LogFile -Value $Line
	  } catch { }
	}

	if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
	  function C2F-Evidence {
	    param([string]$Message)
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
	    } catch { }
	  }
	}

	if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
	  function C2F-Status {
	    param([string]$Status, [string]$Message = "")
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
	      if ($Message) {
	        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
	        $line = $line + " message=" + $clean
	      }
	      Write-C2FLogLine $line
	    } catch { }
	  }
	}

	try {
	  C2F-Status "START"
	  $reportDir = "C:\Click2Fix\reports"
	  New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
	  $isToc = (([string]$ActionId).ToLower() -eq "toc-scan")
	  $scanPrefix = if ($isToc) { "toc-scan" } else { "ioc-scan" }
	  $scanType = if ($isToc) { "toc" } else { "ioc" }
	  $scanLabel = if ($isToc) { "TOC" } else { "IOC" }
	  $reportPath = Join-Path $reportDir ($scanPrefix + "-" + $ExecId + ".txt")
	  $scanStarted = Get-Date
	  $patterns = @(
	    "powershell -enc",
	    "cmd.exe /c",
	    "rundll32",
	    "regsvr32",
	    "mimikatz",
	    "cobalt strike",
	    "bitsadmin",
	    "certutil -urlcache"
	  )
	  $hits = @()
	  $processes = @()
	  try {
	    $processes = Get-CimInstance Win32_Process -ErrorAction Stop
	  } catch {
	    $processes = @()
	  }
	  $totalExamined = [int]$processes.Count
	  foreach ($proc in $processes) {
	    $cmd = [string]$proc.CommandLine
	    if (-not $cmd) { continue }
	    $cmdLow = $cmd.ToLower()
	    foreach ($pat in $patterns) {
	      $patLow = [string]$pat
	      if ($cmdLow.Contains($patLow.ToLower())) {
	        $recommendation = "Review process context and terminate/quarantine if unauthorized."
	        switch -Regex ($patLow.ToLower()) {
	          "powershell -enc|base64" { $recommendation = "Decode and inspect the command, then block malicious script execution via AppLocker or Defender ASR."; break }
	          "mimikatz|cobalt strike" { $recommendation = "Isolate endpoint immediately, rotate credentials, and collect memory for credential theft triage."; break }
	          "rundll32|regsvr32" { $recommendation = "Validate DLL/script origin, block signed-binary proxy execution abuse, and quarantine suspicious binaries."; break }
	          "certutil -urlcache|bitsadmin" { $recommendation = "Investigate potential download cradles, block outbound IOC domains/IPs, and remove dropped payloads."; break }
	        }
	        $hits += @{
	          "type" = "process"
	          "pattern" = [string]$pat
	          "process" = [string]$proc.Name
	          "pid" = [int]$proc.ProcessId
	          "command" = $cmd
	          "recommendation" = $recommendation
	        }
	        break
	      }
	    }
	  }
	  $maxHits = 100
	  if ($hits.Count -gt $maxHits) {
	    $hits = @($hits | Select-Object -First $maxHits)
	  }
	  $scanFinished = Get-Date
	  $scanStatus = if ($hits.Count -gt 0) { "MATCH" } else { "CLEAN" }
	  $summary = ($scanLabel + " scan complete: status=" + $scanStatus + " matches=" + $hits.Count + " examined=" + $totalExamined + " set=" + $IocSet)
	  $reportLines = New-Object System.Collections.Generic.List[string]
	  $reportLines.Add("Click2Fix " + $scanLabel + " Scan Report")
	  $reportLines.Add("Execution ID: " + $ExecId)
	  $reportLines.Add("Agent ID: " + $AgentId)
	  $reportLines.Add("Started: " + $scanStarted.ToString("o"))
	  $reportLines.Add("Finished: " + $scanFinished.ToString("o"))
	  $reportLines.Add("Scope: " + $IocSet)
	  $reportLines.Add("Engine: builtin-patterns")
	  $reportLines.Add("Status: " + $scanStatus)
	  $reportLines.Add("Total Examined: " + $totalExamined)
	  $reportLines.Add("Matches: " + $hits.Count)
	  $reportLines.Add("")
	  if ($hits.Count -gt 0) {
	    $reportLines.Add("Findings")
	    for ($i = 0; $i -lt $hits.Count; $i++) {
	      $h = $hits[$i]
	      $reportLines.Add(("#" + ($i + 1)))
	      $reportLines.Add(("Pattern: " + [string]$h.pattern))
	      $reportLines.Add(("Process: " + [string]$h.process + " (PID " + [string]$h.pid + ")"))
	      $reportLines.Add(("Command: " + [string]$h.command))
	      $reportLines.Add(("Recommendation: " + [string]$h.recommendation))
	      $reportLines.Add("")
	    }
	  } else {
	    $reportLines.Add("No suspicious process indicators were matched.")
	  }
	  $reportLines.Add("")
	  $reportLines.Add("Summary: " + $summary)
	  Set-Content -Path $reportPath -Value $reportLines -Encoding UTF8
	  C2F-Evidence ("scan_type=" + $scanType)
	  C2F-Evidence ("scan_scope=" + $IocSet)
	  C2F-Evidence "scan_engine=builtin-patterns"
	  C2F-Evidence ("scan_report_path=" + $reportPath)
	  C2F-Evidence ("scan_total_examined=" + $totalExamined)
	  C2F-Evidence ("scan_matches=" + $hits.Count)
	  C2F-Evidence ("scan_status=" + $scanStatus)
	  C2F-Evidence ("artifact_0=report|" + $reportPath + "|format=txt")
	  for ($i = 0; $i -lt $hits.Count; $i++) {
	    $h = $hits[$i]
	    $safeDetail = [string]$h.command
	    if ($safeDetail.Length -gt 220) { $safeDetail = $safeDetail.Substring(0, 220) + "..." }
	    $safeDetail = $safeDetail -replace '\|','/' -replace '\r?\n',' '
	    $safeRecommendation = ([string]$h.recommendation -replace '\|','/' -replace '\r?\n',' ')
	    C2F-Evidence ("scan_hit_" + $i + "=" + $scanType + "|" + [string]$h.pattern + "|process=" + [string]$h.process + "|pid=" + [string]$h.pid + "|detail=" + $safeDetail + "|recommendation=" + $safeRecommendation)
	  }
	  C2F-Evidence ("scan_summary=" + ($summary -replace '\|','/' -replace '\r?\n',' '))
	  C2F-Status "SUCCESS"
	  Write-Output $summary
	  Write-Output ("report=" + $reportPath)
	  exit 0
	}
	catch {
	  $err = $_.Exception.Message
	  C2F-Evidence ("error=" + $err)
	  C2F-Status "FAILED" $err
	  throw
	}
	""".strip()

        if aid == "yara-scan":
            return r"""
	param(
	  [string]$ExecId = "adhoc",
	  [string]$AgentId = "",
	  [string]$ActionId = "yara-scan",
	  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
	  [string]$ScanPath = ""
	)

	$ErrorActionPreference = "Stop"
	$ProgressPreference = "SilentlyContinue"

	function Write-C2FLogLine {
	  param([string]$Line)
	  try {
	    $dir = Split-Path -Parent $LogFile
	    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
	    Add-Content -Path $LogFile -Value $Line
	  } catch { }
	}

	if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
	  function C2F-Evidence {
	    param([string]$Message)
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
	    } catch { }
	  }
	}

	if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
	  function C2F-Status {
	    param([string]$Status, [string]$Message = "")
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
	      if ($Message) {
	        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
	        $line = $line + " message=" + $clean
	      }
	      Write-C2FLogLine $line
	    } catch { }
	  }
	}

	try {
	  C2F-Status "START"
	  if (-not $ScanPath) { throw "yara-scan requires path argument" }
	  if (-not (Test-Path $ScanPath)) { throw ("scan path not found: " + $ScanPath) }
	  $reportDir = "C:\Click2Fix\reports"
	  New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
	  $reportPath = Join-Path $reportDir ("yara-scan-" + $ExecId + ".txt")
	  $scanStarted = Get-Date
	  $patterns = @{
	    "SuspiciousEncodedPowerShell" = "powershell -enc"
	    "MimikatzKeyword" = "mimikatz"
	    "Rundll32Keyword" = "rundll32"
	    "CertutilDownload" = "certutil -urlcache"
	    "Base64Decode" = "base64 -d"
	  }
	  $files = @()
	  try {
	    $files = Get-ChildItem -Path $ScanPath -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 500
	  } catch {
	    $files = @()
	  }
	  $hits = @()
	  $totalExamined = [int]$files.Count
	  foreach ($f in $files) {
	    if ($f.Length -gt 5242880) { continue }
	    $content = ""
	    try {
	      $content = Get-Content -Path $f.FullName -Raw -ErrorAction Stop
	    } catch {
	      $content = ""
	    }
	    if (-not $content) { continue }
	    $contentLow = $content.ToLower()
	    foreach ($k in $patterns.Keys) {
	      $needle = [string]$patterns[$k]
	      if (-not $needle) { continue }
	      if ($contentLow.Contains($needle.ToLower())) {
	        $recommendation = "Review file immediately and quarantine if untrusted."
	        switch -Regex ([string]$k) {
	          "SuspiciousEncodedPowerShell" { $recommendation = "Inspect script payload, decode encoded content, and block malicious PowerShell execution."; break }
	          "MimikatzKeyword" { $recommendation = "Treat as credential theft risk: isolate host, reset credentials, and collect memory artifacts."; break }
	          "Rundll32Keyword" { $recommendation = "Validate DLL origin/signature and block LOLBin abuse through policy controls."; break }
	          "CertutilDownload|Base64Decode" { $recommendation = "Investigate staged payload delivery and remove dropped files plus persistence artifacts."; break }
	        }
	        $hits += @{
	          "rule" = [string]$k
	          "file" = [string]$f.FullName
	          "needle" = $needle
	          "recommendation" = $recommendation
	        }
	        break
	      }
	    }
	  }
	  $maxHits = 100
	  if ($hits.Count -gt $maxHits) {
	    $hits = @($hits | Select-Object -First $maxHits)
	  }
	  $scanFinished = Get-Date
	  $scanStatus = if ($hits.Count -gt 0) { "MATCH" } else { "CLEAN" }
	  $summary = ("YARA scan complete: status=" + $scanStatus + " matches=" + $hits.Count + " examined=" + $totalExamined + " path=" + $ScanPath)
	  $reportLines = New-Object System.Collections.Generic.List[string]
	  $reportLines.Add("Click2Fix YARA Scan Report")
	  $reportLines.Add("Execution ID: " + $ExecId)
	  $reportLines.Add("Agent ID: " + $AgentId)
	  $reportLines.Add("Started: " + $scanStarted.ToString("o"))
	  $reportLines.Add("Finished: " + $scanFinished.ToString("o"))
	  $reportLines.Add("Path: " + $ScanPath)
	  $reportLines.Add("Engine: builtin-patterns")
	  $reportLines.Add("Status: " + $scanStatus)
	  $reportLines.Add("Total Examined: " + $totalExamined)
	  $reportLines.Add("Matches: " + $hits.Count)
	  $reportLines.Add("")
	  if ($hits.Count -gt 0) {
	    $reportLines.Add("Findings")
	    for ($i = 0; $i -lt $hits.Count; $i++) {
	      $h = $hits[$i]
	      $reportLines.Add(("#" + ($i + 1)))
	      $reportLines.Add(("Rule: " + [string]$h.rule))
	      $reportLines.Add(("File: " + [string]$h.file))
	      $reportLines.Add(("Matched String: " + [string]$h.needle))
	      $reportLines.Add(("Recommendation: " + [string]$h.recommendation))
	      $reportLines.Add("")
	    }
	  } else {
	    $reportLines.Add("No YARA indicator matches were detected.")
	  }
	  $reportLines.Add("")
	  $reportLines.Add("Summary: " + $summary)
	  Set-Content -Path $reportPath -Value $reportLines -Encoding UTF8
	  C2F-Evidence "scan_type=yara"
	  C2F-Evidence ("scan_scope=" + $ScanPath)
	  C2F-Evidence "scan_engine=builtin-patterns"
	  C2F-Evidence ("scan_report_path=" + $reportPath)
	  C2F-Evidence ("scan_total_examined=" + $totalExamined)
	  C2F-Evidence ("scan_matches=" + $hits.Count)
	  C2F-Evidence ("scan_status=" + $scanStatus)
	  C2F-Evidence ("artifact_0=report|" + $reportPath + "|format=txt")
	  for ($i = 0; $i -lt $hits.Count; $i++) {
	    $h = $hits[$i]
	    $safeDetail = ([string]$h.file -replace '\|','/' -replace '\r?\n',' ')
	    $safeRecommendation = ([string]$h.recommendation -replace '\|','/' -replace '\r?\n',' ')
	    C2F-Evidence ("scan_hit_" + $i + "=yara|" + [string]$h.rule + "|file=" + $safeDetail + "|detail=needle:" + [string]$h.needle + "|recommendation=" + $safeRecommendation)
	  }
	  C2F-Evidence ("scan_summary=" + ($summary -replace '\|','/' -replace '\r?\n',' '))
	  C2F-Status "SUCCESS"
	  Write-Output $summary
	  Write-Output ("report=" + $reportPath)
	  exit 0
	}
	catch {
	  $err = $_.Exception.Message
	  C2F-Evidence ("error=" + $err)
	  C2F-Status "FAILED" $err
	  throw
	}
	""".strip()

        if aid == "collect-forensics":
            return r"""
	param(
	  [string]$ExecId = "adhoc",
	  [string]$AgentId = "",
	  [string]$ActionId = "collect-forensics",
	  [string]$LogFile = "C:\Click2Fix\logs\executions.log"
	)

	$ErrorActionPreference = "Stop"
	$ProgressPreference = "SilentlyContinue"

	function Write-C2FLogLine {
	  param([string]$Line)
	  try {
	    $dir = Split-Path -Parent $LogFile
	    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
	    Add-Content -Path $LogFile -Value $Line
	  } catch { }
	}

	if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
	  function C2F-Evidence {
	    param([string]$Message)
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
	    } catch { }
	  }
	}

	if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
	  function C2F-Status {
	    param([string]$Status, [string]$Message = "")
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
	      if ($Message) {
	        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
	        $line = $line + " message=" + $clean
	      }
	      Write-C2FLogLine $line
	    } catch { }
	  }
	}

	try {
	  C2F-Status "START"
	  $reportDir = "C:\Click2Fix\reports"
	  New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
	  $reportPath = Join-Path $reportDir ("forensics-" + $ExecId + ".txt")
	  $scanStarted = Get-Date
	  $procRows = @()
	  try {
	    $procRows = Get-Process | Sort-Object CPU -Descending | Select-Object -First 80 Name,Id,CPU,WS,Path
	  } catch {
	    $procRows = @()
	  }
	  $connRows = @()
	  try {
	    $connRows = Get-NetTCPConnection -ErrorAction Stop | Select-Object -First 120 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
	  } catch {
	    $connRows = @()
	  }
	  $runKeys = @(
	    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
	    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
	  )
	  $startup = @()
	  foreach ($rk in $runKeys) {
	    if (Test-Path $rk) {
	      try {
	        $props = Get-ItemProperty -Path $rk -ErrorAction Stop
	        foreach ($p in $props.PSObject.Properties) {
	          if ($p.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
	            $startup += @{
	              "key" = $rk
	              "name" = [string]$p.Name
	              "value" = [string]$p.Value
	            }
	          }
	        }
	      } catch { }
	    }
	  }
	  $serviceRows = @()
	  try {
	    $serviceRows = Get-Service | Where-Object { $_.Status -ne "Running" } | Select-Object -First 80 Name,DisplayName,Status,StartType
	  } catch {
	    $serviceRows = @()
	  }
	  $scanFinished = Get-Date
	  $suspiciousPattern = "(powershell|cmd\.exe|wscript|cscript|rundll32|mshta|https?://|\\AppData\\Temp|\\Users\\Public\\)"
	  $suspiciousStartup = @($startup | Where-Object { ([string]$_.value) -match $suspiciousPattern } | Select-Object -First 100)
	  $scanStatus = if ($suspiciousStartup.Count -gt 0) { "MATCH" } else { "CLEAN" }
	  $summary = ("Forensics collection complete: status=" + $scanStatus + " suspicious_startup=" + $suspiciousStartup.Count + " processes=" + $procRows.Count + " connections=" + $connRows.Count + " startup_items=" + $startup.Count)
	  $reportLines = New-Object System.Collections.Generic.List[string]
	  $reportLines.Add("Click2Fix Forensics Report")
	  $reportLines.Add("Execution ID: " + $ExecId)
	  $reportLines.Add("Agent ID: " + $AgentId)
	  $reportLines.Add("Host: " + $env:COMPUTERNAME)
	  $reportLines.Add("User: " + (whoami))
	  $reportLines.Add("Started: " + $scanStarted.ToString("o"))
	  $reportLines.Add("Finished: " + $scanFinished.ToString("o"))
	  $reportLines.Add("Status: " + $scanStatus)
	  $reportLines.Add("Process Count: " + $procRows.Count)
	  $reportLines.Add("Connection Count: " + $connRows.Count)
	  $reportLines.Add("Startup Items: " + $startup.Count)
	  $reportLines.Add("Suspicious Startup Findings: " + $suspiciousStartup.Count)
	  $reportLines.Add("")
	  if ($suspiciousStartup.Count -gt 0) {
	    $reportLines.Add("Findings")
	    for ($i = 0; $i -lt $suspiciousStartup.Count; $i++) {
	      $f = $suspiciousStartup[$i]
	      $reportLines.Add(("#" + ($i + 1)))
	      $reportLines.Add(("Registry Key: " + [string]$f.key))
	      $reportLines.Add(("Entry Name: " + [string]$f.name))
	      $reportLines.Add(("Entry Value: " + [string]$f.value))
	      $reportLines.Add("Recommendation: Validate startup entry owner/publisher, disable unauthorized autoruns, and quarantine referenced binaries.")
	      $reportLines.Add("")
	    }
	  } else {
	    $reportLines.Add("No suspicious startup persistence indicators were detected.")
	    $reportLines.Add("")
	  }
	  $reportLines.Add("Top Processes (CPU)")
	  foreach ($p in ($procRows | Select-Object -First 40)) {
	    $reportLines.Add(([string]$p.Name + " PID=" + [string]$p.Id + " CPU=" + [string]$p.CPU + " WS=" + [string]$p.WS + " Path=" + [string]$p.Path))
	  }
	  $reportLines.Add("")
	  $reportLines.Add("Top TCP Connections")
	  foreach ($c in ($connRows | Select-Object -First 40)) {
	    $reportLines.Add(([string]$c.LocalAddress + ":" + [string]$c.LocalPort + " -> " + [string]$c.RemoteAddress + ":" + [string]$c.RemotePort + " state=" + [string]$c.State + " pid=" + [string]$c.OwningProcess))
	  }
	  $reportLines.Add("")
	  $reportLines.Add("Summary: " + $summary)
	  Set-Content -Path $reportPath -Value $reportLines -Encoding UTF8
	  C2F-Evidence "scan_type=forensics"
	  C2F-Evidence "scan_engine=windows-native"
	  C2F-Evidence ("scan_report_path=" + $reportPath)
	  C2F-Evidence ("scan_total_examined=" + ($procRows.Count + $connRows.Count + $startup.Count))
	  C2F-Evidence ("scan_matches=" + $suspiciousStartup.Count)
	  C2F-Evidence ("scan_status=" + $scanStatus)
	  C2F-Evidence ("artifact_0=report|" + $reportPath + "|format=txt")
	  for ($i = 0; $i -lt $suspiciousStartup.Count; $i++) {
	    $h = $suspiciousStartup[$i]
	    $safeDetail = ([string]$h.value -replace '\|','/' -replace '\r?\n',' ')
	    if ($safeDetail.Length -gt 220) { $safeDetail = $safeDetail.Substring(0, 220) + "..." }
	    C2F-Evidence ("scan_hit_" + $i + "=forensics|" + [string]$h.name + "|detail=" + $safeDetail + "|recommendation=Validate startup entry owner, disable unauthorized autorun, and quarantine referenced binaries.")
	  }
	  C2F-Evidence ("scan_summary=" + ($summary -replace '\|','/' -replace '\r?\n',' '))
	  C2F-Status "SUCCESS"
	  Write-Output $summary
	  Write-Output ("report=" + $reportPath)
	  exit 0
	}
	catch {
	  $err = $_.Exception.Message
	  C2F-Evidence ("error=" + $err)
	  C2F-Status "FAILED" $err
	  throw
	}
	""".strip()

        if aid == "collect-memory":
            return r"""
		param(
		  [string]$ExecId = "adhoc",
	  [string]$AgentId = "",
	  [string]$ActionId = "collect-memory",
	  [string]$LogFile = "C:\Click2Fix\logs\executions.log"
	)

	$ErrorActionPreference = "Stop"
	$ProgressPreference = "SilentlyContinue"

	function Write-C2FLogLine {
	  param([string]$Line)
	  try {
	    $dir = Split-Path -Parent $LogFile
	    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
	    Add-Content -Path $LogFile -Value $Line
	  } catch { }
	}

	if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
	  function C2F-Evidence {
	    param([string]$Message)
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
	    } catch { }
	  }
	}

	if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
	  function C2F-Status {
	    param([string]$Status, [string]$Message = "")
	    try {
	      $ts = Get-Date -Format o
	      $u = whoami
	      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
	      if ($Message) {
	        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
	        $line = $line + " message=" + $clean
	      }
	      Write-C2FLogLine $line
	    } catch { }
	  }
	}

	try {
	  C2F-Status "START"
	  $reportDir = "C:\Click2Fix\reports"
	  New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
	  $reportPath = Join-Path $reportDir ("memory-" + $ExecId + ".txt")
	  $scanStarted = Get-Date
	  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
	  $top = @()
	  try {
	    $top = Get-Process | Sort-Object WS -Descending | Select-Object -First 60 Name,Id,@{N='WorkingSetMB';E={[math]::Round(($_.WS/1MB),2)}},@{N='PrivateMemoryMB';E={[math]::Round(($_.PM/1MB),2)}}
	  } catch {
	    $top = @()
	  }
	  $scanFinished = Get-Date
	  $totalMb = 0
	  $freeMb = 0
	  if ($os) {
	    $totalMb = [math]::Round(([double]$os.TotalVisibleMemorySize / 1024), 2)
	    $freeMb = [math]::Round(([double]$os.FreePhysicalMemory / 1024), 2)
	  }
	  $suspicious = @()
	  foreach ($p in $top) {
	    $name = ([string]$p.Name).ToLower()
	    $wsMb = 0.0
	    try { $wsMb = [double]$p.WorkingSetMB } catch { $wsMb = 0.0 }
	    $isSuspiciousName = $name -match "(powershell|rundll32|wscript|cscript|mshta|mimikatz)"
	    $isHighMemory = $wsMb -ge 1200
	    if ($isSuspiciousName -or $isHighMemory) {
	      $reasons = @()
	      if ($isSuspiciousName) { $reasons += "suspicious_process_name" }
	      if ($isHighMemory) { $reasons += "high_working_set_mb" }
	      $suspicious += @{
	        "name" = [string]$p.Name
	        "pid" = [string]$p.Id
	        "working_set_mb" = [string]$p.WorkingSetMB
	        "private_mb" = [string]$p.PrivateMemoryMB
	        "reason" = [string]::Join(",", $reasons)
	        "recommendation" = "Inspect process lineage/command-line; if malicious, terminate process and collect memory image."
	      }
	    }
	  }
	  if ($suspicious.Count -gt 80) {
	    $suspicious = @($suspicious | Select-Object -First 80)
	  }
	  $scanStatus = if ($suspicious.Count -gt 0) { "MATCH" } else { "CLEAN" }
	  $summary = ("Memory collection complete: status=" + $scanStatus + " total_mb=" + $totalMb + " free_mb=" + $freeMb + " top_processes=" + $top.Count + " suspicious=" + $suspicious.Count)
	  $reportLines = New-Object System.Collections.Generic.List[string]
	  $reportLines.Add("Click2Fix Memory Report")
	  $reportLines.Add("Execution ID: " + $ExecId)
	  $reportLines.Add("Agent ID: " + $AgentId)
	  $reportLines.Add("Host: " + $env:COMPUTERNAME)
	  $reportLines.Add("User: " + (whoami))
	  $reportLines.Add("Started: " + $scanStarted.ToString("o"))
	  $reportLines.Add("Finished: " + $scanFinished.ToString("o"))
	  $reportLines.Add("Status: " + $scanStatus)
	  $reportLines.Add("Total Memory (MB): " + $totalMb)
	  $reportLines.Add("Free Memory (MB): " + $freeMb)
	  $reportLines.Add("Top Processes Count: " + $top.Count)
	  $reportLines.Add("Suspicious Process Findings: " + $suspicious.Count)
	  $reportLines.Add("")
	  if ($suspicious.Count -gt 0) {
	    $reportLines.Add("Findings")
	    for ($i = 0; $i -lt $suspicious.Count; $i++) {
	      $h = $suspicious[$i]
	      $reportLines.Add(("#" + ($i + 1)))
	      $reportLines.Add(("Process: " + [string]$h.name + " (PID " + [string]$h.pid + ")"))
	      $reportLines.Add(("Working Set MB: " + [string]$h.working_set_mb + " | Private MB: " + [string]$h.private_mb))
	      $reportLines.Add(("Reason: " + [string]$h.reason))
	      $reportLines.Add(("Recommendation: " + [string]$h.recommendation))
	      $reportLines.Add("")
	    }
	  } else {
	    $reportLines.Add("No suspicious memory/process indicators were detected.")
	    $reportLines.Add("")
	  }
	  $reportLines.Add("Top Processes")
	  foreach ($p in $top) {
	    $reportLines.Add(([string]$p.Name + " PID=" + [string]$p.Id + " WS_MB=" + [string]$p.WorkingSetMB + " PM_MB=" + [string]$p.PrivateMemoryMB))
	  }
	  $reportLines.Add("")
	  $reportLines.Add("Summary: " + $summary)
	  Set-Content -Path $reportPath -Value $reportLines -Encoding UTF8
	  C2F-Evidence "scan_type=memory"
	  C2F-Evidence "scan_engine=windows-native"
	  C2F-Evidence ("scan_report_path=" + $reportPath)
	  C2F-Evidence ("scan_total_examined=" + $top.Count)
	  C2F-Evidence ("scan_matches=" + $suspicious.Count)
	  C2F-Evidence ("scan_status=" + $scanStatus)
	  C2F-Evidence ("artifact_0=report|" + $reportPath + "|format=txt")
	  for ($i = 0; $i -lt $suspicious.Count; $i++) {
	    $h = $suspicious[$i]
	    $detail = ("reason=" + [string]$h.reason + ";ws_mb=" + [string]$h.working_set_mb + ";private_mb=" + [string]$h.private_mb) -replace '\|','/' -replace '\r?\n',' '
	    C2F-Evidence ("scan_hit_" + $i + "=memory|" + [string]$h.name + "|pid=" + [string]$h.pid + "|detail=" + $detail + "|recommendation=" + [string]$h.recommendation)
	  }
	  C2F-Evidence ("scan_summary=" + ($summary -replace '\|','/' -replace '\r?\n',' '))
	  C2F-Status "SUCCESS"
	  Write-Output $summary
	  Write-Output ("report=" + $reportPath)
	  exit 0
	}
	catch {
	  $err = $_.Exception.Message
	  C2F-Evidence ("error=" + $err)
	  C2F-Status "FAILED" $err
	  throw
		}
		""".strip()

        if aid == "hash-blocklist":
            return r"""
		param(
		  [string]$ExecId = "adhoc",
		  [string]$AgentId = "",
		  [string]$ActionId = "hash-blocklist",
		  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
		  [string]$Sha256Hash = ""
		)

		$ErrorActionPreference = "Stop"
		$ProgressPreference = "SilentlyContinue"

		function Write-C2FLogLine {
		  param([string]$Line)
		  try {
		    $dir = Split-Path -Parent $LogFile
		    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
		    Add-Content -Path $LogFile -Value $Line
		  } catch { }
		}

		if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
		  function C2F-Evidence {
		    param([string]$Message)
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
		    } catch { }
		  }
		}

		if (-not (Get-Command C2F-Status -ErrorAction SilentlyContinue)) {
		  function C2F-Status {
		    param([string]$Status, [string]$Message = "")
		    try {
		      $ts = Get-Date -Format o
		      $u = whoami
		      $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
		      if ($Message) {
		        $clean = $Message.Replace("`r", " ").Replace("`n", " ")
		        $line = $line + " message=" + $clean
		      }
		      Write-C2FLogLine $line
		    } catch { }
		  }
		}

		try {
		  C2F-Status "START"
		  $hash = ([string]$Sha256Hash).Trim().ToLower()
		  if (-not $hash -or $hash -notmatch '^[a-f0-9]{64}$') {
		    throw "hash-blocklist requires valid SHA256 hash"
		  }

		  $baseDir = "C:\Click2Fix\blocklist"
		  New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
		  $listPath = Join-Path $baseDir "sha256.txt"

		  $already = $false
		  if (Test-Path $listPath) {
		    try {
		      $already = [bool](Get-Content -Path $listPath -ErrorAction SilentlyContinue | Where-Object { ([string]$_).Trim().ToLower() -eq $hash } | Select-Object -First 1)
		    } catch { $already = $false }
		  }
		  if (-not $already) {
		    Add-Content -Path $listPath -Value $hash
		  }

		  $count = 0
		  try {
		    $count = [int]((Get-Content -Path $listPath -ErrorAction SilentlyContinue | Where-Object { ([string]$_).Trim() -ne "" } | Measure-Object).Count)
		  } catch {
		    $count = if ($already) { 1 } else { 0 }
		  }
		  $state = if ($already) { "EXISTS" } else { "ADDED" }
		  $summary = if ($already) { "Hash already present in blocklist: " + $hash } else { "Hash added to blocklist: " + $hash }

		  C2F-Evidence ("blocklist_hash=" + $hash)
		  C2F-Evidence ("blocklist_path=" + $listPath)
		  C2F-Evidence ("blocklist_entry_count=" + $count)
		  C2F-Evidence ("blocklist_status=" + $state)
		  C2F-Status "SUCCESS"
		  Write-Output $summary
		  Write-Output ("blocklist=" + $listPath)
		  exit 0
		}
		catch {
		  $err = $_.Exception.Message
		  C2F-Evidence ("error=" + $err)
		  C2F-Status "FAILED" $err
		  throw
		}
		""".strip()

        # Runs either:
        # - directly inside the wrapper PS session (C2F-Evidence already defined), or
        # - standalone (scheduled task as SYSTEM) with explicit parameters.
        return r"""
		param(
		  [string]$ExecId = "adhoc",
		  [string]$AgentId = "",
		  [string]$ActionId = "patch-windows",
		  [string]$LogFile = "C:\Click2Fix\logs\executions.log",
		  [string]$ResultFile = "",
		  [int]$MaxRuntimeSeconds = 3600
		)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-C2FLogLine {
  param([string]$Line)
  try {
    $dir = Split-Path -Parent $LogFile
    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $Line
  } catch { }
}

if (-not (Get-Command C2F-Evidence -ErrorAction SilentlyContinue)) {
  function C2F-Evidence {
    param([string]$Message)
    try {
      $ts = Get-Date -Format o
      $u = whoami
      Write-C2FLogLine ($ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " evidence=" + $Message)
    } catch { }
  }
}

function C2F-Status {
  param([string]$Status, [string]$Message = "")
  try {
    $ts = Get-Date -Format o
    $u = whoami
    $line = $ts + " exec=" + $ExecId + " agent=" + $AgentId + " action=" + $ActionId + " user=" + $u + " status=" + $Status
    if ($Message) {
      $clean = $Message.Replace("`r", " ").Replace("`n", " ")
      $line = $line + " message=" + $clean
    }
    Write-C2FLogLine $line
  } catch { }
}

	if (-not $ResultFile) {
	  $ResultFile = Join-Path "C:\Click2Fix\results" ("patch-windows-" + $ExecId + ".json")
	}

	function Write-Result {
	  param([bool]$Ok, [hashtable]$Payload)
	  if (-not $ResultFile) { return }
	  try {
	    $dir = Split-Path -Parent $ResultFile
    if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $ResultFile) { Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue }
    $obj = @{"ok" = $Ok }
    if ($Payload) {
      foreach ($k in $Payload.Keys) { $obj[$k] = $Payload[$k] }
    }
    $obj | ConvertTo-Json -Depth 6 | Set-Content -Path $ResultFile -Encoding UTF8
  } catch { }
}

$summary = ""
$rebootScheduled = $false
$controlDir = "C:\Click2Fix\control"
try { New-Item -ItemType Directory -Path $controlDir -Force | Out-Null } catch { }
$rebootFlag = Join-Path $controlDir ("reboot-scheduled-" + $ExecId + ".flag")

try {
  C2F-Status "START"

	$cv=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
	$build=$cv.CurrentBuildNumber; if(-not $build){ $build=$cv.CurrentBuild }
	$ubr=$cv.UBR; if($ubr -eq $null){ $ubr='' }
	$disp=$cv.DisplayVersion; if(-not $disp){ $disp=$cv.ReleaseId }
	C2F-Evidence ("os_version=" + $disp)
	C2F-Evidence ("os_build=" + $build + "." + $ubr)

function Read-C2FReg {
  param([string]$Path, [string]$Name)
  try {
    $v = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($v -eq $null) { return "" }
    return [string]$v
  } catch { return "" }
}

$wsusServer = Read-C2FReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
$wuStatusServer = Read-C2FReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUStatusServer'
$useWUServer = Read-C2FReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'UseWUServer'
$pauseEnd = Read-C2FReg 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesEndTime'
if($wsusServer){ C2F-Evidence ("wsus_server=" + $wsusServer) }
if($wuStatusServer){ C2F-Evidence ("wsus_status_server=" + $wuStatusServer) }
if($useWUServer){ C2F-Evidence ("wsus_enabled=" + $useWUServer) }
if($pauseEnd){ C2F-Evidence ("pause_updates_end=" + $pauseEnd) }

function Ensure-C2FPSWindowsUpdateModule {
  try {
    $m = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($m) {
      try { Import-Module -Name PSWindowsUpdate -ErrorAction SilentlyContinue | Out-Null } catch { }
      C2F-Evidence ("pswindowsupdate_module=present|" + [string]$m.Version)
      return $true
    }
  } catch { }
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  } catch { }
  try {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue | Out-Null
  } catch { }
  try {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null
  } catch { }
  try {
    Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force -AllowClobber -Confirm:$false -ErrorAction Stop | Out-Null
    Import-Module -Name PSWindowsUpdate -ErrorAction SilentlyContinue | Out-Null
    $m2 = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($m2) {
      C2F-Evidence ("pswindowsupdate_module=installed|" + [string]$m2.Version)
      return $true
    }
  } catch {
    $msg = ($_.Exception.Message -replace '\r?\n',' ' -replace '\|','/').Trim()
    C2F-Evidence ("pswindowsupdate_module=install_failed|" + $msg)
  }
  C2F-Evidence "pswindowsupdate_module=unavailable"
  return $false
}

$pswuReady = Ensure-C2FPSWindowsUpdateModule
C2F-Evidence ("pswindowsupdate_module_ready=" + $pswuReady)

$buildNum = 0
try { $buildNum = [int]$build } catch { $buildNum = 0 }
$ubrNum = 0
try { $ubrNum = [int]$ubr } catch { $ubrNum = 0 }
$dispText = [string]$disp
$isWin10_22H2 = (($buildNum -eq 19045) -and ($dispText -match '(?i)22H2'))
$baselineTargetKb = "5075912"
$baselineMinBuild = 19045
$baselineMinUbr = 6937
$baselineRequired = $isWin10_22H2
$baselineMetBefore = ((-not $baselineRequired) -or (($buildNum -gt $baselineMinBuild) -or (($buildNum -eq $baselineMinBuild) -and ($ubrNum -ge $baselineMinUbr)))
)
C2F-Evidence ("baseline_required=" + $baselineRequired)
C2F-Evidence ("baseline_target_kb=KB" + $baselineTargetKb)
C2F-Evidence ("baseline_min_build=" + $baselineMinBuild + "." + $baselineMinUbr)
C2F-Evidence ("baseline_met_before=" + $baselineMetBefore)
$baselineDirectAttempted = $false
$baselineDirectQueryCount = 0
$baselineDirectInstalled = $false
$baselineDirectReason = ""
$baselineDirectError = ""

function Get-C2FESUStatus {
  $raw = ""
  try {
    $slmgr = Join-Path $env:SystemRoot 'System32\slmgr.vbs'
    if (Test-Path $slmgr) {
      $raw = (& cscript.exe //Nologo $slmgr /dlv 2>&1 | Out-String)
    }
  } catch { $raw = "" }
  $flat = ($raw -replace '\r?\n',' ' -replace '\s+',' ').Trim()
  $hasMarker = $false
  $licensed = $false
  if ($flat) {
    if ($flat -match '(?i)(extended security updates|esu)') { $hasMarker = $true }
    if ($flat -match '(?i)(license status:\s*licensed|status:\s*licensed)') { $licensed = $true }
  }
  return @{
    "checked" = [bool]($flat)
    "has_marker" = $hasMarker
    "licensed" = $licensed
    "raw" = $flat
  }
}

$esu = Get-C2FESUStatus
$esuChecked = [bool]$esu.checked
$esuHasMarker = [bool]$esu.has_marker
$esuEnrolled = [bool]$esu.licensed
C2F-Evidence ("esu_check=" + $esuChecked + "|marker=" + $esuHasMarker + "|enrolled=" + $esuEnrolled)

if($baselineRequired -and (-not $esuEnrolled)){
  $summary = "Unpatchable - ESU Required"
  $errText = "Unpatchable - ESU Required: Windows 10 22H2 endpoint is not enrolled for Extended Security Updates."
  C2F-Evidence ("error=" + $errText)
  Write-Output $summary
  Write-Result $false @{
    "summary" = $summary
    "outcome" = "FAILED"
    "error" = $errText
    "update_profile" = "Standard-Cumulative"
    "updates_discovered" = 0
    "updates_applicable" = 0
    "updates_installable" = 0
    "updates_skipped_interactive" = 0
    "updates_skipped_non_target" = 0
    "updates_installed" = 0
    "updates_failed" = 0
    "updates_remaining" = 0
    "updates_remaining_total" = 0
    "os_build_before" = ($build + "." + $ubr)
    "os_build_after" = ($build + "." + $ubr)
    "esu_required" = $true
    "esu_enrolled" = $false
    "baseline_required" = $baselineRequired
    "baseline_target_kb" = ("KB" + $baselineTargetKb)
    "baseline_met" = $false
  }
  C2F-Status "FAILED" $errText
  exit 0
}

$actionKey = ([string]$ActionId).ToLowerInvariant()
$osOnlyMode = ($actionKey -eq "windows-os-update")
$updateProfile = if($osOnlyMode) { "Standard-Cumulative" } else { "fleet" }
C2F-Evidence ("update_profile=" + $updateProfile)

function Get-C2FCategoryNames {
  param($Update)
  $names = New-Object System.Collections.Generic.List[string]
  try {
    if ($Update -and $Update.Categories) {
      for ($ci = 0; $ci -lt $Update.Categories.Count; $ci++) {
        try {
          $name = [string]$Update.Categories.Item($ci).Name
          if ($name) { [void]$names.Add($name) }
        } catch { }
      }
    }
  } catch { }
  return [string]::Join(";", $names.ToArray())
}

		function Test-C2FIsTargetWindowsUpdate {
		  param(
		    $Update,
		    [bool]$RequireBuildAdvancement = $false
		  )
	  if (-not $Update) { return $false }
	  $title = ""
	  try { $title = [string]$Update.Title } catch { $title = "" }
  $cats = Get-C2FCategoryNames -Update $Update
  $blob = ($title + " " + $cats).ToLowerInvariant()
  $catsLower = [string]$cats
  if ($catsLower) { $catsLower = $catsLower.ToLowerInvariant() }
  if (-not $blob) { return $false }

	  $excludeMarkers = @(
	    "driver",
	    "firmware",
	    "preview",
	    "windows subsystem for linux",
	    " wsl ",
	    "definition update",
	    "definition updates",
	    "security intelligence update",
	    "microsoft defender antivirus",
	    "defender antivirus"
	  )
	  foreach ($marker in $excludeMarkers) {
	    if ($blob -like ("*" + $marker + "*")) { return $false }
	  }

	  $hasKb = ($blob -match '\bkb\d{4,8}\b')
	  $isWindowsTitle = ($blob -like "*windows 10*" -or $blob -like "*windows 11*" -or $blob -like "*for windows server*")
	  $isCategoryTarget = ($catsLower -like "*security updates*" -or $catsLower -like "*critical updates*" -or $catsLower -like "*update rollups*" -or $catsLower -like "*updates*")
	  $isBuildBearing = (
	    $blob -like "*cumulative update*" -or
	    $blob -like "*monthly quality rollup*" -or
	    $blob -like "*quality update*" -or
	    $blob -like "*servicing stack*" -or
	    $blob -like "*security update for windows*"
	  )

	  if ($RequireBuildAdvancement) {
	    if ($blob -like "*.net*" -or $blob -like "*dotnet*") { return $false }
	    if ($isBuildBearing -and $isWindowsTitle) { return $true }
	    if ($hasKb -and $isWindowsTitle -and $isCategoryTarget) { return $true }
	    return $false
	  }

	  if ($isBuildBearing -and $isWindowsTitle) { return $true }
	  if ($hasKb -and ($isWindowsTitle -or $isBuildBearing)) { return $true }
		  if ($isWindowsTitle -and $isCategoryTarget) { return $true }
		  return $false
		}

		function Invoke-C2FBaselineDirectInstall {
		  param(
		    [string]$TargetKb = "",
		    [bool]$PswuReady = $false
		  )
		  $result = @{
		    "attempted" = $false
		    "query_count" = 0
		    "installed" = $false
		    "reason" = ""
		    "error" = ""
		  }
		  if (-not $PswuReady) {
		    $result["reason"] = "pswindowsupdate_unavailable"
		    return $result
		  }
		  $kbNorm = [string]$TargetKb
		  if ($kbNorm) { $kbNorm = $kbNorm.ToUpper().Replace("KB","").Trim() }
		  if (-not $kbNorm) {
		    $result["reason"] = "missing_target_kb"
		    return $result
		  }
		  $kbToken = "KB" + $kbNorm
		  $result["attempted"] = $true
		  C2F-Evidence ("baseline_direct_install_start=" + $kbToken)
		  try { Import-Module -Name PSWindowsUpdate -ErrorAction SilentlyContinue | Out-Null } catch { }
		  try { Add-WUServiceManager -MicrosoftUpdate -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { }
		  $hits = @()
		  try {
		    $hits = @(Get-WindowsUpdate -KBArticleID $kbToken -MicrosoftUpdate -IgnoreReboot -ErrorAction SilentlyContinue)
		  } catch {
		    $result["error"] = [string]$_.Exception.Message
		  }
		  $hits = @($hits | Where-Object {
		    if($_ -eq $null){ return $false }
		    $k = ""
		    $t = ""
		    try { $k = [string]$_.KB } catch { $k = "" }
		    try { $t = [string]$_.Title } catch { $t = "" }
		    return ((-not [string]::IsNullOrWhiteSpace($k)) -or (-not [string]::IsNullOrWhiteSpace($t)))
		  })
		  $hitCount = 0
		  try { $hitCount = [int]$hits.Count } catch { $hitCount = 0 }
		  $result["query_count"] = $hitCount
		  C2F-Evidence ("baseline_direct_query_count=" + $hitCount)
		  $hitEmit = 0
		  foreach ($hit in $hits) {
		    if ($hitEmit -ge 10) { break }
		    $hitKb = ""
		    $hitTitle = ""
		    $hitCats = ""
		    $hitCanInput = ""
		    try { $hitKb = [string]$hit.KB } catch { $hitKb = "" }
		    try { $hitTitle = [string]$hit.Title } catch { $hitTitle = "" }
		    try {
		      if ($hit.Categories) {
		        $names = @()
		        foreach ($hc in $hit.Categories) { try { $names += [string]$hc.Name } catch { } }
		        $hitCats = [string]::Join(";", $names)
		      }
		    } catch { $hitCats = "" }
		    try { $hitCanInput = [string]$hit.CanRequestUserInput } catch { $hitCanInput = "" }
		    C2F-Evidence ("baseline_direct_query_row_" + $hitEmit + "=" + $hitKb + "|" + $hitTitle + "|categories=" + $hitCats + "|can_input=" + $hitCanInput)
		    $hitEmit++
		  }
		  $attemptOnlineInstall = ($hitCount -gt 0)
		  if ($hitCount -le 0 -and (-not $result["error"])) {
		    $result["reason"] = "kb_not_listed"
		  }
		  $installRows = @()
		  if ($attemptOnlineInstall) {
		    try {
		      $installRows = @(Get-WindowsUpdate -KBArticleID $kbToken -MicrosoftUpdate -Download -Install -AcceptAll -IgnoreReboot -AutoReboot:$false -Confirm:$false -ErrorAction SilentlyContinue)
		      if (@($installRows).Count -le 0) {
		        $installRows = @(Install-WindowsUpdate -KBArticleID $kbToken -MicrosoftUpdate -AcceptAll -IgnoreReboot -AutoReboot:$false -Confirm:$false -ErrorAction SilentlyContinue)
		      }
		    } catch {
		      $result["error"] = [string]$_.Exception.Message
		    }
		  }
		  $emit = 0
		  foreach ($row in $installRows) {
		    if ($emit -ge 10) { break }
		    $kbVal = ""
		    $titleVal = ""
		    $resultVal = ""
		    $statusVal = ""
		    $rebootVal = ""
		    $hrVal = ""
		    try { $kbVal = [string]$row.KB } catch { $kbVal = "" }
		    try { $titleVal = [string]$row.Title } catch { $titleVal = "" }
		    try { $resultVal = [string]$row.Result } catch { $resultVal = "" }
		    try { $statusVal = [string]$row.Status } catch { $statusVal = "" }
		    try { $rebootVal = [string]$row.RebootRequired } catch { $rebootVal = "" }
		    try { $hrVal = [string]$row.HResult } catch { $hrVal = "" }
		    C2F-Evidence ("baseline_direct_install_row_" + $emit + "=" + $kbVal + "|" + $titleVal + "|result=" + $resultVal + "|status=" + $statusVal + "|reboot=" + $rebootVal + "|hr=" + $hrVal)
		    $emit++
		  }
		  $installed = $false
		  try {
		    $blob = [string]($installRows | Out-String)
		    if ($blob -match '(?i)(installed|succeeded|rebootrequired)') { $installed = $true }
		  } catch { }
		  if (-not $installed) {
		    foreach ($row in $installRows) {
		      $rowText = ""
		      try { $rowText = [string]($row | Out-String) } catch { $rowText = "" }
		      if ($rowText -match '(?i)(installed|succeeded|rebootrequired)') {
		        $installed = $true
		        break
		      }
		    }
		  }
		  if (-not $installed) {
		    $offlineDir = "C:\Click2Fix\cache\offline-msu"
		    try { New-Item -ItemType Directory -Path $offlineDir -Force | Out-Null } catch { }
		    $offlineRows = @()
		    try {
		      $offlineRows = @(Get-WUOfflineMSU -KBArticleID $kbToken -Destination $offlineDir -AcceptAll -ErrorAction SilentlyContinue)
		    } catch {
		      $offlineErr = [string]$_.Exception.Message
		      if (-not $result["error"]) { $result["error"] = $offlineErr }
		      if ((-not $result["reason"]) -or ($result["reason"] -eq "kb_not_listed")) { $result["reason"] = "offline_query_failed" }
		    }
		    $offEmit = 0
		    foreach ($orow in $offlineRows) {
		      if ($offEmit -ge 10) { break }
		      $msg = ""
		      try { $msg = [string](($orow | Out-String).Trim()) } catch { $msg = "" }
		      if ($msg) { C2F-Evidence ("baseline_direct_offline_row_" + $offEmit + "=" + $msg.Replace("|","/")) }
		      $offEmit++
		    }
		    $msuPath = ""
		    try {
		      $candidate = Get-ChildItem -Path $offlineDir -Filter ("*"+$kbNorm+"*.msu") -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
		      if ($candidate) { $msuPath = [string]$candidate.FullName }
		    } catch { $msuPath = "" }
		    if ($msuPath) {
		      C2F-Evidence ("baseline_direct_offline_msu=" + $msuPath)
		      try {
		        $wusa = Join-Path $env:SystemRoot "System32\wusa.exe"
		        $proc = Start-Process -FilePath $wusa -ArgumentList @($msuPath, "/quiet", "/norestart") -PassThru -Wait -WindowStyle Hidden
		        $wusaExit = 0
		        try { $wusaExit = [int]$proc.ExitCode } catch { $wusaExit = 0 }
		        C2F-Evidence ("baseline_direct_offline_wusa_exit=" + $wusaExit)
		        if($wusaExit -eq 0 -or $wusaExit -eq 3010){
		          $installed = $true
		        } elseif (-not $result["reason"]) {
		          $result["reason"] = ("offline_wusa_exit_" + $wusaExit)
		        }
		      } catch {
		        if (-not $result["error"]) { $result["error"] = [string]$_.Exception.Message }
		      }
		    } elseif (-not $result["reason"]) {
		      $result["reason"] = "offline_msu_not_found"
		    }
		  }
		  $result["installed"] = [bool]$installed
		  if (-not $installed -and (-not $result["error"])) {
		    $result["reason"] = "install_no_success_marker"
		  }
		  return $result
		}

function Test-C2FPendingReboot {
  $paths=@(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  )
  foreach($p in $paths){ if(Test-Path $p){ return $true } }
  try{
    $pfr=Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if($pfr){ return $true }
  }catch{}
  return $false
}

$pendingBefore=Test-C2FPendingReboot
C2F-Evidence ("pending_reboot_before=" + $pendingBefore)

$svc=Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if($svc -and $svc.Status -ne 'Running'){ Start-Service wuauserv -ErrorAction SilentlyContinue }

$session=New-Object -ComObject 'Microsoft.Update.Session'
$searcher=$session.CreateUpdateSearcher()
$criterion="IsInstalled=0 and IsHidden=0"
$searchResult=$searcher.Search($criterion)
$rawUpdates=$searchResult.Updates
$rawCount=$rawUpdates.Count
C2F-Evidence ("updates_discovered=" + $rawCount)

$updates = New-Object -ComObject 'Microsoft.Update.UpdateColl'
$skippedNonTarget = 0
$skipNonTargetIdx = 0
$baselineTargetAvailable = $false
$baselineTargetApplicable = $false
for($i=0; $i -lt $rawCount; $i++){
  $uRaw=$rawUpdates.Item($i)
  $kbRaw=''
  try{ if($uRaw.KBArticleIDs -and $uRaw.KBArticleIDs.Count -gt 0){ $kbRaw=$uRaw.KBArticleIDs.Item(0) } }catch{}
  $kbNorm = [string]$kbRaw
  if ($kbNorm) { $kbNorm = $kbNorm.ToUpper().Replace("KB","").Trim() }
  if($baselineRequired -and $kbNorm -eq $baselineTargetKb){
    $baselineTargetAvailable = $true
    C2F-Evidence ("baseline_target_available=true|kb=KB" + $baselineTargetKb)
  }
	  if($osOnlyMode -and (-not (Test-C2FIsTargetWindowsUpdate -Update $uRaw -RequireBuildAdvancement $baselineRequired))){
	    $skippedNonTarget++
	    C2F-Evidence ("update_skipped_non_target_" + $skipNonTargetIdx + "=" + $kbRaw + "|" + $uRaw.Title)
	    $skipNonTargetIdx++
	    continue
  }
  if($baselineRequired -and $kbNorm -eq $baselineTargetKb){
    $baselineTargetApplicable = $true
    C2F-Evidence ("baseline_target_applicable=true|kb=KB" + $baselineTargetKb)
  }
  [void]$updates.Add($uRaw)
}

	$count=$updates.Count
	C2F-Evidence ("updates_applicable=" + $count)
	C2F-Evidence ("updates_skipped_non_target=" + $skippedNonTarget)

	if($count -eq 0 -and $baselineRequired -and (-not $baselineMetBefore) -and (-not $baselineTargetAvailable)){
	  $direct = Invoke-C2FBaselineDirectInstall -TargetKb $baselineTargetKb -PswuReady $pswuReady
	  $baselineDirectAttempted = [bool]$direct["attempted"]
	  $baselineDirectQueryCount = [int]$direct["query_count"]
	  $baselineDirectInstalled = [bool]$direct["installed"]
	  $baselineDirectReason = [string]$direct["reason"]
	  $baselineDirectError = [string]$direct["error"]
	  if($baselineDirectQueryCount -gt 0){ $baselineTargetAvailable = $true }
	  C2F-Evidence ("baseline_direct_attempted=" + $baselineDirectAttempted)
	  C2F-Evidence ("baseline_direct_installed=" + $baselineDirectInstalled)
	  if($baselineDirectReason){ C2F-Evidence ("baseline_direct_reason=" + $baselineDirectReason) }
	  if($baselineDirectError){ C2F-Evidence ("baseline_direct_error=" + $baselineDirectError) }
	  if($baselineDirectInstalled){
	    Start-Sleep -Seconds 8
	    $cvAfterDirect=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
	    $build=$cvAfterDirect.CurrentBuildNumber; if(-not $build){ $build=$cvAfterDirect.CurrentBuild }
	    $ubr=$cvAfterDirect.UBR; if($ubr -eq $null){ $ubr='' }
	    $buildNum = 0
	    try { $buildNum = [int]$build } catch { $buildNum = 0 }
	    $ubrNum = 0
	    try { $ubrNum = [int]$ubr } catch { $ubrNum = 0 }
	    $baselineMetBefore = ((-not $baselineRequired) -or (($buildNum -gt $baselineMinBuild) -or (($buildNum -eq $baselineMinBuild) -and ($ubrNum -ge $baselineMinUbr))))
	    C2F-Evidence ("os_build_after_direct_attempt=" + $build + "." + $ubr)
	    C2F-Evidence ("baseline_met_after_direct_attempt=" + $baselineMetBefore)
	  }
	}
	
				if($count -eq 0){
				  if($baselineRequired -and (-not $baselineMetBefore)){
			    if($pendingBefore){
			      $summary = ("windows update waiting reboot: baseline KB" + $baselineTargetKb + " not reached and endpoint already has pending reboot state.")
			      C2F-Evidence "reboot_pending=true"
			      C2F-Evidence "reboot_scheduled=false"
			      C2F-Evidence "reboot_policy=deferred_user_controlled"
			      C2F-Evidence "outcome=WAITING_REBOOT"
			      Write-Output $summary
			      Write-Result $true @{
			        "summary" = $summary
			        "outcome" = "WAITING_REBOOT"
			        "update_profile" = $updateProfile
			        "updates_discovered" = $rawCount
			        "updates_applicable" = 0
			        "updates_installable" = 0
			        "updates_skipped_non_target" = $skippedNonTarget
			        "updates_installed" = 0
			        "updates_failed" = 0
			        "updates_remaining" = 0
			        "reboot_required" = $true
			        "reboot_scheduled" = $false
			        "os_build_before" = ($build + "." + $ubr)
			        "os_build_after" = ($build + "." + $ubr)
			        "baseline_required" = $baselineRequired
			        "baseline_target_kb" = ("KB" + $baselineTargetKb)
			        "baseline_target_available" = $baselineTargetAvailable
			        "baseline_met" = $false
			        "esu_required" = $baselineRequired
			        "esu_enrolled" = $esuEnrolled
			      }
			      C2F-Status "SUCCESS"
			      exit 0
			    }
			    $summary = ("FAILED - Patch Not Applied: baseline KB" + $baselineTargetKb + " not reached and no applicable updates were found.")
			    $errText = ("FAILED - Patch Not Applied: expected minimum build " + $baselineMinBuild + "." + $baselineMinUbr + " (KB" + $baselineTargetKb + "), observed " + $build + "." + $ubr)
			    C2F-Evidence ("error=" + $errText)
			    Write-Output $summary
			    Write-Result $false @{
			      "summary" = $summary
			      "outcome" = "FAILED"
			      "error" = $errText
			      "update_profile" = $updateProfile
			      "updates_discovered" = $rawCount
			      "updates_applicable" = 0
			      "updates_installable" = 0
			      "updates_skipped_non_target" = $skippedNonTarget
			      "updates_installed" = 0
			      "updates_failed" = 0
			      "updates_remaining" = 0
			      "reboot_required" = $false
			      "reboot_scheduled" = $false
			      "os_build_before" = ($build + "." + $ubr)
			      "os_build_after" = ($build + "." + $ubr)
			      "baseline_required" = $baselineRequired
			      "baseline_target_kb" = ("KB" + $baselineTargetKb)
			      "baseline_target_available" = $baselineTargetAvailable
			      "baseline_met" = $false
			      "esu_required" = $baselineRequired
			      "esu_enrolled" = $esuEnrolled
			    }
			    C2F-Status "FAILED" $errText
			    exit 0
			  }
			  $summary = ("No applicable updates for profile=" + $updateProfile + ".")
			  Write-Output $summary
			  Write-Result $true @{
			    "summary" = $summary
			    "update_profile" = $updateProfile
			    "updates_discovered" = $rawCount
			    "updates_applicable" = 0
			    "updates_skipped_non_target" = $skippedNonTarget
			    "updates_installed" = 0
			    "updates_failed" = 0
			    "updates_remaining" = 0
			    "reboot_required" = $false
		    "reboot_scheduled" = $false
		    "os_build_before" = ($build + "." + $ubr)
		    "os_build_after" = ($build + "." + $ubr)
		    "baseline_required" = $baselineRequired
		    "baseline_target_kb" = ("KB" + $baselineTargetKb)
		    "baseline_target_available" = $baselineTargetAvailable
		    "baseline_met" = $baselineMetBefore
		    "esu_required" = $baselineRequired
		    "esu_enrolled" = $esuEnrolled
		  }
		  C2F-Status "SUCCESS"
		  exit 0
		}

$updateDetails=@()
$availableDetails=@()
$skippedDetails=@()
$installedDetails=@()
$failedDetails=@()
$remainingDetails=@()

$max=[Math]::Min($count, 200)
for($i=0; $i -lt $max; $i++){
  $u=$updates.Item($i)
  $kb=''
  try{ if($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0){ $kb=$u.KBArticleIDs.Item(0) } }catch{}
  $availableDetails += @{
    "index" = $i
    "kb" = $kb
    "title" = $u.Title
  }
  C2F-Evidence ("available_update_" + $i + "=" + $kb + "|" + $u.Title)
  C2F-Evidence ("update_" + $i + "=" + $kb + "|" + $u.Title)
}

$installable = New-Object -ComObject 'Microsoft.Update.UpdateColl'
$skippedInteractive = 0
for($i=0; $i -lt $count; $i++){
  $u=$updates.Item($i)
  $kb=''
  try{ if($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0){ $kb=$u.KBArticleIDs.Item(0) } }catch{}
  $canInstall = $true
  try{
    if($u.InstallationBehavior -and $u.InstallationBehavior.CanRequestUserInput){
      $canInstall = $false
    }
  }catch{}
  if(-not $canInstall){
    $skippedInteractive++
    $skippedDetails += @{
      "index" = $i
      "reason" = "interactive"
      "kb" = $kb
      "title" = $u.Title
    }
    C2F-Evidence ("update_skipped_" + $i + "=interactive|" + $kb + "|" + $u.Title)
    C2F-Evidence ("skipped_update_" + $i + "=interactive|" + $kb + "|" + $u.Title)
    continue
  }
  if(-not $u.EulaAccepted){ try{ $u.AcceptEula() } catch{} }
  [void]$installable.Add($u)
}

$installableCount = $installable.Count
C2F-Evidence ("updates_installable=" + $installableCount)
C2F-Evidence ("updates_skipped_interactive=" + $skippedInteractive)

$downloadCode = 0
$installCode = 0
$rebootRequired = $false
$installed=0; $failed=0

if($installableCount -gt 0){
  $downloader=$session.CreateUpdateDownloader()
  $downloader.Updates=$installable
  $dlResult=$downloader.Download()
  $downloadCode = [int]$dlResult.ResultCode
  C2F-Evidence ("download_result=" + $downloadCode)

  $installer=$session.CreateUpdateInstaller()
  $installer.Updates=$installable
  $instResult=$installer.Install()
  $installCode = [int]$instResult.ResultCode
  $rebootRequired = [bool]$instResult.RebootRequired
  C2F-Evidence ("install_result=" + $installCode)
  C2F-Evidence ("reboot_required=" + $rebootRequired)

  for($i=0; $i -lt $installableCount; $i++){
    $u=$installable.Item($i)
    $r=$instResult.GetUpdateResult($i)
    $kb=''
    try{ if($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0){ $kb=$u.KBArticleIDs.Item(0) } }catch{}
    $rc=[int]$r.ResultCode
    $hr=[int]$r.HResult
    if($rc -eq 2 -or $rc -eq 3){
      $installed++
      $installedDetails += @{
        "index" = $i
        "kb" = $kb
        "title" = $u.Title
        "result_code" = $rc
        "hresult" = $hr
      }
      C2F-Evidence ("installed_update_" + $i + "=" + $kb + "|" + $u.Title + "|rc=" + $rc + "|hr=" + $hr)
    } else {
      $failed++
      $failedDetails += @{
        "index" = $i
        "kb" = $kb
        "title" = $u.Title
        "result_code" = $rc
        "hresult" = $hr
      }
      C2F-Evidence ("failed_update_" + $i + "=" + $kb + "|" + $u.Title + "|rc=" + $rc + "|hr=" + $hr)
    }
    $updateDetails += @{
      "index" = $i
      "kb" = $kb
      "title" = $u.Title
      "result_code" = $rc
      "hresult" = $hr
    }
    C2F-Evidence ("update_result_" + $i + "=" + $rc + "|" + $hr + "|" + $kb + "|" + $u.Title)
  }
} else {
  C2F-Evidence "download_result=0"
  C2F-Evidence "install_result=0"
  C2F-Evidence "reboot_required=False"
}

C2F-Evidence ("updates_installed=" + $installed)
C2F-Evidence ("updates_failed=" + $failed)

$searcher2=$session.CreateUpdateSearcher()
$afterResult=$searcher2.Search($criterion)
$afterUpdatesRaw=$afterResult.Updates
$afterTotal=$afterUpdatesRaw.Count
C2F-Evidence ("updates_remaining_total=" + $afterTotal)

		$remainingInstallable = 0
		$remainingInteractive = 0
		$remainingNonTarget = 0
		$remainingDetails=@()

		if($afterTotal -gt 0){
		  $maxAfter=[Math]::Min($afterTotal, 200)
		  $emitIdx = 0
		  for($i=0; $i -lt $maxAfter; $i++){
		    $u2=$afterUpdatesRaw.Item($i)
		    $kb2=''
		    try{ if($u2.KBArticleIDs -and $u2.KBArticleIDs.Count -gt 0){ $kb2=$u2.KBArticleIDs.Item(0) } }catch{}

			    if($osOnlyMode -and (-not (Test-C2FIsTargetWindowsUpdate -Update $u2 -RequireBuildAdvancement $baselineRequired))){
			      $remainingNonTarget++
			      continue
			    }

		    $canInstall2 = $true
		    try{
		      if($u2.InstallationBehavior -and $u2.InstallationBehavior.CanRequestUserInput){
	        $canInstall2 = $false
	      }
	    }catch{}

	    if(-not $canInstall2){
	      $remainingInteractive++
	      continue
	    }

	    $remainingInstallable++
	    $remainingDetails += @{
	      "index" = $i
	      "kb" = $kb2
	      "title" = $u2.Title
	    }
	    C2F-Evidence ("remaining_update_" + $emitIdx + "=" + $kb2 + "|" + $u2.Title)
	    $emitIdx++
	  }
		}
			C2F-Evidence ("updates_remaining_installable=" + $remainingInstallable)
			C2F-Evidence ("updates_remaining_interactive=" + $remainingInteractive)
			C2F-Evidence ("updates_remaining_non_target=" + $remainingNonTarget)
			C2F-Evidence ("updates_remaining=" + $remainingInstallable)

	if($baselineRequired -and (-not $baselineMetBefore) -and (-not $baselineTargetAvailable) -and (-not $baselineDirectAttempted)){
	  $directPost = Invoke-C2FBaselineDirectInstall -TargetKb $baselineTargetKb -PswuReady $pswuReady
	  $baselineDirectAttempted = [bool]$directPost["attempted"]
	  $baselineDirectQueryCount = [int]$directPost["query_count"]
	  $baselineDirectInstalled = [bool]$directPost["installed"]
	  $baselineDirectReason = [string]$directPost["reason"]
	  $baselineDirectError = [string]$directPost["error"]
	  if($baselineDirectQueryCount -gt 0){ $baselineTargetAvailable = $true }
	  C2F-Evidence ("baseline_direct_attempted=" + $baselineDirectAttempted)
	  C2F-Evidence ("baseline_direct_installed=" + $baselineDirectInstalled)
	  if($baselineDirectReason){ C2F-Evidence ("baseline_direct_reason=" + $baselineDirectReason) }
	  if($baselineDirectError){ C2F-Evidence ("baseline_direct_error=" + $baselineDirectError) }
	  if($baselineDirectInstalled){ Start-Sleep -Seconds 8 }
	}

	$pendingAfter=Test-C2FPendingReboot
	C2F-Evidence ("pending_reboot_after=" + $pendingAfter)

$cv2=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build2=$cv2.CurrentBuildNumber; if(-not $build2){ $build2=$cv2.CurrentBuild }
$ubr2=$cv2.UBR; if($ubr2 -eq $null){ $ubr2='' }
C2F-Evidence ("os_build_after=" + $build2 + "." + $ubr2)

$build2Num = 0
try { $build2Num = [int]$build2 } catch { $build2Num = 0 }
$ubr2Num = 0
try { $ubr2Num = [int]$ubr2 } catch { $ubr2Num = 0 }
$buildAdvanced = (($build2Num -gt $buildNum) -or (($build2Num -eq $buildNum) -and ($ubr2Num -gt $ubrNum)))
$baselineMetAfter = ((-not $baselineRequired) -or (($build2Num -gt $baselineMinBuild) -or (($build2Num -eq $baselineMinBuild) -and ($ubr2Num -ge $baselineMinUbr)))
)
C2F-Evidence ("os_build_advanced=" + $buildAdvanced)
C2F-Evidence ("baseline_met_after=" + $baselineMetAfter)
C2F-Evidence ("baseline_target_available=" + $baselineTargetAvailable)
C2F-Evidence ("baseline_target_applicable=" + $baselineTargetApplicable)

			$outcome="SUCCESS"
			if($installableCount -eq 0 -and $count -gt 0){
			  $outcome="PARTIAL"
			}
			if($failed -gt 0 -or $installCode -eq 4 -or $downloadCode -eq 4 -or $installCode -eq 5 -or $downloadCode -eq 5){
			  $outcome="FAILED"
			} elseif($remainingInstallable -gt 0){
			  $outcome="PARTIAL"
			} elseif($rebootRequired -or $pendingAfter -or $installCode -eq 3){
			  $outcome="WAITING_REBOOT"
			}
				if($baselineRequired -and (-not $baselineMetAfter)){
				  if($rebootRequired -or $pendingBefore -or $pendingAfter){
				    $outcome="WAITING_REBOOT"
				    C2F-Evidence "baseline_waiting_reboot=true"
				  } else {
				    $outcome="FAILED"
				  }
				}
			C2F-Evidence ("outcome=" + $outcome)

	if($rebootRequired -or $pendingAfter){
	  C2F-Evidence "reboot_pending=true"
	  C2F-Evidence "reboot_scheduled=false"
	  C2F-Evidence "reboot_policy=deferred_user_controlled"
	  $rebootScheduled = $false
		} else {
		  C2F-Evidence "reboot_pending=false"
		  C2F-Evidence "reboot_scheduled=false"
		  C2F-Evidence "reboot_policy=not_required"
		  $rebootScheduled = $false
		}

		$summary = ("windows update install complete: profile=" + $updateProfile + " outcome=" + $outcome + " discovered=" + $rawCount + " applicable=" + $count + " installable=" + $installableCount + " skipped_interactive=" + $skippedInteractive + " skipped_non_target=" + $skippedNonTarget + " installed=" + $installed + " failed=" + $failed + " remaining=" + $remainingInstallable + " remaining_total=" + $afterTotal + " reboot_required=" + $rebootRequired)
		Write-Output $summary

$warning = ""
if($installCode -eq 4 -or $downloadCode -eq 4 -or $installCode -eq 5 -or $downloadCode -eq 5){
  $warning = ("Windows Update had non-success result: install_result=" + $installCode + "; download_result=" + $downloadCode)
  C2F-Evidence ("warning=" + $warning)
}

			$ok = ($outcome -eq "SUCCESS" -or $outcome -eq "WAITING_REBOOT")
			$errText = ""
			if(-not $ok){
			  if($baselineRequired -and (-not $baselineMetAfter)){
			    $errText = ("FAILED - Patch Not Applied: expected minimum build " + $baselineMinBuild + "." + $baselineMinUbr + " (KB" + $baselineTargetKb + "), observed " + $build2 + "." + $ubr2)
			    if(-not $baselineTargetAvailable){
			      $errText = $errText + "; target KB" + $baselineTargetKb + " was not offered by update source"
			    }
			  } else {
			    $errText = ("Windows Update incomplete: outcome=" + $outcome + " installed=" + $installed + " failed=" + $failed + " remaining=" + $remainingInstallable + " remaining_total=" + $afterTotal)
			  }
			}

		Write-Result $ok @{
		  "summary" = $summary
		  "update_profile" = $updateProfile
		  "outcome" = $outcome
		  "updates_discovered" = $rawCount
		  "updates_applicable" = $count
		  "updates_installable" = $installableCount
		  "updates_skipped_interactive" = $skippedInteractive
		  "updates_skipped_non_target" = $skippedNonTarget
		  "updates_installed" = $installed
		  "updates_failed" = $failed
		  "updates_remaining" = $remainingInstallable
		  "updates_remaining_total" = $afterTotal
		  "updates_remaining_installable" = $remainingInstallable
		  "updates_remaining_interactive" = $remainingInteractive
		  "updates_remaining_non_target" = $remainingNonTarget
		  "download_result" = $downloadCode
		  "install_result" = $installCode
	  "updates" = $updateDetails
	  "available_updates" = $availableDetails
	  "skipped_updates" = $skippedDetails
	  "installed_updates" = $installedDetails
	  "failed_updates" = $failedDetails
	  "remaining_updates" = $remainingDetails
		  "reboot_required" = [bool]$rebootRequired
		  "reboot_scheduled" = [bool]$rebootScheduled
		  "os_build_before" = ($build + "." + $ubr)
		  "os_build_after" = ($build2 + "." + $ubr2)
		  "os_build_advanced" = $buildAdvanced
		  "baseline_required" = $baselineRequired
		  "baseline_target_kb" = ("KB" + $baselineTargetKb)
		  "baseline_target_available" = $baselineTargetAvailable
		  "baseline_target_applicable" = $baselineTargetApplicable
		  "baseline_met_before" = $baselineMetBefore
		  "baseline_met" = $baselineMetAfter
		  "baseline_direct_attempted" = $baselineDirectAttempted
		  "baseline_direct_query_count" = $baselineDirectQueryCount
		  "baseline_direct_installed" = $baselineDirectInstalled
		  "baseline_direct_reason" = $baselineDirectReason
		  "baseline_direct_error" = $baselineDirectError
		  "esu_required" = $baselineRequired
		  "esu_enrolled" = $esuEnrolled
		  "warning" = $warning
		  "error" = $errText
		}
	
	if($ok){
	  C2F-Status "SUCCESS"
	} else {
	  C2F-Status "FAILED" $errText
	}
	exit 0
	}
catch {
  $err = $_.Exception.Message
  C2F-Evidence ("error=" + $err)
  Write-Result $false @{ "error" = $err; "summary" = $summary }
  C2F-Status "FAILED" $err
  throw
}
""".strip()

    def _ensure_windows_action_script(self, target: Dict[str, Any], action_id: str) -> None:
        content = self._windows_action_script_content(action_id)
        if not content:
            return

        path = self._windows_action_script_path(action_id)
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest().upper()

        def _run_required(script: str, step: str, timeout_seconds: int = 60) -> str:
            code, out, err = self._run_winrm(target, script, timeout_seconds=timeout_seconds)
            if int(code) != 0:
                detail = (err or out or f"{step} failed").strip()
                raise RuntimeError(f"{step} failed for {path}: {detail}")
            return str(out or "")

        # Check if already installed with matching hash to avoid re-uploading on every run.
        check_script = (
            "$p=" + _ps_quote(path) + ";"
            "if(Test-Path $p){"
            "try{ (Get-FileHash -Algorithm SHA256 -Path $p).Hash }catch{ '' }"
            "} else { '' }"
        )
        try:
            code, out, _ = self._run_winrm(target, check_script, timeout_seconds=30)
        except Exception:
            code, out = 1, ""
        remote_hash = (out or "").strip().upper()
        if code == 0 and remote_hash and remote_hash == expected:
            return

        # Upload as base64 chunks (avoid WinRM encoded-command length limits).
        raw = base64.b64encode(content.encode("utf-8")).decode("ascii")
        chunks = [raw[i : i + 2000] for i in range(0, len(raw), 2000)]
        upload_id = uuid.uuid4().hex
        b64_path = f"{path}.{upload_id}.b64"
        tmp_path = f"{path}.{upload_id}.tmp"

        init_script = (
            "$dst=" + _ps_quote(path) + ";"
            "$dir=Split-Path -Parent $dst;"
            "New-Item -ItemType Directory -Path $dir -Force | Out-Null;"
            "$b64=" + _ps_quote(b64_path) + ";"
            "Set-Content -Path $b64 -Value '' -Encoding ASCII;"
        )
        _run_required(init_script, "script upload init", timeout_seconds=60)

        for chunk in chunks:
            add_script = (
                "$b64=" + _ps_quote(b64_path) + ";"
                "Add-Content -Path $b64 -Value " + _ps_quote(chunk) + " -Encoding ASCII;"
            )
            _run_required(add_script, "script upload chunk", timeout_seconds=60)

        finalize_script = (
            "$dst=" + _ps_quote(path) + ";"
            "$tmp=" + _ps_quote(tmp_path) + ";"
            "$b64=" + _ps_quote(b64_path) + ";"
            "$raw=Get-Content -Path $b64 -Raw;"
            "[IO.File]::WriteAllBytes($tmp,[Convert]::FromBase64String($raw));"
            "Move-Item -Path $tmp -Destination $dst -Force;"
            "Remove-Item -Path $b64,$tmp -Force -ErrorAction SilentlyContinue;"
        )
        # Some endpoints emit benign CLIXML progress records and return non-zero here even when
        # the file is written correctly. Always verify by hash before deciding success/failure.
        self._run_winrm(target, finalize_script, timeout_seconds=60)

        verify_script = (
            "$p=" + _ps_quote(path) + ";"
            "if(Test-Path $p){"
            "try{ (Get-FileHash -Algorithm SHA256 -Path $p).Hash }catch{ '' }"
            "} else { '' }"
        )
        uploaded_hash = _run_required(verify_script, "script upload verify", timeout_seconds=30).strip().upper()
        if not uploaded_hash or uploaded_hash != expected:
            raise RuntimeError(
                f"script upload verification mismatch for {path}: expected={expected} got={uploaded_hash or '<missing>'}"
            )

    def _upload_windows_script(self, target: Dict[str, Any], path: str, content: str) -> None:
        payload = str(content or "")
        if not payload:
            raise RuntimeError("script payload is empty")

        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest().upper()
        raw = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        chunks = [raw[i : i + 2000] for i in range(0, len(raw), 2000)]
        upload_id = uuid.uuid4().hex
        b64_path = f"{path}.{upload_id}.b64"
        tmp_path = f"{path}.{upload_id}.tmp"

        def _run_required(script: str, step: str, timeout_seconds: int = 60) -> str:
            code, out, err = self._run_winrm(target, script, timeout_seconds=timeout_seconds)
            if int(code) != 0:
                detail = (err or out or f"{step} failed").strip()
                raise RuntimeError(f"{step} failed for {path}: {detail}")
            return str(out or "")

        init_script = (
            "$dst=" + _ps_quote(path) + ";"
            "$dir=Split-Path -Parent $dst;"
            "New-Item -ItemType Directory -Path $dir -Force | Out-Null;"
            "$b64=" + _ps_quote(b64_path) + ";"
            "Set-Content -Path $b64 -Value '' -Encoding ASCII;"
        )
        _run_required(init_script, "payload upload init", timeout_seconds=60)

        for chunk in chunks:
            add_script = (
                "$b64=" + _ps_quote(b64_path) + ";"
                "Add-Content -Path $b64 -Value " + _ps_quote(chunk) + " -Encoding ASCII;"
            )
            _run_required(add_script, "payload upload chunk", timeout_seconds=60)

        finalize_script = (
            "$dst=" + _ps_quote(path) + ";"
            "$tmp=" + _ps_quote(tmp_path) + ";"
            "$b64=" + _ps_quote(b64_path) + ";"
            "$raw=Get-Content -Path $b64 -Raw;"
            "[IO.File]::WriteAllBytes($tmp,[Convert]::FromBase64String($raw));"
            "Move-Item -Path $tmp -Destination $dst -Force;"
            "Remove-Item -Path $b64,$tmp -Force -ErrorAction SilentlyContinue;"
        )
        # Some endpoints emit benign CLIXML progress records and return non-zero here
        # even when the file is written correctly. Verify by hash before failing.
        self._run_winrm(target, finalize_script, timeout_seconds=60)

        verify_script = (
            "$p=" + _ps_quote(path) + ";"
            "if(Test-Path $p){"
            "try{ (Get-FileHash -Algorithm SHA256 -Path $p).Hash }catch{ '' }"
            "} else { '' }"
        )
        uploaded_hash = _run_required(verify_script, "payload upload verify", timeout_seconds=30).strip().upper()
        if not uploaded_hash or uploaded_hash != expected:
            raise RuntimeError(
                f"payload upload verification mismatch for {path}: expected={expected} got={uploaded_hash or '<missing>'}"
            )

    def _windows_credentials_for_agent(self, agent_id: Optional[str]) -> Dict[str, str]:
        norm = self._normalize_agent_id(agent_id or "")
        if norm:
            per_agent = self.windows_agent_credentials.get(norm) or {}
            if per_agent.get("username") and per_agent.get("password"):
                return {
                    "username": per_agent.get("username", ""),
                    "password": per_agent.get("password", ""),
                }
        return {
            "username": self.windows_cfg.get("username", ""),
            "password": self.windows_cfg.get("password", ""),
        }

    def has_windows_credentials(self, agent_id: Optional[str] = None) -> bool:
        if agent_id:
            creds = self._windows_credentials_for_agent(agent_id)
            return bool(creds.get("username") and creds.get("password"))
        if self.windows_cfg.get("username") and self.windows_cfg.get("password"):
            return True
        return any(
            creds.get("username") and creds.get("password")
            for creds in self.windows_agent_credentials.values()
        )

    def execute(
        self,
        action_id: str,
        action_args: List[str],
        agent_ids: Iterable[str],
        context: Optional[Dict[str, Any]] = None,
        on_progress=None,
    ) -> Dict[str, Any]:
        target_ids = [str(a) for a in (agent_ids or []) if str(a).strip()]
        if not target_ids:
            raise HTTPException(status_code=404, detail="No agents provided for endpoint execution")

        # Resolve targets from one fleet snapshot first to avoid one manager API call per endpoint.
        agent_lookup = self._build_agent_lookup(target_ids)
        targets = [self._resolve_agent_target(agent_id, agent_lookup=agent_lookup) for agent_id in target_ids]
        workers = max(1, min(self.max_workers, len(targets)))
        results: List[Dict[str, Any]] = []
        ctx = context or {}
        event_sink = ctx.get("_event_sink") if isinstance(ctx, dict) and callable(ctx.get("_event_sink")) else None
        aid = str(action_id or "").strip().lower()
        stagger_actions = {"patch-windows", "windows-os-update", "fleet-software-update", "package-update"}
        use_stagger = (
            aid in stagger_actions
            and self.windows_patch_stagger_seconds > 0
            and len(targets) >= self.windows_patch_stagger_min_targets
        )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for idx, target in enumerate(targets):
                self._guard_task_ingestion_for_memory(aid, event_sink=event_sink)
                if use_stagger and idx > 0:
                    time.sleep(self.windows_patch_stagger_seconds)
                fut = pool.submit(self._execute_target, action_id, action_args, target, ctx)
                futures[fut] = target

            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    result = {
                        "agent_id": target["agent_id"],
                        "agent_name": target["agent_name"],
                        "target_ip": target["ip"],
                        "platform": target["platform"],
                        "ok": False,
                        "stdout": "",
                        "stderr": str(exc),
                    }
                results.append(result)
                if on_progress:
                    try:
                        on_progress(result)
                    except Exception:
                        # Streaming/progress hooks must never break execution.
                        pass
                if self.stop_on_error and not result["ok"]:
                    break

        success = sum(1 for r in results if r["ok"])
        failed = len(results) - success

        return {
            "channel": "endpoint",
            "mode": "direct_endpoint",
            "action": action_id,
            "total": len(results),
            "success": success,
            "failed": failed,
            "ok": failed == 0 and len(results) > 0,
            "results": results,
        }

    def _normalize_agent_id(self, agent_id: str) -> str:
        raw = str(agent_id or "").strip()
        if raw.isdigit():
            return raw.zfill(3)
        return raw

    def _cache_target(self, target: Dict[str, Any]) -> None:
        aid = self._normalize_agent_id(target.get("agent_id"))
        if aid:
            self._target_cache[aid] = target

    def _extract_agent_items(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, dict):
            items = (
                data.get("data", {}).get("affected_items")
                or data.get("affected_items")
                or data.get("items")
                or []
            )
            return items if isinstance(items, list) else []
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        return []

    def _build_agent_lookup(self, agent_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        requested = {
            self._normalize_agent_id(agent_id)
            for agent_id in (agent_ids or [])
            if self._normalize_agent_id(agent_id)
        }
        if not requested:
            return {}
        try:
            data = self.client.get_agents(use_cache=True)
        except Exception:
            return {}

        lookup: Dict[str, Dict[str, Any]] = {}
        for agent in self._extract_agent_items(data):
            aid = self._normalize_agent_id(agent.get("id") or agent.get("agent_id") or "")
            if not aid or aid not in requested or aid in lookup:
                continue
            lookup[aid] = agent
        return lookup

    def _target_from_agent_record(self, agent: Dict[str, Any], requested_id: str) -> Dict[str, Any]:
        ip = agent.get("ip") or agent.get("registerIP") or agent.get("ip_address") or agent.get("last_ip")
        if not ip:
            raise HTTPException(status_code=400, detail=f"Agent {requested_id} has no reachable IP")

        os_name = ""
        if isinstance(agent.get("os"), dict):
            os_name = str(agent["os"].get("name") or agent["os"].get("platform") or agent["os"].get("full") or "")
        else:
            os_name = str(agent.get("os_name") or agent.get("os") or "")
        os_l = os_name.lower()
        platform = "windows" if "windows" in os_l else "linux"

        return {
            "agent_id": self._normalize_agent_id(str(agent.get("id") or requested_id)),
            "agent_name": str(agent.get("name") or agent.get("hostname") or requested_id),
            "ip": str(ip),
            "platform": platform,
            "raw": agent,
        }

    def _resolve_target_from_manager(self, agent_id: str) -> Dict[str, Any]:
        raw = self.client.get_agent(agent_id)
        payload = raw.get("data", {}) if isinstance(raw, dict) else {}
        items = payload.get("affected_items") if isinstance(payload, dict) else None
        if not items and isinstance(raw, dict):
            items = raw.get("affected_items") or raw.get("items")
        if isinstance(items, list) and items:
            agent = items[0] if isinstance(items[0], dict) else {}
        elif isinstance(raw, dict):
            agent = raw if "id" in raw else {}
        else:
            agent = {}
        return self._target_from_agent_record(agent, agent_id)

    def _resolve_target_from_overrides(self, agent_id: str) -> Optional[Dict[str, Any]]:
        overrides = _cfg("endpoint_connectors.agent_overrides", {})
        if not isinstance(overrides, dict):
            return None
        keys = [self._normalize_agent_id(agent_id), str(agent_id).strip()]
        value = None
        for key in keys:
            if key in overrides:
                value = overrides[key]
                break
        if value is None:
            return None
        if isinstance(value, str):
            return {
                "agent_id": self._normalize_agent_id(agent_id),
                "agent_name": self._normalize_agent_id(agent_id) or str(agent_id),
                "ip": value,
                "platform": "windows",
                "raw": {"id": agent_id, "ip": value, "source": "override"},
            }
        if isinstance(value, dict):
            ip = value.get("ip")
            if not ip:
                return None
            platform = str(value.get("platform") or "windows").strip().lower()
            if platform not in {"windows", "linux"}:
                platform = "windows"
            name = value.get("name") or value.get("agent_name") or self._normalize_agent_id(agent_id) or str(agent_id)
            return {
                "agent_id": self._normalize_agent_id(value.get("agent_id") or agent_id),
                "agent_name": str(name),
                "ip": str(ip),
                "platform": platform,
                "raw": {"id": agent_id, "ip": ip, "source": "override", **value},
            }
        return None

    def _resolve_target_from_indexer(self, agent_id: str) -> Optional[Dict[str, Any]]:
        if not self.indexer.enabled or not self.indexer.base:
            return None
        norm = self._normalize_agent_id(agent_id)
        try:
            alerts = self.indexer.search_alerts(limit=10, agent_id=norm, agent_only=True)
        except HTTPException:
            return None
        hits = alerts.get("hits", {}).get("hits", []) if isinstance(alerts, dict) else []
        if not isinstance(hits, list):
            hits = []
        ip = ""
        name = ""
        platform = ""
        for hit in hits:
            source = hit.get("_source", {}) if isinstance(hit, dict) else {}
            agent = source.get("agent", {}) if isinstance(source, dict) else {}
            if not isinstance(agent, dict):
                continue
            candidate_id = self._normalize_agent_id(agent.get("id") or agent.get("agent_id") or "")
            if candidate_id and candidate_id != norm:
                continue
            ip = str(agent.get("ip") or agent.get("ip_address") or source.get("agent_ip") or "").strip()
            name = str(agent.get("name") or agent.get("hostname") or "").strip()
            os_info = agent.get("os")
            if isinstance(os_info, dict):
                os_name = str(os_info.get("name") or os_info.get("platform") or os_info.get("full") or "")
            else:
                os_name = str(os_info or source.get("host", {}).get("os", {}).get("name") or "")
            if "windows" in os_name.lower():
                platform = "windows"
            elif os_name:
                platform = "linux"
            if ip:
                break
        if not ip:
            return None
        return {
            "agent_id": norm,
            "agent_name": name or norm,
            "ip": ip,
            "platform": platform or "windows",
            "raw": {"id": norm, "name": name, "ip": ip, "source": "indexer"},
        }

    def _resolve_agent_target(
        self,
        agent_id: str,
        agent_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        normalized = self._normalize_agent_id(agent_id)
        manager_error = None

        if isinstance(agent_lookup, dict):
            from_lookup = agent_lookup.get(normalized)
            if isinstance(from_lookup, dict):
                try:
                    target = self._target_from_agent_record(from_lookup, normalized)
                    self._cache_target(target)
                    return target
                except HTTPException:
                    pass

        try:
            target = self._resolve_target_from_manager(normalized)
            self._cache_target(target)
            return target
        except HTTPException as exc:
            manager_error = str(exc.detail)

        cached = self._target_cache.get(normalized)
        if cached and cached.get("ip"):
            return cached

        indexer_target = self._resolve_target_from_indexer(normalized)
        if indexer_target:
            self._cache_target(indexer_target)
            return indexer_target

        override_target = self._resolve_target_from_overrides(normalized)
        if override_target:
            self._cache_target(override_target)
            return override_target

        if manager_error:
            raise HTTPException(
                status_code=503,
                detail=f"Wazuh manager unavailable and no fallback target found for agent {normalized}",
            )
        raise HTTPException(status_code=404, detail=f"Unable to resolve target for agent {normalized}")

    def _execute_target(
        self,
        action_id: str,
        action_args: List[str],
        target: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        timeout_seconds = self._action_timeout_seconds(action_id)
        aid = str(action_id or "").strip().lower()
        if target["platform"] == "windows":
            if aid in {"fleet-software-update", "windows-os-update"}:
                script_action_id = "patch-windows"
            elif aid in {"toc-scan"}:
                script_action_id = "ioc-scan"
            else:
                script_action_id = action_id
            try:
                self._ensure_windows_action_script(target, script_action_id)
            except Exception as exc:
                return {
                    "agent_id": target["agent_id"],
                    "agent_name": target["agent_name"],
                    "target_ip": target["ip"],
                    "platform": target["platform"],
                    "ok": False,
                    "status_code": 1,
                    "stdout": "",
                    "stderr": f"Failed to prepare endpoint script: {exc}",
                }

            if aid in {"patch-windows", "fleet-software-update", "windows-os-update"}:
                status_code, stdout, stderr = self._execute_windows_patch(
                    target,
                    context=context,
                    timeout_seconds=timeout_seconds,
                    action_id=aid,
                )
                if aid == "windows-os-update" and status_code != 0:
                    status_code, stdout, stderr = self._attempt_windows_os_update_kb_fallback(
                        target=target,
                        context=context,
                        status_code=status_code,
                        timeout_seconds=timeout_seconds,
                        stdout=stdout,
                        stderr=stderr,
                    )
            elif aid in {"package-update", "malware-scan", "threat-hunt-persistence", "custom-os-command"}:
                task_args: Dict[str, Any] = {}
                command_file = ""
                if aid == "package-update":
                    task_args["PackageSpec"] = action_args[0] if action_args else "all"
                    task_args["Version"] = action_args[1] if len(action_args) > 1 else ""
                    task_args["MaxRuntimeSeconds"] = max(180, int(timeout_seconds))
                if aid == "malware-scan":
                    task_args["Scope"] = action_args[0] if action_args else "quick"
                    task_args["MaxRuntimeSeconds"] = max(180, int(timeout_seconds))
                if aid == "threat-hunt-persistence":
                    task_args["MaxRuntimeSeconds"] = max(180, int(timeout_seconds))
                if aid == "custom-os-command":
                    if not action_args or not str(action_args[0]).strip():
                        return {
                            "agent_id": target["agent_id"],
                            "agent_name": target["agent_name"],
                            "target_ip": target["ip"],
                            "platform": target["platform"],
                            "ok": False,
                            "status_code": 1,
                            "stdout": "",
                            "stderr": "custom-os-command requires command argument",
                        }
                    normalized_command = self._normalize_windows_custom_command(action_args[0])
                    if not normalized_command.strip():
                        return {
                            "agent_id": target["agent_id"],
                            "agent_name": target["agent_name"],
                            "target_ip": target["ip"],
                            "platform": target["platform"],
                            "ok": False,
                            "status_code": 1,
                            "stdout": "",
                            "stderr": "custom-os-command command is empty after normalization",
                        }
                    command_file = (
                        r"C:\Click2Fix\scripts\inputs\custom-cmd-"
                        + self._execution_tag(context)
                        + "-"
                        + str(target.get("agent_id") or "agent")
                        + "-"
                        + uuid.uuid4().hex
                        + ".ps1"
                    )
                    try:
                        self._upload_windows_script(target, command_file, normalized_command)
                    except Exception as exc:
                        return {
                            "agent_id": target["agent_id"],
                            "agent_name": target["agent_name"],
                            "target_ip": target["ip"],
                            "platform": target["platform"],
                            "ok": False,
                            "status_code": 1,
                            "stdout": "",
                            "stderr": f"Failed to upload custom command payload: {exc}",
                        }
                    task_args["CommandFile"] = command_file
                    task_args["VerifyKb"] = action_args[1] if len(action_args) > 1 else ""
                    task_args["VerifyMinBuild"] = action_args[2] if len(action_args) > 2 else ""
                    task_args["VerifyStdoutContains"] = action_args[3] if len(action_args) > 3 else ""
                    task_args["RunAsSystem"] = _bool(action_args[4] if len(action_args) > 4 else False, False)
                    task_args["MaxRuntimeSeconds"] = max(180, int(timeout_seconds))

                try:
                    status_code, stdout, stderr = self._execute_windows_script_task(
                        target,
                        context=context,
                        timeout_seconds=timeout_seconds,
                        action_id=aid,
                        script_action_id=script_action_id,
                        script_args=task_args,
                    )
                finally:
                    if command_file:
                        cleanup_script = (
                            "$ErrorActionPreference='SilentlyContinue';"
                            "$ProgressPreference='SilentlyContinue';"
                            f"$cf={_ps_quote(command_file)};"
                            "try { Remove-Item -Path $cf -Force -ErrorAction SilentlyContinue } catch { };"
                        )
                        try:
                            self._run_winrm(target, cleanup_script, timeout_seconds=30)
                        except Exception:
                            pass
            else:
                script = self._build_windows_script(action_id, action_args, context=context, target=target)
                status_code, stdout, stderr = self._run_winrm(target, script, timeout_seconds=timeout_seconds)
                if status_code != 0:
                    combined_error = f"{stderr}\n{stdout}".lower()
                    fallback_actions = {
                        "endpoint-healthcheck",
                        "ioc-scan",
                        "toc-scan",
                        "yara-scan",
                        "collect-forensics",
                        "collect-memory",
                    }
                    if "command line is too long" in combined_error and aid in fallback_actions:
                        fallback_args: Dict[str, Any] = {}
                        if aid in {"ioc-scan", "toc-scan"} and action_args and str(action_args[0]).strip():
                            fallback_args["IocSet"] = str(action_args[0]).strip()
                        elif aid == "yara-scan" and action_args and str(action_args[0]).strip():
                            fallback_args["ScanPath"] = str(action_args[0]).strip()
                        status_code, stdout, stderr = self._execute_windows_script_task(
                            target,
                            context=context,
                            timeout_seconds=timeout_seconds,
                            action_id=aid,
                            script_action_id=script_action_id,
                            script_args=fallback_args,
                        )
        else:
            script = self._build_linux_script(action_id, action_args, context=context, target=target)
            status_code, stdout, stderr = self._run_ssh(target["ip"], script, timeout_seconds=timeout_seconds)

        return {
            "agent_id": target["agent_id"],
            "agent_name": target["agent_name"],
            "target_ip": target["ip"],
            "platform": target["platform"],
            "ok": status_code == 0,
            "status_code": status_code,
            "stdout": stdout,
            "stderr": stderr,
        }

    def _emit_target_log(self, target: Dict[str, Any], context: Dict[str, Any], lines: List[str]) -> None:
        """
        Stream endpoint evidence lines during long-running actions.

        The sink is injected from core.action_execution and forwards to the WS bus.
        """
        sink = context.get("_event_sink")
        if not callable(sink) or not lines:
            return
        agent_id = str(target.get("agent_id") or "").strip()
        step = f"endpoint:{agent_id}" if agent_id else "endpoint"
        payload = "\n".join("C2F_LOG " + line for line in lines if line)
        if not payload.strip():
            return
        try:
            sink(
                {
                    "type": "target_log",
                    "step": step,
                    "status": "RUNNING",
                    "stdout": payload,
                    "stderr": "",
                }
            )
        except Exception:
            return

    @staticmethod
    def _extract_c2f_evidence_metrics(stdout: str) -> Dict[str, str]:
        metrics: Dict[str, str] = {}
        for raw in str(stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("C2F_LOG "):
                line = line[len("C2F_LOG ") :].strip()
            marker = " evidence="
            marker_idx = line.find(marker)
            if marker_idx < 0:
                continue
            payload = line[marker_idx + len(marker) :].strip()
            if "=" not in payload:
                continue
            key, value = payload.split("=", 1)
            key_norm = str(key or "").strip()
            if not key_norm:
                continue
            metrics[key_norm] = str(value or "").strip()
        return metrics

    @staticmethod
    def _parse_bool_metric(value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value
        text_value = str(value or "").strip().lower()
        if not text_value:
            return default
        return text_value in {"1", "true", "yes", "on"}

    @staticmethod
    def _normalize_kb_value(value: Any) -> str:
        raw = str(value or "").strip().upper().replace(" ", "")
        if not raw:
            return ""
        if raw.startswith("KB"):
            raw = raw[2:]
        if not raw.isdigit():
            return ""
        return f"KB{raw}"

    @classmethod
    def _extract_kb_from_text(cls, value: Any) -> str:
        text = str(value or "")
        if not text:
            return ""
        match = re.search(r"\bKB\s*([0-9]{4,8})\b", text, flags=re.IGNORECASE)
        if not match:
            return ""
        return cls._normalize_kb_value(match.group(0))

    @staticmethod
    def _normalize_windows_build(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        match = re.search(r"\b(?:10\.0\.)?(\d{4,5}\.\d{1,5})\b", text)
        if not match:
            return ""
        return str(match.group(1)).strip()

    @staticmethod
    def _strip_wrapping_quotes(value: str) -> str:
        text = str(value or "").strip()
        if len(text) >= 2 and ((text[0] == '"' and text[-1] == '"') or (text[0] == "'" and text[-1] == "'")):
            return text[1:-1]
        return text

    @classmethod
    def _normalize_windows_custom_command(cls, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""

        # Convert "powershell ... -EncodedCommand <base64>" wrappers to raw script text.
        enc_match = re.search(r"(?is)-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]+)", raw)
        if enc_match:
            try:
                decoded = base64.b64decode(enc_match.group(1))
                script = decoded.decode("utf-16-le", errors="replace").strip()
                if script:
                    return script
            except Exception:
                pass

        # Convert "powershell ... -Command <script>" wrappers to raw script text.
        cmd_match = re.search(r"(?is)\b(?:powershell|pwsh)(?:\.exe)?\b.*?-command\s+(.+)$", raw)
        if cmd_match:
            payload = cls._strip_wrapping_quotes(cmd_match.group(1)).strip()
            if payload:
                return payload

        return raw

    @staticmethod
    def _build_windows_kb_fallback_command(kb: str) -> str:
        kb_norm = str(kb or "").strip()
        return (
            f"Import-Module PSWindowsUpdate; Install-WindowsUpdate -KBArticleID {kb_norm} "
            "-MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Continue"
        )

    def _attempt_windows_os_update_kb_fallback(
        self,
        *,
        target: Dict[str, Any],
        context: Dict[str, Any],
        status_code: int,
        timeout_seconds: int,
        stdout: str,
        stderr: str,
    ) -> tuple[int, str, str]:
        if not self.windows_os_update_force_kb_fallback_enabled:
            return status_code, stdout, stderr

        metrics = self._extract_c2f_evidence_metrics(stdout)
        blob = f"{stdout}\n{stderr}"
        blob_l = blob.lower()

        trigger_markers = (
            "not offered by update source",
            "failed - patch not applied",
            "expected minimum build",
            "no applicable updates were found",
            "baseline_target_available=false",
            "baseline_met_after=false",
        )
        should_attempt = any(marker in blob_l for marker in trigger_markers)
        if not should_attempt:
            return status_code, stdout, stderr

        kb = self._normalize_kb_value(metrics.get("baseline_target_kb")) or self._extract_kb_from_text(blob)
        if not kb:
            return status_code, stdout, stderr

        min_build = self._normalize_windows_build(metrics.get("baseline_min_build"))
        command = self._normalize_windows_custom_command(self._build_windows_kb_fallback_command(kb))
        if not command.strip():
            return status_code, stdout, stderr
        fallback_timeout = max(
            300,
            min(
                int(self.windows_os_update_force_kb_fallback_timeout_seconds),
                max(int(timeout_seconds or 0), 300),
            ),
        )
        command_file = (
            r"C:\Click2Fix\scripts\inputs\custom-cmd-"
            + self._execution_tag(context)
            + "-"
            + str(target.get("agent_id") or "agent")
            + "-"
            + uuid.uuid4().hex
            + ".ps1"
        )
        try:
            self._ensure_windows_action_script(target, "custom-os-command")
            self._upload_windows_script(target, command_file, command)
            task_args: Dict[str, Any] = {
                "CommandFile": command_file,
                "VerifyKb": kb,
                "MaxRuntimeSeconds": fallback_timeout,
            }
            if min_build:
                task_args["VerifyMinBuild"] = min_build
            fb_code, fb_out, fb_err = self._execute_windows_script_task(
                target,
                context=context,
                timeout_seconds=fallback_timeout,
                action_id="custom-os-command",
                script_action_id="custom-os-command",
                script_args=task_args,
            )
        except Exception as exc:
            fb_code, fb_out, fb_err = 1, "", str(exc)
        finally:
            cleanup_script = (
                "$ErrorActionPreference='SilentlyContinue';"
                "$ProgressPreference='SilentlyContinue';"
                f"$cf={_ps_quote(command_file)};"
                "try { Remove-Item -Path $cf -Force -ErrorAction SilentlyContinue } catch { };"
            )
            try:
                self._run_winrm(target, cleanup_script, timeout_seconds=30)
            except Exception:
                pass

        details = [
            "windows_os_update_fallback=custom_os_command",
            f"windows_os_update_fallback_kb={kb}",
        ]
        if min_build:
            details.append(f"windows_os_update_fallback_min_build={min_build}")
        details.append(f"windows_os_update_fallback_result={'SUCCESS' if fb_code == 0 else 'FAILED'}")
        combined_stdout = "\n".join(
            [line for line in [stdout, *details, str(fb_out or "").strip()] if str(line).strip()]
        )

        if fb_code == 0:
            return 0, combined_stdout, ""

        combined_stderr = "\n".join(
            [
                line
                for line in [
                    str(stderr or "").strip(),
                    "windows-os-update fallback custom-os-command failed",
                    str(fb_err or "").strip(),
                ]
                if str(line).strip()
            ]
        )
        return status_code, combined_stdout, combined_stderr

    def _latest_windows_os_update_hint(self, agent_id: str) -> Dict[str, Any]:
        hint: Dict[str, Any] = {
            "fallback": False,
            "execution_id": None,
            "reason": "",
            "profile": "",
            "updates_discovered": 0,
            "updates_applicable": 0,
            "updates_skipped_non_target": 0,
        }
        agent = str(agent_id or "").strip()
        if not agent:
            return hint

        conn = None
        row = None
        try:
            from db.database import connect  # Imported lazily to keep module startup lightweight.

            conn = connect()
            row = conn.execute(
                text(
                    """
                    SELECT
                        e.id AS execution_id,
                        COALESCE(e.status, '') AS execution_status,
                        COALESCE(t.ok, false) AS target_ok,
                        COALESCE(t.stdout, '') AS stdout,
                        COALESCE(t.stderr, '') AS stderr
                    FROM execution_targets t
                    JOIN executions e ON e.id = t.execution_id
                    WHERE t.agent_id = :agent_id
                      AND LOWER(COALESCE(e.action, '')) = 'windows-os-update'
                    ORDER BY e.id DESC
                    LIMIT 1
                    """
                ),
                {"agent_id": agent},
            ).fetchone()
        except Exception:
            row = None
        finally:
            if conn is not None:
                conn.close()

        if not row:
            return hint

        rec = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
        stdout = str(rec.get("stdout") or "")
        stderr = str(rec.get("stderr") or "")
        metrics = self._extract_c2f_evidence_metrics(stdout)

        profile = str(metrics.get("update_profile") or "").strip()
        discovered = max(0, _to_int(metrics.get("updates_discovered"), 0))
        applicable = max(0, _to_int(metrics.get("updates_applicable"), 0))
        skipped_non_target = max(0, _to_int(metrics.get("updates_skipped_non_target"), 0))
        baseline_required = self._parse_bool_metric(metrics.get("baseline_required"), False)

        failure_blob = f"{stdout}\n{stderr}".lower()
        patch_failure = (
            "failed - patch not applied" in failure_blob
            or "no applicable updates were found" in failure_blob
            or "expected minimum build" in failure_blob
        )
        if not baseline_required and patch_failure:
            # Backfill for historical runs that did not emit baseline_required.
            baseline_required = True
        all_discovered_skipped_non_target = (
            discovered > 0 and applicable == 0 and skipped_non_target >= discovered
        )
        status_failed = str(rec.get("execution_status") or "").strip().upper() == "FAILED"
        target_ok = bool(rec.get("target_ok"))
        fallback = (
            (status_failed or not target_ok)
            and baseline_required
            and profile.lower() == "standard-cumulative"
            and all_discovered_skipped_non_target
            and patch_failure
        )

        reason = ""
        if fallback:
            reason = "latest_standard_cumulative_run_filtered_all_discovered_updates_as_non_target"

        hint.update(
            {
                "fallback": fallback,
                "execution_id": rec.get("execution_id"),
                "reason": reason,
                "profile": profile,
                "updates_discovered": discovered,
                "updates_applicable": applicable,
                "updates_skipped_non_target": skipped_non_target,
            }
        )
        return hint

    def _execute_windows_patch(
        self,
        target: Dict[str, Any],
        *,
        context: Dict[str, Any],
        timeout_seconds: int,
        action_id: str = "patch-windows",
    ) -> tuple[int, str, str]:
        """
        Patch Windows via a SYSTEM scheduled task, while streaming evidence.

        Why:
        - WinRM `-EncodedCommand` length limits make large inline scripts brittle.
        - Windows Update COM API often requires SYSTEM to reliably download/install.
        - We want incremental, live evidence in the UI (polling endpoint log file).
        """
        exec_tag = self._execution_tag(context)
        agent_id = str(target.get("agent_id") or "").strip()
        requested_action_id = str(action_id or "patch-windows").strip().lower() or "patch-windows"
        effective_action_id = requested_action_id
        fallback_hint: Dict[str, Any] | None = None
        if requested_action_id == "windows-os-update" and self.windows_os_update_profile_fallback:
            fallback_hint = self._latest_windows_os_update_hint(agent_id)
            if fallback_hint.get("fallback"):
                effective_action_id = "patch-windows"

        script_path = self._windows_action_script_path("patch-windows")
        log_file = r"C:\Click2Fix\logs\executions.log"
        result_dir = r"C:\Click2Fix\results"
        result_file = rf"{result_dir}\patch-windows-{exec_tag}.json"
        task_name = f"C2F_patch_windows_{exec_tag}"

        # schtasks.exe /TR has a hard length limit (~261 chars). Keep it short and let the
        # script derive default log/result paths from ExecId.
        tr = (
            "powershell.exe -NoProfile -ExecutionPolicy Bypass "
            f'-File "{script_path}" '
            f"-ExecId {exec_tag} -AgentId {agent_id} -ActionId {effective_action_id}"
        )

        start_script = (
            "$ErrorActionPreference='Stop';"
            "$ProgressPreference='SilentlyContinue';"
            f"$sp={_ps_quote(script_path)};"
            "if(-not (Test-Path $sp)){ throw ('patch-windows script missing at '+$sp); };"
            f"$rd={_ps_quote(result_dir)};"
            "New-Item -ItemType Directory -Path $rd -Force | Out-Null;"
            f"$rf={_ps_quote(result_file)};"
            "Remove-Item -Path $rf -Force -ErrorAction SilentlyContinue;"
            f"$tn={_ps_quote(task_name)};"
            f"$tr={_ps_quote(tr)};"
            "try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { };"
            "$dt=(Get-Date).AddMinutes(5);"
            "$act=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $tr;"
            "$trg=New-ScheduledTaskTrigger -Once -At $dt;"
            "$set=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
            "Register-ScheduledTask -TaskName $tn -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null;"
            "Start-ScheduledTask -TaskName $tn;"
            "try { Disable-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue | Out-Null } catch { };"
            "Write-Output 'patch-windows task started';"
        )

        # Kick off the task. Keep a small timeout here; the long work happens in the task.
        start_code, start_out, start_err = self._run_winrm(target, start_script, timeout_seconds=60)
        if start_code != 0:
            stderr = (start_err or start_out or "Failed to start patch-windows task").strip()
            return 1, "", stderr

        deadline = time.time() + max(30, int(timeout_seconds or 120))
        needle = f" exec={exec_tag} agent={agent_id} action={effective_action_id} "
        sent: set[str] = set()
        sent_order: List[str] = []
        terminal_status: Optional[tuple[str, str]] = None

        poll_log_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$lf={_ps_quote(log_file)};"
            f"$needle={_ps_quote(needle)};"
            "if(Test-Path $lf){"
            "Get-Content -Path $lf -Tail 200 | Select-String -SimpleMatch $needle | ForEach-Object { $_.Line }"
            "}"
        )

        poll_result_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$rf={_ps_quote(result_file)};"
            "if(Test-Path $rf){ Get-Content -Path $rf -Raw }"
        )

        def poll_once() -> Optional[Dict[str, Any]]:
            nonlocal terminal_status
            # Stream any new log evidence.
            try:
                _, out, _ = self._run_winrm(target, poll_log_script, timeout_seconds=30)
            except Exception:
                out = ""
            lines = [ln.strip() for ln in str(out or "").splitlines() if ln.strip()]
            for ln in reversed(lines):
                if " status=SUCCESS" in ln:
                    msg = ""
                    if " message=" in ln:
                        msg = ln.split(" message=", 1)[1].strip()
                    terminal_status = ("SUCCESS", msg)
                    break
                if " status=FAILED" in ln:
                    msg = ""
                    if " message=" in ln:
                        msg = ln.split(" message=", 1)[1].strip()
                    terminal_status = ("FAILED", msg)
                    break
            new_lines = [ln for ln in lines if ln not in sent]
            if new_lines:
                for ln in new_lines:
                    sent.add(ln)
                    sent_order.append(ln)
                self._emit_target_log(target, context, new_lines)

            # Check result file.
            try:
                _, payload, _ = self._run_winrm(target, poll_result_script, timeout_seconds=30)
            except Exception:
                payload = ""
            raw = str(payload or "").strip()
            if not raw:
                if terminal_status is not None:
                    status, msg = terminal_status
                    if status == "SUCCESS":
                        return {
                            "ok": True,
                            "summary": msg or f"{action_id} completed",
                        }
                    return {
                        "ok": False,
                        "summary": msg or f"{action_id} failed on endpoint",
                        "error": msg or f"{action_id} failed on endpoint",
                    }
                return None
            try:
                return json.loads(raw.lstrip("\ufeff"))
            except Exception:
                # If the file is being written, try again on the next loop.
                return None

        result_obj: Optional[Dict[str, Any]] = None
        while time.time() < deadline:
            result_obj = poll_once()
            if result_obj is not None:
                break
            time.sleep(2)

        # Best-effort cleanup.
        cleanup_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$tn={_ps_quote(task_name)};"
            "try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { };"
        )
        try:
            self._run_winrm(target, cleanup_script, timeout_seconds=30)
        except Exception:
            pass

        # One last poll to capture tail evidence after task completion.
        try:
            result_obj = result_obj or poll_once()
        except Exception:
            pass

        if result_obj is None:
            stderr = "Timed out waiting for patch result"
            stdout = "\n".join("C2F_LOG " + ln for ln in sent_order[-50:])
            return 1, stdout, stderr

        ok = bool(result_obj.get("ok"))
        summary = str(result_obj.get("summary") or "").strip()
        error = str(result_obj.get("error") or "").strip()
        stdout_lines = []
        if requested_action_id != effective_action_id and (fallback_hint or {}).get("fallback"):
            prev_exec = str((fallback_hint or {}).get("execution_id") or "").strip() or "unknown"
            fallback_reason = str((fallback_hint or {}).get("reason") or "profile_fallback").strip()
            stdout_lines.append(
                "profile_override=requested:"
                + requested_action_id
                + "|effective:"
                + effective_action_id
                + "|source_execution:"
                + prev_exec
                + "|reason:"
                + fallback_reason
            )
        if summary:
            stdout_lines.append(summary)
        stdout_lines.extend("C2F_LOG " + ln for ln in sent_order[-200:])
        stdout = "\n".join([ln for ln in stdout_lines if ln])
        stderr = error if not ok else ""
        return (0 if ok else 1), stdout, stderr

    def _execute_windows_script_task(
        self,
        target: Dict[str, Any],
        *,
        context: Dict[str, Any],
        timeout_seconds: int,
        action_id: str,
        script_action_id: str,
        script_args: Optional[Dict[str, Any]] = None,
    ) -> tuple[int, str, str]:
        """
        Run a long Windows action as a scheduled task and stream execution log evidence.

        This avoids long blocking WinRM calls and lets the UI receive incremental logs.
        """
        exec_tag = self._execution_tag(context)
        agent_id = str(target.get("agent_id") or "").strip()
        script_path = self._windows_action_script_path(script_action_id)
        task_suffix = "".join(ch for ch in str(script_action_id or "action") if ch.isalnum() or ch in {"-", "_"})
        task_suffix = task_suffix.replace("-", "_")
        safe_exec_tag = "".join(ch for ch in str(exec_tag or "") if ch.isalnum() or ch in {"-", "_"})
        if not safe_exec_tag:
            safe_exec_tag = f"adhoc{int(time.time())}"
        safe_agent = "".join(ch for ch in str(agent_id or "") if ch.isalnum() or ch in {"-", "_"})
        if not safe_agent:
            safe_agent = "agent"
        # SYSTEM-run scheduled tasks may not be able to append to files created under
        # service-user-owned paths. Use a shared public path so both WinRM user and
        # SYSTEM context can write/read the same execution log reliably.
        log_file = rf"C:\Users\Public\Click2Fix\logs\{task_suffix}-{safe_exec_tag}-{safe_agent}.log"
        task_name = f"C2F_{task_suffix}_{exec_tag}"

        def _cli_quote(value: Any) -> str:
            text = str(value if value is not None else "")
            return '"' + text.replace('"', '""') + '"'

        param_tokens = [
            f"-ExecId {_cli_quote(exec_tag)}",
            f"-AgentId {_cli_quote(agent_id)}",
            f"-LogFile {_cli_quote(log_file)}",
        ]
        if str(action_id or "").strip().lower() != str(script_action_id or "").strip().lower():
            param_tokens.append(f"-ActionId {_cli_quote(action_id)}")

        default_args_by_script: Dict[str, Dict[str, Any]] = {
            "package-update": {
                "PackageSpec": "all",
                "Version": "",
                "MaxRuntimeSeconds": 1800,
            },
            "malware-scan": {
                "Scope": "quick",
                "MaxRuntimeSeconds": 600,
            },
            "threat-hunt-persistence": {
                "MaxRuntimeSeconds": 900,
            },
            "custom-os-command": {
                "RunAsSystem": False,
                "VerifyKb": "",
                "VerifyMinBuild": "",
                "VerifyStdoutContains": "",
                "MaxRuntimeSeconds": 1800,
            },
        }
        script_defaults = default_args_by_script.get(str(script_action_id or "").strip().lower(), {})

        for key, value in (script_args or {}).items():
            if value is None:
                continue
            key_name = "".join(ch for ch in str(key) if ch.isalnum())
            if not key_name:
                continue
            if isinstance(value, str) and value == "":
                continue
            default_value = script_defaults.get(key_name)
            if default_value is not None:
                try:
                    if isinstance(default_value, int):
                        if int(value) == int(default_value):
                            continue
                    elif str(value).strip().lower() == str(default_value).strip().lower():
                        continue
                except Exception:
                    pass
            if isinstance(value, bool):
                bool_literal = "$true" if value else "$false"
                param_tokens.append(f"-{key_name}:{bool_literal}")
            else:
                param_tokens.append(f"-{key_name} {_cli_quote(value)}")

        def _build_invoke_tokens(override_run_as_system: Optional[bool] = None) -> str:
            invoke_parts = list(param_tokens)
            if override_run_as_system is not None:
                bool_literal = "$true" if override_run_as_system else "$false"
                replaced = False
                for idx, token in enumerate(invoke_parts):
                    if str(token).strip().lower().startswith("-runassystem:"):
                        invoke_parts[idx] = f"-RunAsSystem:{bool_literal}"
                        replaced = True
                        break
                if not replaced:
                    invoke_parts.append(f"-RunAsSystem:{bool_literal}")
            return " ".join(invoke_parts)

        def _run_direct_script(override_run_as_system: Optional[bool] = None) -> tuple[int, str, str]:
            # Direct WinRM fallback path avoids ScheduledTask command-line limits.
            invoke_tokens = _build_invoke_tokens(override_run_as_system)
            direct_script = (
                "$ErrorActionPreference='Stop';"
                "$ProgressPreference='SilentlyContinue';"
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('script missing at '+$sp); };"
                f"$out=(& $sp {invoke_tokens} 2>&1 | Out-String);"
                "$rc=0;"
                "if($LASTEXITCODE -ne $null){ try{ $rc=[int]$LASTEXITCODE } catch { $rc=1 } };"
                "if($rc -ne 0){ throw $out };"
                "Write-Output $out;"
            )
            return self._run_winrm(target, direct_script, timeout_seconds=timeout_seconds)

        script_action = str(script_action_id or "").strip().lower()
        run_as_system = False
        if script_action == "custom-os-command":
            run_as_system = _bool((script_args or {}).get("RunAsSystem"), False)
            if not run_as_system:
                return _run_direct_script()

        tr = (
            "-NoProfile -ExecutionPolicy Bypass "
            f'-File "{script_path}" '
            + " ".join(param_tokens)
        )
        if action_id == "package-update":
            package_spec = str((script_args or {}).get("PackageSpec") or "all")
            has_space_sensitive_arg = any(ch.isspace() for ch in package_spec.strip()) or ('"' in package_spec)
            if len(tr) >= 250 or has_space_sensitive_arg:
                version = str((script_args or {}).get("Version") or "")
                direct_script = self._build_windows_script(
                    action_id,
                    [package_spec, version],
                    context=context,
                    target=target,
                )
                return self._run_winrm(target, direct_script, timeout_seconds=timeout_seconds)

        start_script = (
            "$ErrorActionPreference='Stop';"
            "$ProgressPreference='SilentlyContinue';"
            f"$sp={_ps_quote(script_path)};"
            "if(-not (Test-Path $sp)){ throw ('script missing at '+$sp); };"
            f"$lf={_ps_quote(log_file)};"
            "$ld=Split-Path -Parent $lf;"
            "if($ld){ New-Item -ItemType Directory -Path $ld -Force | Out-Null };"
            "if(Test-Path $lf){ try { Clear-Content -Path $lf -Force -ErrorAction SilentlyContinue } catch { } } "
            "else { try { New-Item -ItemType File -Path $lf -Force | Out-Null } catch { } };"
            f"$tn={_ps_quote(task_name)};"
            f"$tr={_ps_quote(tr)};"
            "try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { };"
            "$dt=(Get-Date).AddMinutes(5);"
            "$act=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $tr;"
            "$trg=New-ScheduledTaskTrigger -Once -At $dt;"
            "$set=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
            "Register-ScheduledTask -TaskName $tn -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null;"
            "Start-ScheduledTask -TaskName $tn;"
            "Write-Output 'task started';"
        )

        start_code, start_out, start_err = self._run_winrm(target, start_script, timeout_seconds=60)
        if start_code != 0:
            stderr = (start_err or start_out or f"Failed to start {action_id} task").strip()
            normalized = stderr.lower()
            fallback_markers = (
                "command line is too long",
                "invalid argument/option",
                "cannot find the file specified",
                "the system cannot find the file specified",
            )
            if any(marker in normalized for marker in fallback_markers):
                return _run_direct_script()
            return 1, "", stderr

        start_ts = time.time()
        deadline = start_ts + max(30, int(timeout_seconds or 120))
        needle = f" exec={exec_tag} agent={agent_id} action={action_id} "
        sent: set[str] = set()
        sent_order: List[str] = []
        terminal_status: Optional[tuple[str, str]] = None
        task_nonrunning_polls = 0
        last_task_state = "starting"
        last_task_result_code: Optional[int] = None
        last_task_result_hex = ""
        last_task_run_time = ""
        inconclusive_result_since: Optional[float] = None
        terminal_flush_since: Optional[float] = None
        last_heartbeat_emit = 0.0

        poll_log_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$lf={_ps_quote(log_file)};"
            f"$needle={_ps_quote(needle)};"
            "if(Test-Path $lf){"
            "Get-Content -Path $lf -Tail 300 | Select-String -SimpleMatch $needle | ForEach-Object { $_.Line }"
            "}"
        )

        poll_task_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$tn={_ps_quote(task_name)};"
            "$t=Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue;"
            "if(-not $t){ Write-Output 'state=missing;result=;hex=;run='; }"
            "else {"
            "$ti=Get-ScheduledTaskInfo -TaskName $tn -ErrorAction SilentlyContinue;"
            "$state='unknown';"
            "if($ti -and $ti.State){ $state=([string]$ti.State).ToLower(); };"
            "$result='';"
            "$hex='';"
            "$run='';"
            "if($ti){"
            "if($ti.LastTaskResult -ne $null){"
            "try { $result=[string][int64]$ti.LastTaskResult } catch { $result=[string]$ti.LastTaskResult };"
            "try { "
            "$raw=[int64]$ti.LastTaskResult; "
            "if($raw -lt 0){ $hex=('0x{0:X8}' -f ([uint32]($raw + 0x100000000))) } "
            "else { $hex=('0x{0:X8}' -f ([uint32]$raw)) } "
            "} catch { $hex='' };"
            "};"
            "try { if($ti.LastRunTime){ $run=([DateTime]$ti.LastRunTime).ToString('o') } } catch { };"
            "};"
            "Write-Output ('state='+$state+';result='+$result+';hex='+$hex+';run='+$run);"
            "}"
        )

        def _latest_evidence(lines: List[str], key: str = "") -> str:
            for ln in reversed(lines):
                marker = " evidence="
                idx = ln.find(marker)
                if idx < 0:
                    continue
                payload = ln[idx + len(marker) :].strip()
                if not payload:
                    continue
                if key:
                    prefix = f"{key}="
                    if payload.lower().startswith(prefix.lower()):
                        return payload[len(prefix) :].strip()
                    continue
                return payload
            return ""

        def _task_state() -> Dict[str, Any]:
            try:
                _, out, _ = self._run_winrm(target, poll_task_script, timeout_seconds=30)
                line = str(out or "").strip().splitlines()[-1].strip()
                state = "unknown"
                result_code: Optional[int] = None
                result_hex = ""
                run_time = ""
                for chunk in line.split(";"):
                    part = chunk.strip()
                    if part.startswith("state="):
                        value = part.split("=", 1)[1].strip().lower()
                        if value:
                            state = value
                    elif part.startswith("result="):
                        value = part.split("=", 1)[1].strip()
                        if re.fullmatch(r"-?\d+", value or ""):
                            try:
                                result_code = int(value)
                            except Exception:
                                result_code = None
                    elif part.startswith("hex="):
                        result_hex = part.split("=", 1)[1].strip()
                    elif part.startswith("run="):
                        run_time = part.split("=", 1)[1].strip()
                return {
                    "state": state,
                    "result_code": result_code,
                    "result_hex": result_hex,
                    "run_time": run_time,
                }
            except Exception:
                return {
                    "state": "unknown",
                    "result_code": None,
                    "result_hex": "",
                    "run_time": "",
                }

        def _parse_run_time_epoch(value: str) -> Optional[float]:
            raw = str(value or "").strip()
            if not raw:
                return None
            try:
                normalized = raw.replace("Z", "+00:00")
                # PowerShell may emit seven fractional digits (e.g. .0000000+05:30).
                if "." in normalized:
                    head, tail = normalized.split(".", 1)
                    frac = ""
                    tz = ""
                    for idx, ch in enumerate(tail):
                        if ch in "+-Z":
                            frac = tail[:idx]
                            tz = tail[idx:]
                            break
                    if not frac and tail:
                        frac = tail
                        tz = ""
                    if len(frac) > 6:
                        frac = frac[:6]
                    normalized = head + "." + frac + tz if frac else head + tz
                return datetime.fromisoformat(normalized).timestamp()
            except Exception:
                return None

        def poll_once() -> Optional[Dict[str, Any]]:
            nonlocal terminal_status, task_nonrunning_polls, last_task_state
            nonlocal last_task_result_code, last_task_result_hex, last_task_run_time
            nonlocal inconclusive_result_since
            nonlocal terminal_flush_since
            try:
                _, out, _ = self._run_winrm(target, poll_log_script, timeout_seconds=30)
            except Exception:
                out = ""

            lines = [ln.strip() for ln in str(out or "").splitlines() if ln.strip()]
            for ln in reversed(lines):
                if " status=SUCCESS" in ln:
                    msg = ""
                    if " message=" in ln:
                        msg = ln.split(" message=", 1)[1].strip()
                    terminal_status = ("SUCCESS", msg)
                    break
                if " status=FAILED" in ln:
                    msg = ""
                    if " message=" in ln:
                        msg = ln.split(" message=", 1)[1].strip()
                    terminal_status = ("FAILED", msg)
                    break

            new_lines = [ln for ln in lines if ln not in sent]
            if new_lines:
                for ln in new_lines:
                    sent.add(ln)
                    sent_order.append(ln)
                self._emit_target_log(target, context, new_lines)

            if terminal_status is not None:
                terminal_flush_since = None
                status, msg = terminal_status
                latest_err = _latest_evidence(lines, "error")
                latest_stdout_preview = _latest_evidence(lines, "stdout_preview")
                latest_summary = (
                    latest_stdout_preview
                    or _latest_evidence(lines, "scan_summary")
                    or _latest_evidence(lines, "summary")
                    or _latest_evidence(lines, "outcome")
                )
                if status == "SUCCESS":
                    return {"ok": True, "summary": msg or latest_summary or f"{action_id} completed"}
                return {
                    "ok": False,
                    "summary": msg or latest_err or latest_summary or f"{action_id} failed on endpoint",
                    "error": msg or latest_err or f"{action_id} failed on endpoint",
                }

            task_state = _task_state()
            state = str(task_state.get("state") or "unknown").strip().lower()
            last_task_state = state
            last_task_result_code = task_state.get("result_code")
            last_task_result_hex = str(task_state.get("result_hex") or "").strip()
            last_task_run_time = str(task_state.get("run_time") or "").strip()
            if state in {"running", "queued"}:
                task_nonrunning_polls = 0
                inconclusive_result_since = None
                terminal_flush_since = None
                return None

            task_nonrunning_polls += 1
            # Scheduled-task state can transiently report non-running while log lines
            # are still flushing; wait for a few polls before concluding failure.
            if task_nonrunning_polls < 5:
                return None

            latest_err = _latest_evidence(lines, "error")
            latest_outcome = _latest_evidence(lines, "outcome")
            latest_stdout_preview = _latest_evidence(lines, "stdout_preview")
            latest_summary = (
                latest_stdout_preview
                or _latest_evidence(lines, "scan_summary")
                or _latest_evidence(lines, "summary")
                or _latest_evidence(lines, "outcome")
            )
            if latest_err:
                return {
                    "ok": False,
                    "summary": latest_err,
                    "error": latest_err,
                }
            if latest_outcome:
                outcome_u = str(latest_outcome).strip().upper()
                if outcome_u in {"FAILED", "ERROR"}:
                    return {
                        "ok": False,
                        "summary": latest_summary or f"{action_id} reported {outcome_u} outcome",
                        "error": latest_summary or f"{action_id} reported {outcome_u} outcome",
                    }
                if outcome_u in {"SUCCESS", "WAITING_REBOOT"}:
                    return {
                        "ok": True,
                        "summary": latest_summary or f"{action_id} completed",
                    }
            if isinstance(last_task_result_code, int):
                run_epoch = _parse_run_time_epoch(last_task_run_time)
                has_current_evidence = bool(lines or sent_order)
                if run_epoch is not None and run_epoch < (start_ts - 2) and not has_current_evidence:
                    # LastTaskResult/LastRunTime can lag and still reflect a prior task run.
                    # Do not classify this execution until we see a fresh run timestamp.
                    now = time.time()
                    if inconclusive_result_since is None:
                        inconclusive_result_since = now
                    stale_grace_seconds = min(
                        180,
                        max(45, int(max(60, int(timeout_seconds or 0)) / 4)),
                    )
                    if (now - inconclusive_result_since) < stale_grace_seconds:
                        return None
                    stale_msg = (
                        f"{action_id} scheduled task did not start for this execution "
                        f"(stale last_run={last_task_run_time})"
                    )
                    return {
                        "ok": False,
                        "summary": stale_msg,
                        "error": stale_msg,
                    }

                if last_task_result_code == 0:
                    if not latest_summary:
                        now = time.time()
                        if terminal_flush_since is None:
                            terminal_flush_since = now
                        flush_grace_seconds = min(
                            20,
                            max(6, int(max(60, int(timeout_seconds or 0)) / 10)),
                        )
                        if (now - terminal_flush_since) < flush_grace_seconds:
                            return None
                    else:
                        terminal_flush_since = None
                    inconclusive_result_since = None
                    return {
                        "ok": True,
                        "summary": latest_summary
                        or f"{action_id} completed (task result=0 without explicit terminal status log)",
                    }

                # Task Scheduler can report TASK_RUNNING while the task is legitimately
                # still in progress. Keep polling until overall timeout.
                if last_task_result_code == 267009:  # 0x00041301 TASK_RUNNING
                    inconclusive_result_since = None
                    terminal_flush_since = None
                    return None

                # Other transient statuses can appear briefly while the task is still
                # being dispatched. Treat these as inconclusive for a bounded grace period.
                transient_scheduler_codes = {
                    267008,  # 0x00041300 TASK_READY
                    267011,  # 0x00041303 TASK_HAS_NOT_RUN
                }
                if last_task_result_code in transient_scheduler_codes:
                    now = time.time()
                    if inconclusive_result_since is None:
                        inconclusive_result_since = now
                    grace_seconds = min(
                        180,
                        max(45, int(max(60, int(timeout_seconds or 0)) / 4)),
                    )
                    if (now - inconclusive_result_since) < grace_seconds:
                        return None
                else:
                    inconclusive_result_since = None

                # Non-zero task result may be observed just before the script flushes
                # terminal error/status lines to the log file. Give one short grace window
                # so we can surface the real endpoint error instead of generic task_result.
                if not latest_err:
                    now = time.time()
                    if terminal_flush_since is None:
                        terminal_flush_since = now
                    flush_grace_seconds = min(
                        20,
                        max(6, int(max(60, int(timeout_seconds or 0)) / 10)),
                    )
                    if (now - terminal_flush_since) < flush_grace_seconds:
                        return None
                else:
                    terminal_flush_since = None

                task_result = last_task_result_hex or str(last_task_result_code)
                detail_suffix = f"; last_run={last_task_run_time}" if last_task_run_time else ""
                task_failure_msg = (
                    latest_summary
                    or f"{action_id} failed with task_result={task_result} without explicit terminal status log{detail_suffix}"
                )
                return {
                    "ok": False,
                    "summary": task_failure_msg,
                    "error": task_failure_msg,
                }
            missing_status_msg = (
                latest_summary
                or f"{action_id} finished without terminal status evidence (status=SUCCESS/FAILED)"
            )
            return {
                "ok": False,
                "summary": missing_status_msg,
                "error": missing_status_msg,
            }

        result_obj: Optional[Dict[str, Any]] = None
        while time.time() < deadline:
            result_obj = poll_once()
            if result_obj is not None:
                break
            now = time.time()
            if (now - last_heartbeat_emit) >= 15:
                elapsed = int(now - start_ts)
                self._emit_target_log(
                    target,
                    context,
                    [f"heartbeat action={action_id} state={last_task_state} elapsed_seconds={elapsed}"],
                )
                last_heartbeat_emit = now
            time.sleep(2)

        cleanup_script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$ProgressPreference='SilentlyContinue';"
            f"$tn={_ps_quote(task_name)};"
            "try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { };"
        )
        try:
            self._run_winrm(target, cleanup_script, timeout_seconds=30)
        except Exception:
            pass

        try:
            result_obj = result_obj or poll_once()
        except Exception:
            pass

        if result_obj is None:
            timeout_msg = f"Timed out waiting for {action_id} result after {int(timeout_seconds or 0)}s"
            if last_task_result_code == 267009:
                timeout_msg += " (Task Scheduler still reports RUNNING: 0x00041301)"
                if last_task_run_time:
                    timeout_msg += f"; last_run={last_task_run_time}"
            if action_id == "package-update":
                stop_script = (
                    "$ErrorActionPreference='SilentlyContinue';"
                    "$ProgressPreference='SilentlyContinue';"
                    "foreach($n in @('winget.exe','WindowsPackageManagerServer.exe','AppInstallerCLI.exe')){"
                    "$ps2=Get-CimInstance Win32_Process -Filter (\"Name='\"+$n+\"'\");"
                    "foreach($p in $ps2){ try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }catch{} }"
                    "};"
                )
                try:
                    self._run_winrm(target, stop_script, timeout_seconds=45)
                except Exception:
                    pass
            if action_id == "malware-scan":
                stop_script = (
                    "$ErrorActionPreference='SilentlyContinue';"
                    "$ProgressPreference='SilentlyContinue';"
                    f"$exec={_ps_quote(exec_tag)};"
                    "$procs=Get-CimInstance Win32_Process | "
                    "Where-Object { $_.CommandLine -and $_.CommandLine -match '\\\\Click2Fix\\\\scripts\\\\malware-scan\\.ps1' -and $_.CommandLine -match $exec };"
                    "foreach($p in $procs){ try{ Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop }catch{} };"
                )
                try:
                    self._run_winrm(target, stop_script, timeout_seconds=45)
                except Exception:
                    pass
            stdout = "\n".join("C2F_LOG " + ln for ln in sent_order[-200:])
            return 1, stdout, timeout_msg

        ok = bool(result_obj.get("ok"))
        summary = str(result_obj.get("summary") or "").strip()
        error = str(result_obj.get("error") or "").strip()

        stdout_lines = []
        if summary:
            stdout_lines.append(summary)
        stdout_lines.extend("C2F_LOG " + ln for ln in sent_order[-300:])
        stdout = "\n".join([ln for ln in stdout_lines if ln])
        stderr = error if not ok else ""
        return (0 if ok else 1), stdout, stderr

    def _run_winrm(self, target: Dict[str, Any], script: str, *, timeout_seconds: Optional[int] = None):
        if not self.windows_cfg["enabled"]:
            raise HTTPException(status_code=400, detail="Windows endpoint connector is disabled")
        agent_id = str(target.get("agent_id") or "")
        ip = str(target.get("ip") or "")
        creds = self._windows_credentials_for_agent(agent_id)
        username = creds.get("username", "")
        password = creds.get("password", "")
        if not username or not password:
            raise HTTPException(
                status_code=400,
                detail=f"Windows endpoint connector credentials are missing for agent {agent_id}",
            )

        try:
            import winrm
        except ImportError as exc:
            raise HTTPException(status_code=500, detail="pywinrm is not installed in backend") from exc

        cert_validation = "validate" if self.windows_cfg["verify_tls"] else "ignore"
        base_session_kwargs: Dict[str, Any] = {
            "auth": (username, password),
            "transport": self.windows_cfg["transport"],
            "server_cert_validation": cert_validation,
        }
        if timeout_seconds:
            # pywinrm expects operation_timeout_sec <= read_timeout_sec.
            op_timeout = max(20, int(timeout_seconds))
            read_timeout = max(op_timeout + 60, op_timeout)
            base_session_kwargs["operation_timeout_sec"] = op_timeout
            base_session_kwargs["read_timeout_sec"] = read_timeout

        cfg_scheme = "https" if self.windows_cfg["use_https"] else "http"
        cfg_port = int(self.windows_cfg["port"])
        candidates = [
            (cfg_scheme, cfg_port),
            ("https", 5986),
            ("http", 5985),
            ("https", 5985),
            ("http", 5986),
        ]
        deduped: List[tuple[str, int]] = []
        seen = set()
        for scheme, port in candidates:
            key = (scheme, int(port))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(key)

        def _is_connectivity_error(message: str) -> bool:
            text = (message or "").lower()
            return any(
                token in text
                for token in [
                    "failed to establish a new connection",
                    "max retries exceeded",
                    "connection refused",
                    "timed out",
                    "connection aborted",
                    "name or service not known",
                    "temporary failure in name resolution",
                    "connection reset by peer",
                    "no route to host",
                ]
            )

        attempt_errors: List[str] = []
        last_exc: Exception | None = None

        for scheme, port in deduped:
            endpoint = f"{scheme}://{ip}:{port}/wsman"
            session_kwargs = dict(base_session_kwargs)
            try:
                try:
                    session = winrm.Session(endpoint, **session_kwargs)
                except TypeError:
                    # Older pywinrm versions may not accept timeout kwargs.
                    session_kwargs.pop("operation_timeout_sec", None)
                    session_kwargs.pop("read_timeout_sec", None)
                    session = winrm.Session(endpoint, **session_kwargs)
                result = session.run_ps(script)
                stdout = (result.std_out or b"").decode(errors="replace")
                stderr = (result.std_err or b"").decode(errors="replace")
                return int(result.status_code), stdout, stderr
            except Exception as exc:
                last_exc = exc
                msg = str(exc).strip() or exc.__class__.__name__
                attempt_errors.append(f"{endpoint} -> {msg}")
                # For clear auth/permission failures we still try other listeners once,
                # but do not hide the failure context from the caller.
                continue

        detail = (
            f"WinRM connection failed for agent {agent_id} ({ip}). "
            f"Tried endpoints: {'; '.join(attempt_errors[:5])}"
        )
        if attempt_errors and _is_connectivity_error(" | ".join(attempt_errors)):
            detail += ". Endpoint WinRM listener is unavailable; ensure WinRM service/listener is enabled on the endpoint."
            raise HTTPException(status_code=503, detail=detail)
        if last_exc is not None:
            raise HTTPException(status_code=502, detail=detail)
        raise HTTPException(status_code=502, detail=f"WinRM execution failed for agent {agent_id} ({ip})")

    def _run_ssh(self, ip: str, script: str, *, timeout_seconds: Optional[int] = None):
        if not self.linux_cfg["enabled"]:
            raise HTTPException(status_code=400, detail="Linux endpoint connector is disabled")
        if not self.linux_cfg["username"]:
            raise HTTPException(status_code=400, detail="Linux endpoint connector username is missing")

        try:
            import paramiko
        except ImportError as exc:
            raise HTTPException(status_code=500, detail="paramiko is not installed in backend") from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        timeout = int(timeout_seconds or self.default_timeout or 120)
        try:
            client.connect(
                hostname=ip,
                port=self.linux_cfg["port"],
                username=self.linux_cfg["username"],
                password=self.linux_cfg["password"] or None,
                key_filename=self.linux_cfg["key_file"] or None,
                timeout=timeout,
            )
            stdin, stdout, stderr = client.exec_command(script, timeout=timeout)
            stdout.channel.settimeout(timeout)
            stderr.channel.settimeout(timeout)
            status_code = stdout.channel.recv_exit_status()
            out_text = stdout.read().decode(errors="replace")
            err_text = stderr.read().decode(errors="replace")
            return int(status_code), out_text, err_text
        finally:
            client.close()

    def _wrap_windows_script(self, action_id: str, inner: str, context: Dict[str, Any], target: Dict[str, Any]) -> str:
        exec_tag = self._execution_tag(context)
        agent_id = str(target.get("agent_id") or "")
        safe_action = str(action_id or "").replace("'", "''")
        safe_agent = agent_id.replace("'", "''")
        safe_exec = exec_tag.replace("'", "''")
        # Minimal endpoint-side audit trail (no secrets). Tail is emitted back to the orchestrator.
        return (
            "$ErrorActionPreference='Stop';"
            "$ProgressPreference='SilentlyContinue';"
            "$logDir='C:\\\\Click2Fix\\\\logs';"
            "New-Item -ItemType Directory -Path $logDir -Force | Out-Null;"
            "$logFile=Join-Path $logDir 'executions.log';"
            f"$c2fExec='{safe_exec}';"
            f"$c2fAgent='{safe_agent}';"
            f"$c2fAction='{safe_action}';"
            "$c2fUser=whoami;"
            "$c2fIsAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
            "$c2fStart=Get-Date -Format o;"
            "Add-Content -Path $logFile -Value ($c2fStart+' exec='+$c2fExec+' agent='+$c2fAgent+' action='+$c2fAction+' user='+$c2fUser+' status=START');"
            "function C2F-Evidence { param([string]$Message) "
            "try { $ts=Get-Date -Format o; "
            "Add-Content -Path $logFile -Value ($ts+' exec='+$c2fExec+' agent='+$c2fAgent+' action='+$c2fAction+' user='+$c2fUser+' evidence='+$Message); "
            "} catch { } };"
            "try{"
            "if($c2fAction -ne 'endpoint-healthcheck' -and (-not $c2fIsAdmin)){ throw 'Admin privileges are required for endpoint actions'; };"
            + inner +
            ";$c2fStatus='SUCCESS'}"
            "catch{ $c2fStatus='FAILED'; throw }"
            "finally{"
            "$c2fEnd=Get-Date -Format o;"
            "Add-Content -Path $logFile -Value ($c2fEnd+' exec='+$c2fExec+' agent='+$c2fAgent+' action='+$c2fAction+' user='+$c2fUser+' status='+$c2fStatus);"
            "$needle=(' exec='+$c2fExec+' agent='+$c2fAgent+' action='+$c2fAction+' ');"
            "Get-Content -Path $logFile | Select-String -SimpleMatch $needle | Select-Object -Last 50 | ForEach-Object { Write-Output ('C2F_LOG '+$_.Line) }"
            "}"
        )

    def _build_windows_script(
        self,
        action_id: str,
        action_args: List[str],
        context: Optional[Dict[str, Any]] = None,
        target: Optional[Dict[str, Any]] = None,
    ) -> str:
        args = [str(v) for v in (action_args or [])]
        aid = str(action_id or "").strip()
        if aid == "endpoint-healthcheck":
            inner = (
                "$hostName=$env:COMPUTERNAME;"
                "$userName=whoami;"
                "$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);"
                "$now=Get-Date -Format o;"
                "Write-Output ('healthcheck ok');"
                "Write-Output ('host='+$hostName);"
                "Write-Output ('user='+$userName);"
                "Write-Output ('is_admin='+$isAdmin);"
                "Write-Output ('time='+$now)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid in {"restart-wazuh", "sca-rescan"}:
            inner = (
                "$svc=Get-Service -Name 'WazuhSvc','Wazuh' -ErrorAction SilentlyContinue | Select-Object -First 1;"
                "if(-not $svc){ throw 'Wazuh service not found'; };"
                "Restart-Service -Name $svc.Name -Force;"
                "Write-Output ('restarted '+$svc.Name)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid in {"firewall-drop", "host-deny", "netsh"}:
            if not args:
                raise HTTPException(status_code=400, detail=f"{aid} requires ip argument")
            ip = _ps_quote(args[0])
            inner = (
                f"$ip={ip};"
                "$rule='C2F-'+$ip;"
                "netsh advfirewall firewall add rule name=$rule dir=in action=block remoteip=$ip | Out-Null;"
                "Write-Output ('blocked '+$ip)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "unblock-ip":
            if not args:
                raise HTTPException(status_code=400, detail="unblock-ip requires ip argument")
            ip = _ps_quote(args[0])
            inner = (
                f"$ip={ip};"
                "$rule='C2F-'+$ip;"
                "netsh advfirewall firewall delete rule name=$rule | Out-Null;"
                "Write-Output ('unblocked '+$ip)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid in {"route-null", "win_route-null", "win-route-null"}:
            if not args:
                raise HTTPException(status_code=400, detail=f"{aid} requires ip argument")
            ip = _ps_quote(args[0])
            inner = (
                f"$ip={ip};"
                "route DELETE $ip | Out-Null;"
                "route ADD $ip MASK 255.255.255.255 0.0.0.0 | Out-Null;"
                "Write-Output ('null-route '+$ip)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "kill-process":
            if not args:
                raise HTTPException(status_code=400, detail="kill-process requires pid argument")
            pid = int(args[0])
            inner = (
                f"$procId={pid};"
                "$p=Get-Process -Id $procId -ErrorAction SilentlyContinue;"
                "if(-not $p){ Write-Output ('not running '+$procId); }"
                "else { Stop-Process -Id $procId -Force -ErrorAction Stop; Write-Output ('killed '+$procId) }"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "quarantine-file":
            if not args:
                raise HTTPException(status_code=400, detail="quarantine-file requires path argument")
            path = _ps_quote(args[0])
            inner = (
                f"$src={path};"
                "if(-not (Test-Path $src)){ Write-Output 'path not found (already removed)'; }"
                "else {"
                "$dst='C:\\\\Click2Fix\\\\Quarantine';"
                "New-Item -ItemType Directory -Path $dst -Force | Out-Null;"
                "$target=Join-Path $dst ((Get-Date -Format 'yyyyMMdd_HHmmss')+'_'+(Split-Path $src -Leaf));"
                "Move-Item -Path $src -Destination $target -Force;"
                "Write-Output $target"
                "}"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "malware-scan":
            script_path = self._windows_action_script_path(aid)
            scope = _ps_quote(args[0] if args else "quick")
            timeout_seconds = self._action_timeout_seconds(aid)
            max_runtime = max(120, int(timeout_seconds))
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('malware-scan script missing at '+$sp); };"
                f"$scope={scope};"
                f"$maxRuntime={max_runtime};"
                "$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile -Scope $scope -MaxRuntimeSeconds $maxRuntime 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "service-restart":
            if not args:
                raise HTTPException(status_code=400, detail="service-restart requires service argument")
            svc = _ps_quote(args[0])
            inner = (
                f"$svc={svc};"
                "Restart-Service -Name $svc -Force -ErrorAction Stop;"
                "Write-Output ('service restarted '+$svc)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "disable-account":
            if not args:
                raise HTTPException(status_code=400, detail="disable-account requires user argument")
            user = _ps_quote(args[0])
            inner = (
                f"$u={user};"
                "net user $u /active:no | Out-Null;"
                "Write-Output ('disabled '+$u)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "enable-account":
            if not args:
                raise HTTPException(status_code=400, detail="enable-account requires user argument")
            user = _ps_quote(args[0])
            inner = (
                f"$u={user};"
                "net user $u /active:yes | Out-Null;"
                "Write-Output ('enabled '+$u)"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid in {"patch-windows", "windows-os-update"}:
            # This action's logic is installed as a local script to avoid WinRM encoded-command length limits.
            script_path = self._windows_action_script_path("patch-windows")
            timeout_seconds = self._action_timeout_seconds(aid)
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('patch-windows script missing at '+$sp); };"
                "$rd='C:\\\\Click2Fix\\\\results';"
                "New-Item -ItemType Directory -Path $rd -Force | Out-Null;"
                "$rf=Join-Path $rd ('patch-windows-'+$c2fExec+'.json');"
                "Remove-Item -Path $rf -Force -ErrorAction SilentlyContinue;"
                "$tn=('C2F_patch_windows_'+$c2fExec);"
                "$tr=('powershell.exe -NoProfile -ExecutionPolicy Bypass -File '+$sp+' -ExecId '+$c2fExec+' -AgentId '+$c2fAgent+' -ActionId '+$c2fAction+' -LogFile '+$logFile+' -ResultFile '+$rf);"
                "try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { };"
                "$dt=(Get-Date).AddMinutes(5);"
                "$act=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $tr;"
                "$trg=New-ScheduledTaskTrigger -Once -At $dt;"
                "$set=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
                "Register-ScheduledTask -TaskName $tn -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null;"
                "Start-ScheduledTask -TaskName $tn;"
                "try { Disable-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue | Out-Null } catch { };"
                f"$dl=(Get-Date).AddSeconds({timeout_seconds});"
                "while((Get-Date) -lt $dl -and (-not (Test-Path $rf))){ Start-Sleep -Seconds 2 };"
                "try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { };"
                "if(-not (Test-Path $rf)){ throw 'Timed out waiting for patch result'; };"
                "$res=Get-Content -Path $rf -Raw | ConvertFrom-Json;"
                "if(-not $res.ok){ throw $res.error; };"
                "Write-Output $res.summary"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "package-update":
            script_path = self._windows_action_script_path(aid)
            pkg = _ps_quote(args[0] if args else "all")
            ver = _ps_quote(args[1] if len(args) > 1 else "")
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('package-update script missing at '+$sp); };"
                f"$pkg={pkg};"
                f"$ver={ver};"
                "$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile -PackageSpec $pkg -Version $ver 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "custom-os-command":
            if not args or not str(args[0]).strip():
                raise HTTPException(status_code=400, detail="custom-os-command requires command argument")
            cmd = _ps_quote(args[0])
            verify_kb = _ps_quote(args[1] if len(args) > 1 else "")
            verify_min_build = _ps_quote(args[2] if len(args) > 2 else "")
            verify_stdout_contains = _ps_quote(args[3] if len(args) > 3 else "")
            inner = (
                f"$cmd={cmd};"
                f"$verifyKbRaw={verify_kb};"
                f"$verifyBuild={verify_min_build};"
                f"$verifyContains={verify_stdout_contains};"
                "if(-not $cmd){ throw 'custom-os-command requires command argument'; };"
                "function C2F-CompareBuild { param([string]$Current,[string]$Required) "
                "$cParts=@(); foreach($part in ($Current -split '\\.')){ if($part -match '^\\d+$'){ $cParts += [int]$part } };"
                "$rParts=@(); foreach($part in ($Required -split '\\.')){ if($part -match '^\\d+$'){ $rParts += [int]$part } };"
                "if($cParts.Count -eq 0 -or $rParts.Count -eq 0){ return -1 };"
                "$max=[Math]::Max($cParts.Count,$rParts.Count);"
                "for($i=0; $i -lt $max; $i++){"
                "$cv=0; if($i -lt $cParts.Count){ $cv=[int]$cParts[$i] };"
                "$rv=0; if($i -lt $rParts.Count){ $rv=[int]$rParts[$i] };"
                "if($cv -gt $rv){ return 1 };"
                "if($cv -lt $rv){ return -1 };"
                "};"
                "return 0"
                "};"
                "$safe=$cmd.Replace('|','/');"
                "if($safe.Length -gt 220){ $safe=$safe.Substring(0,220)+'...' };"
                "C2F-Evidence ('custom_command='+$safe);"
                "$global:LASTEXITCODE=0;"
                "$out=(& ([ScriptBlock]::Create($cmd)) 2>&1 | Out-String);"
                "$rc=0;"
                "if($LASTEXITCODE -ne $null){ try{ $rc=[int]$LASTEXITCODE } catch { $rc=1 } };"
                "if($rc -ne 0){ throw ('custom-os-command failed rc='+$rc+' output='+$out) };"
                "$verifyKbRaw=($verifyKbRaw -replace '(?i)^\\s*kb','KB').Trim();"
                "if($verifyKbRaw){"
                "$kbDigits=($verifyKbRaw -replace '(?i)^KB','').Trim();"
                "if(-not $kbDigits -or $kbDigits -notmatch '^\\d+$'){ throw 'custom-os-command verify_kb must be KB followed by digits'; };"
                "$requiredKb=('KB'+$kbDigits);"
                "C2F-Evidence ('verify_kb_required='+$requiredKb);"
                "$kbMatch=Get-HotFix -Id $requiredKb -ErrorAction SilentlyContinue;"
                "if(-not $kbMatch){"
                "$kbMatch=Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID -eq $requiredKb } | Select-Object -First 1;"
                "};"
                "$kbPresent=$false; if($kbMatch){ $kbPresent=$true };"
                "C2F-Evidence ('verify_kb_present='+$kbPresent);"
                "if(-not $kbPresent){ throw ('custom-os-command verification failed: required KB not found: '+$requiredKb) };"
                "};"
                "$verifyBuild=$verifyBuild.Trim();"
                "if($verifyBuild){"
                "if($verifyBuild -notmatch '^\\d+(?:\\.\\d+){1,3}$'){ throw 'custom-os-command verify_min_build must be numeric (example: 19045.6937)'; };"
                "$cv=Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -ErrorAction Stop;"
                "$build=[string]$cv.CurrentBuildNumber; if(-not $build){ $build=[string]$cv.CurrentBuild };"
                "$ubr=[string]$cv.UBR; if(-not $ubr){ $ubr='0' };"
                "$currentBuild=($build+'.'+$ubr);"
                "C2F-Evidence ('verify_min_build_required='+$verifyBuild);"
                "C2F-Evidence ('verify_min_build_current='+$currentBuild);"
                "$cmp=C2F-CompareBuild -Current $currentBuild -Required $verifyBuild;"
                "$buildMet=($cmp -ge 0);"
                "C2F-Evidence ('verify_min_build_met='+$buildMet);"
                "if(-not $buildMet){ throw ('custom-os-command verification failed: minimum build '+$verifyBuild+' required, observed '+$currentBuild) };"
                "};"
                "$verifyContains=$verifyContains.Trim();"
                "if($verifyContains){"
                "$safeNeedle=$verifyContains.Replace('|','/').Replace(\"`r\",' ').Replace(\"`n\",' ');"
                "if($safeNeedle.Length -gt 220){ $safeNeedle=$safeNeedle.Substring(0,220)+'...' };"
                "C2F-Evidence ('verify_stdout_contains_required='+$safeNeedle);"
                "$contains=([string]$out).IndexOf($verifyContains,[System.StringComparison]::OrdinalIgnoreCase) -ge 0;"
                "C2F-Evidence ('verify_stdout_contains_met='+$contains);"
                "if(-not $contains){ throw ('custom-os-command verification failed: stdout missing required text: '+$verifyContains) };"
                "};"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "rollback-kb":
            if not args:
                raise HTTPException(status_code=400, detail="rollback-kb requires kb argument")
            kb_raw = str(args[0]).strip().upper().replace("KB", "")
            if not kb_raw.isdigit():
                raise HTTPException(status_code=400, detail="rollback-kb requires numeric KB value")
            inner = (
                f"Start-Process -FilePath \"$env:SystemRoot\\System32\\wusa.exe\" -ArgumentList '/uninstall /kb:{kb_raw} /quiet /norestart' -Wait;"
                f"Write-Output 'rollback KB{kb_raw} triggered'"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "threat-hunt-persistence":
            script_path = self._windows_action_script_path(aid)
            timeout_seconds = self._action_timeout_seconds(aid)
            max_runtime = max(180, int(timeout_seconds))
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('threat-hunt-persistence script missing at '+$sp); };"
                f"$maxRuntime={max_runtime};"
                "$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile -MaxRuntimeSeconds $maxRuntime 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid in {"ioc-scan", "toc-scan"}:
            script_path = self._windows_action_script_path("ioc-scan")
            ioc_set = _ps_quote(args[0] if args else "default")
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('ioc-scan script missing at '+$sp); };"
                f"$iocSet={ioc_set};"
                "$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile -IocSet $iocSet 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "yara-scan":
            if not args:
                raise HTTPException(status_code=400, detail="yara-scan requires path argument")
            script_path = self._windows_action_script_path("yara-scan")
            scan_path = _ps_quote(args[0])
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('yara-scan script missing at '+$sp); };"
                f"$scanPath={scan_path};"
                "$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile -ScanPath $scanPath 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "collect-forensics":
            script_path = self._windows_action_script_path("collect-forensics")
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('collect-forensics script missing at '+$sp); };"
                "$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "collect-memory":
            script_path = self._windows_action_script_path("collect-memory")
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('collect-memory script missing at '+$sp); };"
                "$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        if aid == "hash-blocklist":
            if not args:
                raise HTTPException(status_code=400, detail="hash-blocklist requires sha256 argument")
            script_path = self._windows_action_script_path("hash-blocklist")
            sha = _ps_quote(args[0])
            inner = (
                f"$sp={_ps_quote(script_path)};"
                "if(-not (Test-Path $sp)){ throw ('hash-blocklist script missing at '+$sp); };"
                f"$out=(& $sp -ExecId $c2fExec -AgentId $c2fAgent -ActionId $c2fAction -LogFile $logFile -Sha256Hash {sha} 2>&1 | Out-String);"
                "if($LASTEXITCODE -ne 0){ throw $out };"
                "Write-Output $out"
            )
            return self._wrap_windows_script(aid, inner, context or {}, target or {})
        raise HTTPException(status_code=400, detail=f"Unsupported action for Windows endpoint mode: {aid}")

    def _wrap_linux_script(self, action_id: str, inner: str, context: Dict[str, Any], target: Dict[str, Any]) -> str:
        exec_tag = self._execution_tag(context)
        agent_id = str(target.get("agent_id") or "")
        safe_action = _sh_quote(action_id or "")
        safe_agent = _sh_quote(agent_id)
        safe_exec = _sh_quote(exec_tag)
        return (
            "set -e; "
            "logfile='/var/tmp/click2fix_executions.log'; "
            f"exec_id={safe_exec}; agent_id={safe_agent}; action_id={safe_action}; "
            "user=$(id -un); ts=$(date -Iseconds); "
            "echo \"$ts exec=$exec_id agent=$agent_id action=$action_id user=$user status=START\" | sudo tee -a \"$logfile\" >/dev/null; "
            "c2f_evidence(){ msg=\"$*\"; ts=$(date -Iseconds); echo \"$ts exec=$exec_id agent=$agent_id action=$action_id user=$user evidence=$msg\" | sudo tee -a \"$logfile\" >/dev/null; }; "
            f"{inner}; "
            "ts2=$(date -Iseconds); "
            "echo \"$ts2 exec=$exec_id agent=$agent_id action=$action_id user=$user status=SUCCESS\" | sudo tee -a \"$logfile\" >/dev/null; "
            "grep \"exec=$exec_id agent=$agent_id action=$action_id \" \"$logfile\" | tail -n 50 | sed 's/^/C2F_LOG /'"
        )

    def _build_linux_script(
        self,
        action_id: str,
        action_args: List[str],
        context: Optional[Dict[str, Any]] = None,
        target: Optional[Dict[str, Any]] = None,
    ) -> str:
        args = [str(v) for v in (action_args or [])]
        aid = str(action_id or "").strip()
        if aid == "endpoint-healthcheck":
            inner = "echo 'healthcheck ok'; echo \"host=$(hostname)\"; echo \"user=$(id -un)\"; echo \"is_admin=$(id -u | awk '{print ($1==0)?\"true\":\"false\"}')\"; date -Iseconds"
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid in {"patch-linux", "fleet-software-update"}:
            inner = (
                "set -e; "
                "if [ -f /etc/os-release ]; then . /etc/os-release; "
                "c2f_evidence \"os_name=${PRETTY_NAME:-$NAME}\"; "
                "c2f_evidence \"os_version=${VERSION_ID:-unknown}\"; "
                "fi; "
                "up_before=$(apt list --upgradable 2>/dev/null | sed '1d' | sed '/^$/d' || true); "
                "count_before=$(printf '%s\\n' \"$up_before\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "c2f_evidence updates_applicable=$count_before; "
                "idx=0; "
                "while IFS= read -r line; do "
                "[ -z \"$line\" ] && continue; "
                "pkg=$(printf '%s' \"$line\" | awk -F/ '{print $1}'); "
                "ver=$(printf '%s' \"$line\" | awk '{print $2}'); "
                "c2f_evidence \"available_update_${idx}=${pkg}|${ver}\"; "
                "c2f_evidence \"update_${idx}=${pkg}|${ver}\"; "
                "idx=$((idx+1)); "
                "done <<EOF\n$up_before\nEOF\n"
                "sudo apt-get update -y >/tmp/c2f_apt_update.log 2>&1; "
                "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/tmp/c2f_apt_upgrade.log 2>&1; "
                "up_after=$(apt list --upgradable 2>/dev/null | sed '1d' | sed '/^$/d' || true); "
                "count_after=$(printf '%s\\n' \"$up_after\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "idx=0; "
                "while IFS= read -r line; do "
                "[ -z \"$line\" ] && continue; "
                "pkg=$(printf '%s' \"$line\" | awk -F/ '{print $1}'); "
                "ver=$(printf '%s' \"$line\" | awk '{print $2}'); "
                "c2f_evidence \"remaining_update_${idx}=${pkg}|${ver}\"; "
                "idx=$((idx+1)); "
                "done <<EOF\n$up_after\nEOF\n"
                "installed_est=0; "
                "idx=0; "
                "while IFS= read -r line; do "
                "[ -z \"$line\" ] && continue; "
                "pkg=$(printf '%s' \"$line\" | awk -F/ '{print $1}'); "
                "ver=$(printf '%s' \"$line\" | awk '{print $2}'); "
                "if ! printf '%s\\n' \"$up_after\" | awk -F/ '{print $1}' | grep -Fxq \"$pkg\"; then "
                "installed_est=$((installed_est+1)); "
                "c2f_evidence \"installed_update_${idx}=${pkg}|${ver}\"; "
                "idx=$((idx+1)); "
                "fi; "
                "done <<EOF\n$up_before\nEOF\n"
                "failed_est=0; "
                "if [ \"$count_after\" -gt 0 ]; then failed_est=$count_after; fi; "
                "c2f_evidence updates_installed_estimate=$installed_est; "
                "c2f_evidence updates_failed_estimate=$failed_est; "
                "c2f_evidence updates_remaining=$count_after; "
                "reboot_needed='false'; "
                "if [ -f /var/run/reboot-required ]; then "
                "reboot_needed='true'; "
                "c2f_evidence reboot_required=true; "
                "c2f_evidence reboot_pending=true; "
                "c2f_evidence reboot_scheduled=false; "
                "c2f_evidence reboot_policy=deferred_user_controlled; "
                "else "
                "c2f_evidence reboot_required=false; "
                "c2f_evidence reboot_pending=false; "
                "c2f_evidence reboot_scheduled=false; "
                "c2f_evidence reboot_policy=not_required; "
                "fi; "
                "outcome='SUCCESS'; "
                "if [ \"$count_after\" -gt 0 ]; then outcome='PARTIAL'; fi; "
                "if [ \"$count_after\" -eq 0 ] && [ \"$reboot_needed\" = 'true' ]; then outcome='WAITING_REBOOT'; fi; "
                "c2f_evidence outcome=$outcome; "
                "echo \"linux update complete: outcome=$outcome applicable=$count_before installed_est=$installed_est remaining=$count_after\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "package-update":
            pkg = _sh_quote(args[0] if args else "all")
            ver = _sh_quote(args[1] if len(args) > 1 else "")
            inner = (
                f"pkg={pkg}; ver={ver}; "
                "pkgs=$(printf '%s' \"$pkg\" | tr ',;\\n\\r' ' '); "
                "all_mode=0; "
                "if [ -z \"$(printf '%s' \"$pkgs\" | tr -d '[:space:]')\" ]; then all_mode=1; fi; "
                "if [ \"$pkgs\" = \"all\" ] || [ \"$pkgs\" = \"*\" ]; then all_mode=1; fi; "
                "sudo apt-get update -y >/tmp/c2f_pkg_update.log 2>&1; "
                "applicable=0; installable=0; installed=0; failed=0; remaining=0; idx=0; "
                "if [ \"$all_mode\" -eq 1 ]; then "
                "up_before=$(apt list --upgradable 2>/dev/null | sed '1d' | sed '/^$/d' || true); "
                "while IFS= read -r line; do "
                "[ -z \"$line\" ] && continue; "
                "p=$(printf '%s' \"$line\" | awk -F/ '{print $1}'); "
                "v=$(printf '%s' \"$line\" | awk '{print $2}'); "
                "c2f_evidence \"available_update_${idx}=${p}|${p}|available=${v}\"; "
                "idx=$((idx+1)); "
                "done <<EOF\n$up_before\nEOF\n"
                "applicable=$(printf '%s\\n' \"$up_before\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "installable=$applicable; "
                "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/tmp/c2f_pkg_upgrade_all.log 2>&1 || true; "
                "up_after=$(apt list --upgradable 2>/dev/null | sed '1d' | sed '/^$/d' || true); "
                "remaining=$(printf '%s\\n' \"$up_after\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "installed=$((applicable-remaining)); if [ \"$installed\" -lt 0 ]; then installed=0; fi; "
                "failed=$remaining; "
                "idx=0; "
                "while IFS= read -r line; do "
                "[ -z \"$line\" ] && continue; "
                "p=$(printf '%s' \"$line\" | awk -F/ '{print $1}'); "
                "v=$(printf '%s' \"$line\" | awk '{print $2}'); "
                "c2f_evidence \"remaining_update_${idx}=${p}|${p}|available=${v}\"; "
                "idx=$((idx+1)); "
                "done <<EOF\n$up_after\nEOF\n"
                "else "
                "for p in $pkgs; do "
                "[ -z \"$p\" ] && continue; "
                "applicable=$((applicable+1)); installable=$((installable+1)); "
                "inst_before=$(dpkg-query -W -f='${Version}' \"$p\" 2>/dev/null || true); "
                "cand=$(apt-cache policy \"$p\" 2>/dev/null | awk '/Candidate:/ {print $2; exit}'); "
                "if [ -n \"$ver\" ]; then "
                "c2f_evidence \"available_update_${idx}=${p}|${p}|requested_version=${ver}|installed_before=${inst_before}|candidate=${cand}\"; "
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \"$p=$ver\" >/tmp/c2f_pkg_${idx}.log 2>&1 || rc=$?; "
                "else "
                "c2f_evidence \"available_update_${idx}=${p}|${p}|installed_before=${inst_before}|candidate=${cand}\"; "
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \"$p\" >/tmp/c2f_pkg_${idx}.log 2>&1 || rc=$?; "
                "fi; "
                "rc=${rc:-0}; "
                "inst_after=$(dpkg-query -W -f='${Version}' \"$p\" 2>/dev/null || true); "
                "if [ \"$rc\" -ne 0 ]; then "
                "failed=$((failed+1)); "
                "msg=$(tail -n 2 /tmp/c2f_pkg_${idx}.log 2>/dev/null | tr '\\n' ' ' | tr '|' '/'); "
                "c2f_evidence \"failed_update_${idx}=${p}|${p}|rc=${rc}|message=${msg}\"; "
                "else "
                "if [ -n \"$inst_after\" ] && [ \"$inst_after\" != \"$inst_before\" ]; then "
                "installed=$((installed+1)); "
                "c2f_evidence \"installed_update_${idx}=${p}|${p}|version=${inst_after}\"; "
                "else "
                "remaining=$((remaining+1)); "
                "c2f_evidence \"remaining_update_${idx}=${p}|${p}|version=${inst_after}\"; "
                "fi; "
                "fi; "
                "idx=$((idx+1)); unset rc; "
                "done; "
                "fi; "
                "c2f_evidence updates_applicable=$applicable; "
                "c2f_evidence updates_installable=$installable; "
                "c2f_evidence updates_installed=$installed; "
                "c2f_evidence updates_failed=$failed; "
                "c2f_evidence updates_remaining=$remaining; "
                "outcome='SUCCESS'; if [ \"$failed\" -gt 0 ] || [ \"$remaining\" -gt 0 ]; then outcome='PARTIAL'; fi; "
                "c2f_evidence outcome=$outcome; "
                "echo \"package update complete: outcome=$outcome applicable=$applicable installable=$installable installed=$installed failed=$failed remaining=$remaining\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "custom-os-command":
            if not args or not str(args[0]).strip():
                raise HTTPException(status_code=400, detail="custom-os-command requires command argument")
            cmd = _sh_quote(args[0])
            verify_kb = _sh_quote(args[1] if len(args) > 1 else "")
            verify_min_build = _sh_quote(args[2] if len(args) > 2 else "")
            verify_stdout_contains = _sh_quote(args[3] if len(args) > 3 else "")
            inner = (
                f"cmd={cmd}; verify_kb={verify_kb}; verify_min_build={verify_min_build}; verify_contains={verify_stdout_contains}; "
                "if [ -z \"$(printf '%s' \"$cmd\" | tr -d '[:space:]')\" ]; then echo 'custom-os-command requires command argument' >&2; exit 1; fi; "
                "if [ -n \"$(printf '%s' \"$verify_kb\" | tr -d '[:space:]')\" ] || [ -n \"$(printf '%s' \"$verify_min_build\" | tr -d '[:space:]')\" ]; then "
                "echo 'custom-os-command verification fields verify_kb/verify_min_build are supported only on Windows endpoints' >&2; exit 1; "
                "fi; "
                "safe_cmd=$(printf '%s' \"$cmd\" | tr '|' '/' | cut -c1-220); "
                "c2f_evidence \"custom_command=$safe_cmd\"; "
                "set +e; out=$(bash -lc \"$cmd\" 2>&1); rc=$?; set -e; "
                "printf '%s\\n' \"$out\"; "
                "if [ \"$rc\" -ne 0 ]; then echo \"custom-os-command failed rc=$rc\" >&2; exit \"$rc\"; fi; "
                "if [ -n \"$(printf '%s' \"$verify_contains\" | tr -d '[:space:]')\" ]; then "
                "safe_contains=$(printf '%s' \"$verify_contains\" | tr '\\n\\r|' '   /' | cut -c1-220); "
                "c2f_evidence \"verify_stdout_contains_required=$safe_contains\"; "
                "if printf '%s' \"$out\" | grep -Fqi -- \"$verify_contains\"; then "
                "c2f_evidence \"verify_stdout_contains_met=true\"; "
                "else "
                "c2f_evidence \"verify_stdout_contains_met=false\"; "
                "echo \"custom-os-command verification failed: stdout missing required text: $verify_contains\" >&2; exit 1; "
                "fi; "
                "fi; "
                "echo 'custom-os-command completed'"
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid in {"route-null", "firewall-drop", "host-deny"}:
            if not args:
                raise HTTPException(status_code=400, detail=f"{aid} requires ip argument")
            ip = _sh_quote(args[0])
            inner = f"sudo ip route replace blackhole {ip}"
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "unblock-ip":
            if not args:
                raise HTTPException(status_code=400, detail="unblock-ip requires ip argument")
            ip = _sh_quote(args[0])
            inner = f"sudo ip route del blackhole {ip} || true"
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "kill-process":
            if not args:
                raise HTTPException(status_code=400, detail="kill-process requires pid argument")
            pid = int(args[0])
            inner = f"sudo kill -9 {pid}"
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "service-restart":
            if not args:
                raise HTTPException(status_code=400, detail="service-restart requires service argument")
            svc = _sh_quote(args[0])
            inner = f"sudo systemctl restart {svc}"
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid in {"restart-wazuh", "sca-rescan"}:
            inner = "sudo systemctl restart wazuh-agent || sudo service wazuh-agent restart"
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "quarantine-file":
            if not args:
                raise HTTPException(status_code=400, detail="quarantine-file requires path argument")
            src = _sh_quote(args[0])
            inner = (
                "set -e; dst='/var/tmp/click2fix_quarantine'; "
                "sudo mkdir -p \"$dst\"; "
                f"sudo mv {src} \"$dst/\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid in {"ioc-scan", "toc-scan"}:
            ioc_set = _sh_quote(args[0] if args else "default")
            scan_type = "toc" if aid == "toc-scan" else "ioc"
            scan_label = "TOC" if aid == "toc-scan" else "IOC"
            report_prefix = "toc-scan" if aid == "toc-scan" else "ioc-scan"
            inner = (
                f"ioc_set={ioc_set}; "
                f"scan_type={_sh_quote(scan_type)}; "
                f"scan_label={_sh_quote(scan_label)}; "
                "report_dir='/var/tmp/click2fix_reports'; "
                "sudo mkdir -p \"$report_dir\"; "
                f"report_path=\"$report_dir/{report_prefix}-${{exec_id}}.txt\"; "
                "scan_started=$(date -Iseconds); "
                "patterns='powershell -enc|rundll32|mimikatz|certutil -urlcache|base64 -d|curl[[:space:]].*https?://|nc[[:space:]]+-e'; "
                "ps_out=$(ps axww -o pid=,user=,comm=,args= 2>/dev/null || true); "
                "total_examined=$(printf '%s\\n' \"$ps_out\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "hits=$(printf '%s\\n' \"$ps_out\" | grep -E -i \"$patterns\" || true); "
                "match_count=$(printf '%s\\n' \"$hits\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "scan_status='CLEAN'; if [ \"$match_count\" -gt 0 ]; then scan_status='MATCH'; fi; "
	                "{ "
	                "echo \"scan_type=$scan_type\"; "
	                "echo \"scan_scope=$ioc_set\"; "
	                "echo \"scan_started=$scan_started\"; "
	                "echo \"scan_status=$scan_status\"; "
	                "echo \"scan_total_examined=$total_examined\"; "
	                "echo \"scan_matches=$match_count\"; "
	                "echo \"-- process_hits --\"; "
	                "printf '%s\\n' \"$hits\"; "
	                "echo \"-- recommendation --\"; "
	                "echo \"Investigate matched commands, validate legitimacy, and isolate host if malicious behavior is confirmed.\"; "
	                "} | sudo tee \"$report_path\" >/dev/null; "
	                "idx=0; "
	                "while IFS= read -r line; do "
	                "[ -z \"$line\" ] && continue; "
	                "safe=$(printf '%s' \"$line\" | tr '|' '/' | cut -c1-220); "
	                "rec='Investigate process lineage and terminate/quarantine if unauthorized.'; "
	                "if printf '%s' \"$line\" | grep -Eiq 'powershell[[:space:]]+-enc|base64[[:space:]]+-d'; then rec='Decode payload and block malicious PowerShell/script execution.'; fi; "
	                "if printf '%s' \"$line\" | grep -Eiq 'mimikatz|rundll32|regsvr32|certutil[[:space:]]+-urlcache|bitsadmin'; then rec='Potential credential theft or LOLBin abuse: isolate host and investigate persistence.'; fi; "
	                "safe_rec=$(printf '%s' \"$rec\" | tr '|' '/' | cut -c1-220); "
	                "c2f_evidence \"scan_hit_${idx}=$scan_type|process|detail=${safe}|recommendation=${safe_rec}\"; "
	                "idx=$((idx+1)); "
	                "[ \"$idx\" -ge 50 ] && break; "
	                "done <<EOF\n$hits\nEOF\n"
                "c2f_evidence \"scan_type=$scan_type\"; "
                "c2f_evidence \"scan_scope=$ioc_set\"; "
                "c2f_evidence scan_engine=builtin-patterns; "
                "c2f_evidence \"scan_report_path=$report_path\"; "
                "c2f_evidence \"scan_total_examined=$total_examined\"; "
                "c2f_evidence \"scan_matches=$match_count\"; "
                "c2f_evidence \"scan_status=$scan_status\"; "
                "c2f_evidence \"artifact_0=report|$report_path|format=txt\"; "
                "c2f_evidence \"scan_summary=$scan_label scan complete: status=$scan_status matches=$match_count examined=$total_examined set=$ioc_set\"; "
                "echo \"$scan_label scan complete: status=$scan_status matches=$match_count examined=$total_examined set=$ioc_set\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "yara-scan":
            if not args:
                raise HTTPException(status_code=400, detail="yara-scan requires path argument")
            scan_path = _sh_quote(args[0])
            inner = (
                f"scan_path={scan_path}; "
                "if [ ! -e \"$scan_path\" ]; then echo \"scan path not found: $scan_path\" >&2; exit 1; fi; "
                "report_dir='/var/tmp/click2fix_reports'; "
                "sudo mkdir -p \"$report_dir\"; "
                "report_path=\"$report_dir/yara-scan-${exec_id}.txt\"; "
                "scan_started=$(date -Iseconds); "
                "yara_engine='fallback-grep'; "
                "hit_lines=''; "
                "if command -v yara >/dev/null 2>&1; then "
                "yara_engine='yara'; "
                "rule_file='/var/tmp/c2f_default_rules.yar'; "
                "cat > \"$rule_file\" <<'RULES'\n"
                "rule C2F_SuspiciousEncodedPowerShell {\n"
                "  strings:\n"
                "    $a = \"powershell -enc\" nocase\n"
                "    $b = \"mimikatz\" nocase\n"
                "    $c = \"rundll32\" nocase\n"
                "  condition:\n"
                "    any of them\n"
                "}\n"
                "RULES\n"
                "hit_lines=$(yara -r \"$rule_file\" \"$scan_path\" 2>/dev/null | head -n 200 || true); "
                "else "
                "hit_lines=$(grep -RIna -E \"powershell[[:space:]]+-enc|mimikatz|rundll32|certutil[[:space:]]+-urlcache|base64[[:space:]]+-d\" \"$scan_path\" 2>/dev/null | head -n 200 || true); "
                "fi; "
                "total_examined=$(find \"$scan_path\" -type f 2>/dev/null | head -n 2000 | wc -l | tr -d ' '); "
                "match_count=$(printf '%s\\n' \"$hit_lines\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "scan_status='CLEAN'; if [ \"$match_count\" -gt 0 ]; then scan_status='MATCH'; fi; "
                "{ "
                "echo \"scan_type=yara\"; "
                "echo \"scan_scope=$scan_path\"; "
                "echo \"scan_engine=$yara_engine\"; "
                "echo \"scan_started=$scan_started\"; "
                "echo \"scan_status=$scan_status\"; "
	                "echo \"scan_total_examined=$total_examined\"; "
	                "echo \"scan_matches=$match_count\"; "
	                "echo \"-- hits --\"; "
	                "printf '%s\\n' \"$hit_lines\"; "
	                "echo \"-- recommendation --\"; "
	                "echo \"Validate each matched file, quarantine untrusted artifacts, and hunt for related persistence.\"; "
	                "} | sudo tee \"$report_path\" >/dev/null; "
	                "idx=0; "
	                "while IFS= read -r line; do "
	                "[ -z \"$line\" ] && continue; "
	                "safe=$(printf '%s' \"$line\" | tr '|' '/' | cut -c1-220); "
	                "rec='Inspect matched file and quarantine if untrusted.'; "
	                "if printf '%s' \"$line\" | grep -Eiq 'mimikatz|powershell|rundll32|certutil'; then rec='Treat as high risk: isolate endpoint, remove payload, and rotate exposed credentials.'; fi; "
	                "safe_rec=$(printf '%s' \"$rec\" | tr '|' '/' | cut -c1-220); "
	                "c2f_evidence \"scan_hit_${idx}=yara|match|detail=${safe}|recommendation=${safe_rec}\"; "
	                "idx=$((idx+1)); "
	                "[ \"$idx\" -ge 100 ] && break; "
	                "done <<EOF\n$hit_lines\nEOF\n"
                "c2f_evidence scan_type=yara; "
                "c2f_evidence \"scan_scope=$scan_path\"; "
                "c2f_evidence \"scan_engine=$yara_engine\"; "
                "c2f_evidence \"scan_report_path=$report_path\"; "
                "c2f_evidence \"scan_total_examined=$total_examined\"; "
                "c2f_evidence \"scan_matches=$match_count\"; "
                "c2f_evidence \"scan_status=$scan_status\"; "
                "c2f_evidence \"scan_summary=YARA scan complete: status=$scan_status matches=$match_count examined=$total_examined path=$scan_path\"; "
                "echo \"YARA scan complete: status=$scan_status matches=$match_count examined=$total_examined path=$scan_path\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "collect-forensics":
            inner = (
                "report_dir='/var/tmp/click2fix_reports'; "
                "sudo mkdir -p \"$report_dir\"; "
                "report_path=\"$report_dir/forensics-${exec_id}.txt\"; "
                "scan_started=$(date -Iseconds); "
                "proc_rows=$(ps aux --sort=-%cpu 2>/dev/null | head -n 120 || true); "
                "conn_rows=$(ss -tunap 2>/dev/null | head -n 120 || true); "
                "user_rows=$(who 2>/dev/null || true); "
                "startup_rows=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 120 || true); "
                "proc_count=$(printf '%s\\n' \"$proc_rows\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "conn_count=$(printf '%s\\n' \"$conn_rows\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "startup_count=$(printf '%s\\n' \"$startup_rows\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "{ "
                "echo \"forensics_report\"; "
                "echo \"started_at=$scan_started\"; "
                "echo \"host=$(hostname)\"; "
                "echo \"user=$(id -un)\"; "
                "echo \"process_count=$proc_count\"; "
                "echo \"connection_count=$conn_count\"; "
                "echo \"startup_count=$startup_count\"; "
                "echo \"-- processes --\"; printf '%s\\n' \"$proc_rows\"; "
                "echo \"-- connections --\"; printf '%s\\n' \"$conn_rows\"; "
                "echo \"-- logged_users --\"; printf '%s\\n' \"$user_rows\"; "
                "echo \"-- startup_services --\"; printf '%s\\n' \"$startup_rows\"; "
                "} | sudo tee \"$report_path\" >/dev/null; "
                "c2f_evidence scan_type=forensics; "
                "c2f_evidence scan_engine=linux-native; "
                "c2f_evidence \"scan_report_path=$report_path\"; "
                "c2f_evidence \"scan_total_examined=$((proc_count + conn_count + startup_count))\"; "
                "c2f_evidence \"scan_matches=$startup_count\"; "
                "c2f_evidence scan_status=SUCCESS; "
                "c2f_evidence \"artifact_0=report|$report_path|format=txt\"; "
                "c2f_evidence \"scan_summary=Forensics collection complete: processes=$proc_count connections=$conn_count startup_items=$startup_count\"; "
                "echo \"Forensics collection complete: processes=$proc_count connections=$conn_count startup_items=$startup_count\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "collect-memory":
            inner = (
                "report_dir='/var/tmp/click2fix_reports'; "
                "sudo mkdir -p \"$report_dir\"; "
                "report_path=\"$report_dir/memory-${exec_id}.txt\"; "
                "scan_started=$(date -Iseconds); "
                "meminfo=$(cat /proc/meminfo 2>/dev/null || true); "
                "top_mem=$(ps axww -o pid=,user=,%mem=,rss=,command= --sort=-rss 2>/dev/null | head -n 80 || true); "
                "total_mb=$(awk '/MemTotal:/ {printf \"%.2f\", $2/1024}' /proc/meminfo 2>/dev/null || echo 0); "
                "free_mb=$(awk '/MemAvailable:/ {printf \"%.2f\", $2/1024}' /proc/meminfo 2>/dev/null || echo 0); "
                "top_count=$(printf '%s\\n' \"$top_mem\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "{ "
                "echo \"memory_report\"; "
                "echo \"started_at=$scan_started\"; "
                "echo \"host=$(hostname)\"; "
                "echo \"user=$(id -un)\"; "
                "echo \"total_memory_mb=$total_mb\"; "
                "echo \"available_memory_mb=$free_mb\"; "
                "echo \"top_process_count=$top_count\"; "
                "echo \"-- meminfo --\"; printf '%s\\n' \"$meminfo\"; "
                "echo \"-- top_processes --\"; printf '%s\\n' \"$top_mem\"; "
                "} | sudo tee \"$report_path\" >/dev/null; "
                "c2f_evidence scan_type=memory; "
                "c2f_evidence scan_engine=linux-native; "
                "c2f_evidence \"scan_report_path=$report_path\"; "
                "c2f_evidence \"scan_total_examined=$top_count\"; "
                "c2f_evidence scan_matches=0; "
                "c2f_evidence scan_status=SUCCESS; "
                "c2f_evidence \"artifact_0=report|$report_path|format=txt\"; "
                "c2f_evidence \"scan_summary=Memory collection complete: total_mb=$total_mb available_mb=$free_mb top_processes=$top_count\"; "
                "echo \"Memory collection complete: total_mb=$total_mb available_mb=$free_mb top_processes=$top_count\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "hash-blocklist":
            if not args:
                raise HTTPException(status_code=400, detail="hash-blocklist requires sha256 argument")
            sha = _sh_quote(args[0])
            inner = (
                f"sha={sha}; "
                "if ! printf '%s' \"$sha\" | grep -Eq '^[A-Fa-f0-9]{64}$'; then echo 'hash-blocklist requires valid SHA256 hash' >&2; exit 1; fi; "
                "sha=$(printf '%s' \"$sha\" | tr '[:upper:]' '[:lower:]'); "
                "list_dir='/var/tmp/click2fix_blocklist'; "
                "sudo mkdir -p \"$list_dir\"; "
                "list_path=\"$list_dir/sha256.txt\"; "
                "exists=0; "
                "if sudo test -f \"$list_path\" && sudo grep -Fxiq \"$sha\" \"$list_path\"; then exists=1; else echo \"$sha\" | sudo tee -a \"$list_path\" >/dev/null; fi; "
                "count=$(sudo awk 'NF{c++} END{print c+0}' \"$list_path\" 2>/dev/null || echo 0); "
                "state='ADDED'; if [ \"$exists\" -eq 1 ]; then state='EXISTS'; fi; "
                "c2f_evidence \"blocklist_hash=$sha\"; "
                "c2f_evidence \"blocklist_path=$list_path\"; "
                "c2f_evidence \"blocklist_entry_count=$count\"; "
                "c2f_evidence \"blocklist_status=$state\"; "
                "if [ \"$exists\" -eq 1 ]; then echo \"Hash already present in blocklist: $sha\"; else echo \"Hash added to blocklist: $sha\"; fi; "
                "echo \"blocklist=$list_path\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "malware-scan":
            scope = _sh_quote(args[0] if args else "quick")
            inner = (
                f"scan_scope={scope}; "
                "report_dir='/var/tmp/click2fix_reports'; "
                "sudo mkdir -p \"$report_dir\"; "
                "report_path=\"$report_dir/malware-scan-${exec_id}.txt\"; "
                "scan_started=$(date -Iseconds); "
                "engine='heuristic-process-patterns'; "
                "hits=''; "
                "total_examined=0; "
                "scan_raw=''; "
                "target_paths='/tmp /var/tmp /dev/shm'; "
                "if [ \"$scan_scope\" = 'full' ]; then target_paths='/'; fi; "
                "if command -v clamscan >/dev/null 2>&1; then "
                "engine='clamav'; "
                "scan_raw=$(clamscan -ri --infected $target_paths 2>&1 || true); "
                "hits=$(printf '%s\\n' \"$scan_raw\" | grep ' FOUND$' | head -n 200 || true); "
                "total_examined=$(printf '%s\\n' \"$scan_raw\" | awk -F': ' '/Scanned files:/ {print $2}' | tail -n1 | tr -d ' '); "
                "if [ -z \"$total_examined\" ]; then total_examined=0; fi; "
                "else "
                "proc_rows=$(ps axww -o pid=,user=,comm=,args= 2>/dev/null || true); "
                "total_examined=$(printf '%s\\n' \"$proc_rows\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "hits=$(printf '%s\\n' \"$proc_rows\" | grep -E -i 'mimikatz|xmrig|coinhive|miner|ransom|powershell[[:space:]]+-enc|/tmp/.*\\.sh' | head -n 120 || true); "
                "fi; "
                "match_count=$(printf '%s\\n' \"$hits\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "scan_status='CLEAN'; if [ \"$match_count\" -gt 0 ]; then scan_status='MATCH'; fi; "
                "{ "
                "echo 'Click2Fix Malware Scan Report'; "
                "echo \"execution_id=$exec_id\"; "
                "echo \"started_at=$scan_started\"; "
                "echo \"scope=$scan_scope\"; "
                "echo \"engine=$engine\"; "
                "echo \"status=$scan_status\"; "
                "echo \"total_examined=$total_examined\"; "
                "echo \"matches=$match_count\"; "
                "echo '-- findings --'; "
                "printf '%s\\n' \"$hits\"; "
                "echo '-- recommendation --'; "
                "echo 'Investigate matched artifacts/processes, isolate endpoint if malicious, and remove persistence.'; "
                "} | sudo tee \"$report_path\" >/dev/null; "
                "idx=0; "
                "while IFS= read -r line; do "
                "[ -z \"$line\" ] && continue; "
                "safe=$(printf '%s' \"$line\" | tr '|' '/' | cut -c1-220); "
                "rec='Investigate and terminate suspicious process or quarantine matched file.'; "
                "if printf '%s' \"$line\" | grep -Eiq 'mimikatz|ransom|xmrig|coinhive|miner'; then rec='Potential malware family hit: isolate host, collect memory, and rotate potentially exposed credentials.'; fi; "
                "safe_rec=$(printf '%s' \"$rec\" | tr '|' '/' | cut -c1-220); "
                "c2f_evidence \"scan_hit_${idx}=malware|indicator|detail=${safe}|recommendation=${safe_rec}\"; "
                "idx=$((idx+1)); "
                "[ \"$idx\" -ge 100 ] && break; "
                "done <<EOF\n$hits\nEOF\n"
                "c2f_evidence scan_type=malware; "
                "c2f_evidence \"scan_scope=$scan_scope\"; "
                "c2f_evidence \"scan_engine=$engine\"; "
                "c2f_evidence \"scan_report_path=$report_path\"; "
                "c2f_evidence \"scan_total_examined=$total_examined\"; "
                "c2f_evidence \"scan_matches=$match_count\"; "
                "c2f_evidence \"scan_status=$scan_status\"; "
                "c2f_evidence \"artifact_0=report|$report_path|format=txt\"; "
                "c2f_evidence \"scan_summary=Malware scan complete: status=$scan_status matches=$match_count examined=$total_examined engine=$engine scope=$scan_scope\"; "
                "echo \"Malware scan complete: status=$scan_status matches=$match_count examined=$total_examined engine=$engine scope=$scan_scope\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        if aid == "threat-hunt-persistence":
            inner = (
                "report_dir='/var/tmp/click2fix_reports'; "
                "sudo mkdir -p \"$report_dir\"; "
                "report_path=\"$report_dir/persistence-hunt-${exec_id}.txt\"; "
                "scan_started=$(date -Iseconds); "
                "cron_rows=$( (crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; grep -RIna -E '.' /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null | head -n 200) || true ); "
                "svc_rows=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 200 || true); "
                "rc_rows=$(cat /etc/rc.local 2>/dev/null || true); "
                "auto_rows=$(for d in /etc/xdg/autostart \"$HOME/.config/autostart\"; do [ -d \"$d\" ] || continue; find \"$d\" -maxdepth 2 -type f 2>/dev/null | head -n 200; done); "
                "auto_details=$(printf '%s\\n' \"$auto_rows\" | while IFS= read -r f; do [ -f \"$f\" ] || continue; line=$(head -n 20 \"$f\" 2>/dev/null | tr '\\n' ' '); printf '%s|%s\\n' \"$f\" \"$line\"; done); "
                "all_rows=$(printf '%s\\n%s\\n%s\\n%s\\n' \"$cron_rows\" \"$svc_rows\" \"$rc_rows\" \"$auto_details\"); "
                "total_examined=$(printf '%s\\n' \"$all_rows\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "hits=$(printf '%s\\n' \"$all_rows\" | grep -E -i 'curl|wget|nc[[:space:]]+-e|bash[[:space:]]+-c|python[[:space:]]+-c|base64|/tmp/|/dev/shm/|powershell|rundll32|regsvr32' | head -n 160 || true); "
                "match_count=$(printf '%s\\n' \"$hits\" | sed '/^$/d' | wc -l | tr -d ' '); "
                "scan_status='CLEAN'; if [ \"$match_count\" -gt 0 ]; then scan_status='MATCH'; fi; "
                "{ "
                "echo 'Click2Fix Persistence Hunt Report'; "
                "echo \"execution_id=$exec_id\"; "
                "echo \"started_at=$scan_started\"; "
                "echo \"status=$scan_status\"; "
                "echo \"total_examined=$total_examined\"; "
                "echo \"matches=$match_count\"; "
                "echo '-- findings --'; "
                "printf '%s\\n' \"$hits\"; "
                "echo '-- recommendation --'; "
                "echo 'Validate startup/task entries, remove unauthorized persistence, and quarantine referenced payloads.'; "
                "} | sudo tee \"$report_path\" >/dev/null; "
                "idx=0; "
                "while IFS= read -r line; do "
                "[ -z \"$line\" ] && continue; "
                "safe=$(printf '%s' \"$line\" | tr '|' '/' | cut -c1-220); "
                "rec='Review persistence entry owner/source and disable if unauthorized.'; "
                "if printf '%s' \"$line\" | grep -Eiq '/tmp/|/dev/shm/|base64|curl|wget|nc[[:space:]]+-e'; then rec='High-risk persistence path/command: isolate host and remove startup trigger after triage.'; fi; "
                "safe_rec=$(printf '%s' \"$rec\" | tr '|' '/' | cut -c1-220); "
                "c2f_evidence \"scan_hit_${idx}=persistence|entry|detail=${safe}|recommendation=${safe_rec}\"; "
                "idx=$((idx+1)); "
                "[ \"$idx\" -ge 120 ] && break; "
                "done <<EOF\n$hits\nEOF\n"
                "c2f_evidence scan_type=persistence; "
                "c2f_evidence scan_scope=startup+cron+services; "
                "c2f_evidence scan_engine=builtin-heuristics; "
                "c2f_evidence \"scan_report_path=$report_path\"; "
                "c2f_evidence \"scan_total_examined=$total_examined\"; "
                "c2f_evidence \"scan_matches=$match_count\"; "
                "c2f_evidence \"scan_status=$scan_status\"; "
                "c2f_evidence \"artifact_0=report|$report_path|format=txt\"; "
                "c2f_evidence \"scan_summary=Persistence hunt complete: status=$scan_status matches=$match_count examined=$total_examined\"; "
                "echo \"Persistence hunt complete: status=$scan_status matches=$match_count examined=$total_examined\""
            )
            return self._wrap_linux_script(aid, inner, context or {}, target or {})
        raise HTTPException(status_code=400, detail=f"Unsupported action for Linux endpoint mode: {aid}")

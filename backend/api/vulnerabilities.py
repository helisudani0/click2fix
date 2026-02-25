import re
from typing import Any, Dict, Iterable, List, Set

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text

from core.actions import list_actions
from core.indexer_client import IndexerClient
from core.security import require_role
from core.settings import SETTINGS
from core.time_utils import serialize_row
from core.wazuh_client import WazuhClient
from db.database import connect

router = APIRouter(prefix="/vulnerabilities")
indexer = IndexerClient()
client = WazuhClient()

_KNOWN_SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_DEFAULT_WINDOWS_PACKAGE_MAP: Dict[str, str] = {
    "oracle virtualbox": "Oracle.VirtualBox",
    "visual studio community 2022": "Microsoft.VisualStudio.2022.Community",
    "visual studio build tools": "Microsoft.VisualStudio.BuildTools",
    "visual studio code": "Microsoft.VisualStudioCode",
    "mongodb": "MongoDB.Server",
    "mongodb compass": "MongoDB.Compass.Full",
    "node js": "OpenJS.NodeJS.22",
    "npm": "OpenJS.NodeJS.22",
    "vlc media player": "VideoLAN.VLC",
    "wireshark": "WiresharkFoundation.Wireshark",
    "wazuh agent": "Wazuh.WazuhAgent",
    "google chrome": "Google.Chrome.EXE",
    "mozilla firefox": "Mozilla.Firefox",
    "microsoft edge": "Microsoft.Edge",
    "microsoft onedrive": "Microsoft.OneDrive",
    "microsoft teams": "Microsoft.Teams",
    "edge webview2 runtime": "Microsoft.EdgeWebView2Runtime",
    "7 zip": "7zip.7zip",
    "notepad plus plus": "Notepad++.Notepad++",
    "adobe acrobat reader": "Adobe.Acrobat.Reader.64-bit",
    "adobe reader": "Adobe.Acrobat.Reader.64-bit",
    "zoom": "Zoom.Zoom",
    "slack": "SlackTechnologies.Slack",
    "postman": "Postman.Postman",
    "putty": "PuTTY.PuTTY",
    "winrar": "RARLab.WinRAR",
    "git": "Git.Git",
    "docker desktop": "Docker.DockerDesktop",
    "google cloud sdk": "Google.CloudSDK",
    "nvidia physx": "Nvidia.PhysX",
    "photos": "Microsoft.Windows.Photos",
    "qemu": "QEMU.QEMU",
    "intel hardware accelerated execution manager": "Intel.HAXM",
}
_DEFAULT_LINUX_PACKAGE_MAP: Dict[str, str] = {
    "node js": "nodejs",
    "npm": "npm",
    "mongodb": "mongodb-org",
    "virtualbox": "virtualbox",
    "wireshark": "wireshark",
    "vlc media player": "vlc",
    "google chrome": "google-chrome-stable",
    "firefox": "firefox",
    "openssl": "openssl",
    "curl": "curl",
    "sudo": "sudo",
    "systemd": "systemd",
    "docker": "docker.io",
    "containerd": "containerd",
}
_DEFAULT_WINDOWS_SERVICE_MAP: Dict[str, str] = {
    "wazuh agent": "WazuhSvc",
    "mongodb": "MongoDB",
    "postgresql": "postgresql-x64-17",
    "docker desktop": "com.docker.service",
}
_DEFAULT_LINUX_SERVICE_MAP: Dict[str, str] = {
    "mongodb": "mongod",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "nginx": "nginx",
    "apache": "apache2",
    "docker": "docker",
}
_KEV_MARKERS = (
    "known-exploited-vulnerabilities",
    "known exploited vulnerabilities",
    "cisa.gov/known-exploited",
    "kev",
)
_REMOTE_EXPLOIT_MARKERS = (
    "remote code execution",
    "rce",
    "unauthenticated",
    "network",
    "internet",
    "man in the middle",
)
_LOCAL_PRIV_MARKERS = (
    "elevate privileges",
    "privilege escalation",
    "local privilege escalation",
    "lpe",
)


def _extract_items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        rows = (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
        return rows if isinstance(rows, list) else []
    if isinstance(data, list):
        return data
    return []


def _normalize_agent_id(value: Any) -> str:
    raw = str(value or "").strip()
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _normalize_agent_ids(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for value in values or []:
        norm = _normalize_agent_id(value)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except Exception:
        return None


def _pick(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_key(value: Any) -> str:
    text = str(value or "").strip().lower()
    out = []
    prev_sep = False
    for ch in text:
        if ch.isalnum():
            out.append(ch)
            prev_sep = False
        elif not prev_sep:
            out.append(" ")
            prev_sep = True
    return " ".join("".join(out).split())


def _platform_name(value: Any) -> str:
    key = _normalize_key(value)
    if "windows" in key:
        return "windows"
    if "linux" in key or key in {"ubuntu", "debian", "rhel", "red hat", "centos"}:
        return "linux"
    return ""


def _load_package_maps() -> Dict[str, Dict[str, str]]:
    cfg = SETTINGS.get("vulnerability_remediation", {}) if isinstance(SETTINGS, dict) else {}
    windows_map = dict(_DEFAULT_WINDOWS_PACKAGE_MAP)
    linux_map = dict(_DEFAULT_LINUX_PACKAGE_MAP)
    windows_service_map = dict(_DEFAULT_WINDOWS_SERVICE_MAP)
    linux_service_map = dict(_DEFAULT_LINUX_SERVICE_MAP)
    if isinstance(cfg, dict):
        win_cfg = cfg.get("windows_package_map")
        lin_cfg = cfg.get("linux_package_map")
        win_service_cfg = cfg.get("windows_service_map")
        lin_service_cfg = cfg.get("linux_service_map")
        if isinstance(win_cfg, dict):
            for key, value in win_cfg.items():
                if str(key).strip() and str(value).strip():
                    windows_map[_normalize_key(key)] = str(value).strip()
        if isinstance(lin_cfg, dict):
            for key, value in lin_cfg.items():
                if str(key).strip() and str(value).strip():
                    linux_map[_normalize_key(key)] = str(value).strip()
        if isinstance(win_service_cfg, dict):
            for key, value in win_service_cfg.items():
                if str(key).strip() and str(value).strip():
                    windows_service_map[_normalize_key(key)] = str(value).strip()
        if isinstance(lin_service_cfg, dict):
            for key, value in lin_service_cfg.items():
                if str(key).strip() and str(value).strip():
                    linux_service_map[_normalize_key(key)] = str(value).strip()
    return {
        "windows": windows_map,
        "linux": linux_map,
        "windows_service": windows_service_map,
        "linux_service": linux_service_map,
    }


_PACKAGE_MAPS = _load_package_maps()


def _load_configured_action_ids() -> Set[str]:
    out: Set[str] = set()
    try:
        for row in list_actions():
            if not isinstance(row, dict):
                continue
            action_id = str(row.get("id") or "").strip().lower()
            command = str(row.get("command") or "").strip().lower()
            if action_id:
                out.add(action_id)
            if command:
                out.add(command)
    except Exception:
        pass

    if out:
        return out

    cfg = SETTINGS.get("active_response", {}) if isinstance(SETTINGS, dict) else {}
    commands = cfg.get("commands", []) if isinstance(cfg, dict) else []
    if isinstance(commands, list):
        for row in commands:
            if not isinstance(row, dict):
                continue
            action_id = str(row.get("id") or "").strip().lower()
            command = str(row.get("command") or "").strip().lower()
            if action_id:
                out.add(action_id)
            if command:
                out.add(command)
    return out


_CONFIGURED_ACTION_IDS = _load_configured_action_ids()
_SPECIFIC_SOFTWARE_ACTION_IDS = ("package-update", "software-install-upgrade")


def _specific_software_action_id() -> str:
    if not _CONFIGURED_ACTION_IDS:
        return _SPECIFIC_SOFTWARE_ACTION_IDS[0]
    for action_id in _SPECIFIC_SOFTWARE_ACTION_IDS:
        if action_id in _CONFIGURED_ACTION_IDS:
            return action_id
    return "package-update"


def _package_map_hit(package_name: str, platform: str) -> bool:
    raw = str(package_name or "").strip()
    if not raw:
        return False
    key = _normalize_key(raw)
    mapping = _PACKAGE_MAPS.get(platform, {})
    for candidate, _target in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        if candidate and candidate in key:
            return True
    return False


def _looks_like_winget_id(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw or " " in raw:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)+", raw))


def _looks_like_linux_package_name(value: str) -> bool:
    raw = str(value or "").strip().lower()
    if not raw or " " in raw:
        return False
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9.+-]{0,127}", raw))


def _resolve_windows_package_id(package_name: str) -> str:
    raw = str(package_name or "").strip()
    if not raw:
        return ""
    key = _normalize_key(raw)
    mapping = _PACKAGE_MAPS.get("windows", {})
    for candidate, target in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        if candidate and candidate in key:
            return target
    # If no explicit mapping matched, keep id-looking values untouched.
    if "." in raw and " " not in raw:
        return raw
    return raw


def _resolve_linux_package_name(package_name: str) -> str:
    raw = str(package_name or "").strip()
    if not raw:
        return ""
    key = _normalize_key(raw)
    mapping = _PACKAGE_MAPS.get("linux", {})
    for candidate, target in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        if candidate and candidate in key:
            return target
    return raw.split(" ")[0].strip().lower() or raw


def _resolve_service_name(package_name: str, platform: str) -> str:
    raw = str(package_name or "").strip()
    if not raw:
        return ""
    key = _normalize_key(raw)
    map_key = "windows_service" if platform == "windows" else "linux_service"
    mapping = _PACKAGE_MAPS.get(map_key, {})
    for candidate, target in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        if candidate and candidate in key:
            return target
    return ""


def _is_os_patch_vulnerability(item: Dict[str, Any]) -> bool:
    package = _dict(item.get("package"))
    source = _normalize_key(package.get("source"))
    name = _normalize_key(package.get("name"))
    title = _normalize_key(item.get("title"))
    condition = _normalize_key(package.get("condition"))
    if source == "os":
        return True
    for marker in (
        "microsoft windows",
        "windows update",
        "security intelligence update",
        "microsoft defender",
        "linux kernel",
        "ubuntu",
        "debian",
        "rhel",
        "red hat",
        "centos",
        "kernel",
    ):
        if marker in name or marker in title or marker in condition:
            return True
    if re.search(r"\bkb\d{4,8}\b", f"{name} {title} {condition}"):
        return True
    return False


def _looks_like_os_release_label(value: str) -> bool:
    key = _normalize_key(value)
    if not key:
        return False
    markers = (
        "windows 10",
        "windows 11",
        "windows server",
        "home single language",
        "security intelligence update",
        "microsoft defender",
        "windows update",
        "kb",
        "linux kernel",
        "ubuntu",
        "debian",
        "rhel",
        "red hat",
        "centos",
        "kernel",
    )
    if any(marker in key for marker in markers):
        return True
    if re.search(r"\b10\.0\.\d{4,}\b", key):
        return True
    if re.search(r"\bkb\d{4,8}\b", key):
        return True
    return False


def _looks_like_windows_service_identifier(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]{2,}(Svc|Service|Driver)", raw, flags=re.IGNORECASE):
        return True
    if re.fullmatch(r"[A-Za-z]{2,}[A-Z][A-Za-z0-9]{1,}", raw) and raw.lower().endswith("svc"):
        return True
    return False


def _strip_version_suffix(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    cleaned = re.sub(r"\s*\([^)]*\)\s*$", "", text).strip()
    cleaned = re.sub(r"\s+(?:v)?\d+(?:[._-]\d+){1,}[A-Za-z0-9._-]*\s*$", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    return cleaned or text


def _generate_windows_package_target(package_name: str, resolved: str) -> str:
    candidates: List[str] = []
    for value in (resolved, package_name):
        raw = str(value or "").strip()
        if not raw:
            continue
        stripped = _strip_version_suffix(raw)
        if stripped:
            candidates.append(stripped)
        if raw:
            candidates.append(raw)
    for candidate in candidates:
        key = _normalize_key(candidate)
        if not key or key in {"vulnerability", "unknown", "not available"}:
            continue
        if _looks_like_os_release_label(candidate):
            continue
        if _looks_like_windows_service_identifier(candidate):
            continue
        if re.search(r"\b\d+(?:\.\d+){2,}\b", candidate) and " " in candidate:
            continue
        if _looks_like_winget_id(candidate):
            return candidate
        if 2 <= len(candidate) <= 120 and re.search(r"[A-Za-z]", candidate):
            return candidate
    return ""


def _generate_linux_package_target(package_name: str, resolved: str) -> str:
    candidates: List[str] = []
    for value in (resolved, package_name):
        raw = str(value or "").strip().lower()
        if not raw:
            continue
        stripped = _strip_version_suffix(raw)
        token = stripped.split(" ")[0].strip()
        token = re.sub(r"[^a-z0-9.+-]", "", token)
        if token:
            candidates.append(token)
    for candidate in candidates:
        if _looks_like_os_release_label(candidate):
            continue
        if _looks_like_linux_package_name(candidate):
            return candidate
    return ""


def _generate_generic_package_target(package_name: str, win_resolved: str, lin_resolved: str) -> str:
    candidates = [
        _strip_version_suffix(win_resolved),
        _strip_version_suffix(lin_resolved),
        _strip_version_suffix(package_name),
        str(package_name or "").strip(),
    ]
    for candidate in candidates:
        raw = str(candidate or "").strip()
        if not raw:
            continue
        if _looks_like_os_release_label(raw):
            continue
        if re.search(r"[A-Za-z]", raw):
            return raw[:160]
    return ""


def _normalize_kb(value: Any) -> str:
    raw = str(value or "").strip().upper().replace(" ", "")
    if not raw:
        return ""
    if raw.startswith("KB"):
        raw = raw[2:]
    if not raw.isdigit():
        return ""
    return f"KB{raw}"


def _extract_windows_kb_candidates(text: str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for match in re.findall(r"\bKB\s*([0-9]{4,8})\b", str(text or ""), flags=re.IGNORECASE):
        kb = _normalize_kb(match)
        if kb and kb not in seen:
            seen.add(kb)
            out.append(kb)
    return out


def _normalize_windows_build(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.search(r"\b(?:10\.0\.)?(\d{4,5}\.\d{1,5})\b", text)
    if not match:
        return ""
    return str(match.group(1)).strip()


def _extract_windows_build_candidates(text: str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for match in re.findall(r"\b(?:10\.0\.)?(\d{4,5}\.\d{1,5})\b", str(text or "")):
        build = _normalize_windows_build(match)
        if build and build not in seen:
            seen.add(build)
            out.append(build)
    return out


def _build_sort_key(value: str) -> tuple[int, ...]:
    parts = [part for part in str(value or "").split(".") if str(part).isdigit()]
    if not parts:
        return tuple()
    return tuple(int(part) for part in parts)


def _derive_windows_patch_target(item: Dict[str, Any]) -> Dict[str, str]:
    package = _dict(item.get("package"))
    package_name = str(package.get("name") or "")
    package_version = str(package.get("version") or "")
    condition = str(package.get("condition") or "")
    title = str(item.get("title") or "")
    rationale = str(item.get("rationale") or "")
    scanner_reference = str(item.get("scanner_reference") or "")
    references = " ".join(
        str(ref).strip()
        for ref in (item.get("references") if isinstance(item.get("references"), list) else [])
        if str(ref).strip()
    )
    blob = " ".join(
        part
        for part in [
            package_name,
            package_version,
            condition,
            title,
            rationale,
            scanner_reference,
            references,
        ]
        if str(part).strip()
    )
    kb_candidates = _extract_windows_kb_candidates(blob)
    kb = ""
    if kb_candidates:
        kb = sorted(kb_candidates, key=lambda value: int(value[2:]), reverse=True)[0]

    build_candidates = _extract_windows_build_candidates(blob)
    current_build = _normalize_windows_build(package_version)
    min_build = ""
    if build_candidates:
        sorted_builds = sorted(build_candidates, key=_build_sort_key, reverse=True)
        if current_build:
            current_key = _build_sort_key(current_build)
            higher = [build for build in sorted_builds if _build_sort_key(build) > current_key]
            if higher:
                min_build = higher[0]
        elif sorted_builds:
            min_build = sorted_builds[0]

    if not kb and not min_build:
        return {"kb": "", "min_build": ""}
    return {"kb": kb, "min_build": min_build}


def _windows_kb_install_command(kb: str) -> str:
    kb_norm = _normalize_kb(kb)
    if not kb_norm:
        return ""
    return (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        "if(-not (Get-Command Install-WindowsUpdate -ErrorAction SilentlyContinue)){"
        "  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null;"
        "  Install-Module PSWindowsUpdate -Scope AllUsers -Force -Confirm:$false -ErrorAction Stop | Out-Null;"
        "};"
        "Import-Module PSWindowsUpdate -ErrorAction Stop;"
        f"Install-WindowsUpdate -KBArticleID {kb_norm} -MicrosoftUpdate -AcceptAll -AutoReboot -ErrorAction Stop"
    )


def _ps_single_quoted(value: Any) -> str:
    raw = str(value or "")
    return "'" + raw.replace("'", "''") + "'"


def _windows_package_upgrade_command(package_target: str, display_hint: str = "") -> str:
    tokens: List[str] = []
    seen: Set[str] = set()
    for raw in (package_target, display_hint):
        text = str(raw or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        tokens.append(text)
    if not tokens:
        return ""

    needle_literal = ", ".join(_ps_single_quoted(token) for token in tokens)
    return (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        f"$needles=@({needle_literal});"
        "$updated=$false;"
        "foreach($needle in $needles){"
        "  if(-not $needle){ continue };"
        "  if(Get-Command winget -ErrorAction SilentlyContinue){"
        "    & winget upgrade --id $needle --exact --silent --accept-package-agreements --accept-source-agreements --include-unknown | Out-Host;"
        "    if($LASTEXITCODE -eq 0){ $updated=$true; break };"
        "    & winget upgrade --query $needle --silent --accept-package-agreements --accept-source-agreements --include-unknown | Out-Host;"
        "    if($LASTEXITCODE -eq 0){ $updated=$true; break };"
        "  };"
        "  if(-not $updated -and (Get-Command choco -ErrorAction SilentlyContinue)){"
        "    & choco upgrade $needle -y --no-progress --limit-output | Out-Host;"
        "    if($LASTEXITCODE -eq 0){ $updated=$true; break };"
        "  };"
        "};"
        "if(-not $updated){ throw ('No supported upgrade path succeeded for '+$needles[0]) };"
        "Write-Output ('Package update attempted: '+$needles[0]);"
    )


def _windows_os_update_command() -> str:
    return (
        "$ErrorActionPreference='Stop';"
        "$ProgressPreference='SilentlyContinue';"
        "if(-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)){"
        "  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null;"
        "  Install-Module PSWindowsUpdate -Scope AllUsers -Force -Confirm:$false -ErrorAction Stop | Out-Null;"
        "};"
        "Import-Module PSWindowsUpdate -ErrorAction Stop;"
        "Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -AutoReboot -ErrorAction Stop"
    )


def _build_ai_manual_shell_suggestion(
    *,
    package_name: str,
    win_resolved: str,
    win_target: str,
    generated_win_target: str,
    windows_ids: List[str],
    linux_ids: List[str],
    all_ids: List[str],
    windows_target_kb: str,
    windows_target_build: str,
    os_markers: bool,
    os_like_package_name: bool,
) -> Dict[str, Any] | None:
    # Prefer explicit Windows targets. If platform is unknown in source data,
    # allow all affected IDs (backend execution path still filters to connected Windows agents).
    target_ids = _normalize_agent_ids(windows_ids)
    if not target_ids and not linux_ids:
        target_ids = _normalize_agent_ids(all_ids)
    if not target_ids:
        return None

    command = ""
    strategy = ""
    confidence = "low"
    run_as_system = True
    reason = "Operator-ready command generated from vulnerability metadata."

    if windows_target_kb:
        command = _windows_kb_install_command(windows_target_kb)
        strategy = "kb_install"
        confidence = "high"
        reason = "Install the derived KB target on affected endpoint(s)."
    elif win_target:
        command = _windows_package_upgrade_command(win_target, package_name)
        strategy = "package_upgrade_mapped"
        confidence = "high"
        run_as_system = False
        reason = "Upgrade the mapped vulnerable package on affected endpoint(s)."
    elif generated_win_target:
        command = _windows_package_upgrade_command(generated_win_target, package_name)
        strategy = "package_upgrade_generated"
        confidence = "medium"
        run_as_system = False
        reason = "Upgrade the generated package target derived from vulnerability metadata."
    elif os_markers or os_like_package_name:
        command = _windows_os_update_command()
        strategy = "os_update"
        confidence = "medium"
        reason = "Apply Windows security updates for OS/build-level vulnerability markers."
    else:
        fallback_target = _generate_windows_package_target(package_name, win_resolved)
        if fallback_target:
            command = _windows_package_upgrade_command(fallback_target, package_name)
            strategy = "package_upgrade_fallback"
            confidence = "medium"
            run_as_system = False
            reason = "Attempt package upgrade using inferred package identifier."

    if not command:
        return None

    out: Dict[str, Any] = {
        "label": "Operator-Ready PowerShell Command",
        "shell": "powershell",
        "command": command,
        "agent_ids": target_ids,
        "reason": reason,
        "source": "ai-generated",
        "strategy": strategy,
        "confidence": confidence,
        "run_as_system": run_as_system,
        "target_policy": "affected_agents_only",
    }
    if windows_target_kb:
        out["verify_kb"] = windows_target_kb
    if windows_target_build:
        out["verify_min_build"] = windows_target_build
    return out


def _contains_any(text: str, markers: Iterable[str]) -> bool:
    hay = _normalize_key(text)
    if not hay:
        return False
    return any(_normalize_key(marker) in hay for marker in markers if marker)


def _is_kev_vulnerability(item: Dict[str, Any]) -> bool:
    references = item.get("references") if isinstance(item.get("references"), list) else []
    reference_blob = " ".join(str(ref) for ref in references if str(ref).strip())
    scanner_reference = str(item.get("scanner_reference") or "")
    return _contains_any(f"{reference_blob} {scanner_reference}", _KEV_MARKERS)


def _is_remote_exploitable(item: Dict[str, Any]) -> bool:
    title = str(item.get("title") or "")
    rationale = str(item.get("rationale") or "")
    cwe = str(item.get("cwe_reference") or "")
    return _contains_any(f"{title} {rationale} {cwe}", _REMOTE_EXPLOIT_MARKERS)


def _is_local_priv_esc(item: Dict[str, Any]) -> bool:
    title = str(item.get("title") or "")
    rationale = str(item.get("rationale") or "")
    cwe = str(item.get("cwe_reference") or "")
    return _contains_any(f"{title} {rationale} {cwe}", _LOCAL_PRIV_MARKERS)


def _collect_agent_ids(affected: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    all_ids = [str(a.get("id") or "").strip() for a in affected if str(a.get("id") or "").strip()]
    windows_ids = [
        str(a.get("id") or "").strip()
        for a in affected
        if _platform_name(a.get("platform")) == "windows" and str(a.get("id") or "").strip()
    ]
    linux_ids = [
        str(a.get("id") or "").strip()
        for a in affected
        if _platform_name(a.get("platform")) == "linux" and str(a.get("id") or "").strip()
    ]
    return {
        "all": _normalize_agent_ids(all_ids),
        "windows": _normalize_agent_ids(windows_ids),
        "linux": _normalize_agent_ids(linux_ids),
    }


def _make_step(
    *,
    label: str,
    action_id: str,
    args: Dict[str, Any] | None,
    agent_ids: List[str],
    mode: str = "auto",
    reason: str = "",
) -> Dict[str, Any] | None:
    normalized_ids = _normalize_agent_ids(agent_ids)
    if not normalized_ids:
        return None
    action_key = str(action_id or "").strip().lower()
    if not action_key:
        return None
    if _CONFIGURED_ACTION_IDS and action_key not in _CONFIGURED_ACTION_IDS:
        return None
    return {
        "label": label,
        "action_id": action_key,
        "args": args or {},
        "agent_ids": normalized_ids,
        "mode": mode,
        "reason": reason,
    }


def _dedupe_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        action_id = str(step.get("action_id") or "").strip()
        if not action_id:
            continue
        args = step.get("args") if isinstance(step.get("args"), dict) else {}
        key = f"{action_id}|{str(args)}|{step.get('mode')}"
        current = merged.get(key)
        if not current:
            merged[key] = {
                **step,
                "agent_ids": _normalize_agent_ids(step.get("agent_ids") or []),
            }
            continue
        existing_ids = set(current.get("agent_ids") or [])
        for aid in step.get("agent_ids") or []:
            aid_norm = _normalize_agent_id(aid)
            if aid_norm:
                existing_ids.add(aid_norm)
        current["agent_ids"] = sorted(existing_ids)
        reason = str(current.get("reason") or "").strip()
        new_reason = str(step.get("reason") or "").strip()
        if new_reason and new_reason not in reason:
            current["reason"] = f"{reason}; {new_reason}".strip("; ")
    return list(merged.values())


def _build_remediation(item: Dict[str, Any]) -> Dict[str, Any]:
    package = _dict(item.get("package"))
    package_name = str(package.get("name") or "").strip()
    affected = item.get("affected_agents") if isinstance(item.get("affected_agents"), list) else []
    ids = _collect_agent_ids(affected)
    all_ids = ids["all"]
    windows_ids = ids["windows"]
    linux_ids = ids["linux"]

    severity = str(item.get("severity") or "unknown").lower()
    score = _to_float(item.get("score")) or 0.0
    kev = _is_kev_vulnerability(item)
    remote_exploit = _is_remote_exploitable(item)
    local_priv = _is_local_priv_esc(item)
    high_risk = severity in {"critical", "high"} or score >= 8.0
    specific_software_action_id = _specific_software_action_id()

    strategy = "manual_triage"
    summary = "Review vendor guidance and triage manually."
    confidence = "low"
    coverage = "manual"
    notes: List[str] = []
    tags: List[str] = []
    manual_steps: List[str] = []
    primary_steps: List[Dict[str, Any]] = []
    verification_steps: List[Dict[str, Any]] = []
    investigation_steps: List[Dict[str, Any]] = []
    optional_steps: List[Dict[str, Any]] = []
    fallback_steps: List[Dict[str, Any]] = []
    manual_shell: Dict[str, Any] | None = None

    os_markers = _is_os_patch_vulnerability(item)
    os_like_package_name = _looks_like_os_release_label(package_name)
    win_target = ""
    lin_target = ""
    win_resolved = ""
    lin_resolved = ""
    generated_win_target = ""
    generated_lin_target = ""
    mapped_package_step_added = False
    generated_package_step_added = False
    os_update_step_added = False
    windows_patch_target = _derive_windows_patch_target(item) if windows_ids else {"kb": "", "min_build": ""}
    windows_target_kb = _normalize_kb(windows_patch_target.get("kb"))
    windows_target_build = _normalize_windows_build(windows_patch_target.get("min_build"))

    if windows_ids:
        win_resolved = _resolve_windows_package_id(package_name)
        win_mapped = _package_map_hit(package_name, "windows")
        win_os_like = _looks_like_os_release_label(win_resolved)
        if win_resolved and not win_os_like and (win_mapped or _looks_like_winget_id(win_resolved)):
            win_target = win_resolved
        elif win_resolved and (os_markers or os_like_package_name or win_os_like):
            notes.append(
                "Windows OS/build label does not map to an explicit package manager target; skipped auto package update."
            )
            tags.append("os-marker-unmapped")

    if linux_ids:
        lin_resolved = _resolve_linux_package_name(package_name)
        lin_mapped = _package_map_hit(package_name, "linux")
        lin_os_like = _looks_like_os_release_label(lin_resolved)
        if lin_resolved and (
            ((not os_markers and not os_like_package_name) or lin_mapped or _looks_like_linux_package_name(lin_resolved))
            and not lin_os_like
        ):
            lin_target = lin_resolved
        elif lin_resolved and (os_markers or os_like_package_name or lin_os_like):
            notes.append(
                "Linux OS/build label does not map to an explicit package manager target; skipped auto package update."
            )
            tags.append("os-marker-unmapped")

    if windows_ids and win_target:
        step = _make_step(
            label="Update vulnerable package on Windows",
            action_id=specific_software_action_id,
            args={"package": win_target},
            agent_ids=windows_ids,
            mode="auto",
            reason="Mapped vulnerable package to Windows package manager target from vulnerability feed.",
        )
        if step:
            primary_steps.append(step)
            tags.append("windows-package")
            mapped_package_step_added = True
    if linux_ids and lin_target:
        step = _make_step(
            label="Update vulnerable package on Linux",
            action_id=specific_software_action_id,
            args={"package": lin_target},
            agent_ids=linux_ids,
            mode="auto",
            reason="Mapped vulnerable package to Linux package manager target from vulnerability feed.",
        )
        if step:
            primary_steps.append(step)
            tags.append("linux-package")
            mapped_package_step_added = True

    # OS/build vulnerabilities should use explicit OS update actions, not generic fleet/package targets.
    if windows_ids and (os_markers or os_like_package_name):
        step = _make_step(
            label="Apply Windows OS security updates",
            action_id="windows-os-update",
            args={},
            agent_ids=windows_ids,
            mode="auto",
            reason="OS/build vulnerability detected on Windows; run OS/security update workflow.",
        )
        if step:
            primary_steps.append(step)
            os_update_step_added = True
            tags.append("windows-os-update")
            tags.append("os-marker")

    if linux_ids and (os_markers or os_like_package_name):
        step = _make_step(
            label="Apply Linux OS updates",
            action_id="patch-linux",
            args={},
            agent_ids=linux_ids,
            mode="auto",
            reason="OS/kernel vulnerability detected on Linux; run OS patch workflow.",
        )
        if step:
            primary_steps.append(step)
            os_update_step_added = True
            tags.append("linux-os-update")
            tags.append("os-marker")

    # Unmapped software vulnerabilities: generate a best-effort package target so the UI can still execute remediation.
    if windows_ids and not win_target and not (os_markers or os_like_package_name):
        generated_win_target = _generate_windows_package_target(package_name, win_resolved)
        if generated_win_target:
            step = _make_step(
                label="Generated package update target (Windows)",
                action_id=specific_software_action_id,
                args={"package": generated_win_target},
                agent_ids=windows_ids,
                mode="auto",
                reason="No explicit package map; generated package target from vulnerability metadata.",
            )
            if step:
                primary_steps.append(step)
                generated_package_step_added = True
                tags.append("windows-package-generated")

    if linux_ids and not lin_target and not (os_markers or os_like_package_name):
        generated_lin_target = _generate_linux_package_target(package_name, lin_resolved)
        if generated_lin_target:
            step = _make_step(
                label="Generated package update target (Linux)",
                action_id=specific_software_action_id,
                args={"package": generated_lin_target},
                agent_ids=linux_ids,
                mode="auto",
                reason="No explicit package map; generated package target from vulnerability metadata.",
            )
            if step:
                primary_steps.append(step)
                generated_package_step_added = True
                tags.append("linux-package-generated")

    covered_primary_ids = set()
    for step in primary_steps:
        covered_primary_ids.update(_normalize_agent_ids(step.get("agent_ids") or []))
    uncovered_ids = [aid for aid in all_ids if aid not in covered_primary_ids]
    if uncovered_ids and not (os_markers or os_like_package_name):
        generic_target = _generate_generic_package_target(package_name, win_resolved, lin_resolved)
        if generic_target:
            step = _make_step(
                label="Generated package update target (platform-agnostic)",
                action_id=specific_software_action_id,
                args={"package": generic_target},
                agent_ids=uncovered_ids,
                mode="auto",
                reason="Endpoint platform metadata missing; generated a platform-agnostic package target from vulnerability metadata.",
            )
            if step:
                primary_steps.append(step)
                generated_package_step_added = True
                tags.append("package-generated-generic")

    # Fallback play when targeted package remediation does not clear the issue.
    has_package_primary = any(
        str(step.get("action_id") or "") in {"package-update", "software-install-upgrade"}
        for step in primary_steps
    )
    if has_package_primary and windows_ids:
        step = _make_step(
            label="Fallback: Apply Windows OS security updates",
            action_id="windows-os-update",
            args={},
            agent_ids=windows_ids,
            mode="recommended",
            reason="Fallback if package-level remediation fails or package target is not resolvable on endpoint.",
        )
        if step:
            fallback_steps.append(step)
    if has_package_primary and linux_ids:
        step = _make_step(
            label="Fallback: Apply Linux OS updates",
            action_id="patch-linux",
            args={},
            agent_ids=linux_ids,
            mode="recommended",
            reason="Fallback if package-level remediation fails or package target is not resolvable on endpoint.",
        )
        if step:
            fallback_steps.append(step)
    if windows_ids and (os_markers or os_like_package_name or has_package_primary):
        kb_command = _windows_kb_install_command(windows_target_kb)
        if kb_command:
            manual_shell = {
                "label": f"Manual Global Shell fallback for {windows_target_kb}",
                "shell": "powershell",
                "command": kb_command,
                "agent_ids": _normalize_agent_ids(windows_ids),
                "reason": "Fallback when standard Windows update workflow does not offer required target KB.",
                "source": "rule-derived",
                "strategy": "kb_install",
                "confidence": "high",
                "run_as_system": True,
                "target_policy": "affected_agents_only",
            }
            if windows_target_kb:
                manual_shell["verify_kb"] = windows_target_kb
            if windows_target_build:
                manual_shell["verify_min_build"] = windows_target_build
            manual_steps.append(
                "If automatic remediation does not clear this vulnerability, run the generated PowerShell fallback via Global Shell."
            )
            tags.append("windows-kb-global-shell-fallback")
        elif os_markers or os_like_package_name:
            notes.append(
                "Windows OS marker detected but no explicit KB target could be derived for manual Global Shell fallback."
            )

    if manual_shell is None:
        manual_shell = _build_ai_manual_shell_suggestion(
            package_name=package_name,
            win_resolved=win_resolved,
            win_target=win_target,
            generated_win_target=generated_win_target,
            windows_ids=windows_ids,
            linux_ids=linux_ids,
            all_ids=all_ids,
            windows_target_kb=windows_target_kb,
            windows_target_build=windows_target_build,
            os_markers=os_markers,
            os_like_package_name=os_like_package_name,
        )
        if manual_shell:
            manual_steps.append(
                "Generated operator-ready PowerShell command is available in Global Shell for affected agent(s) only."
            )
            tags.append("ai-command-suggested")
    elif isinstance(manual_shell, dict):
        manual_shell.setdefault("source", "rule-derived")
        manual_shell.setdefault("run_as_system", False)
        manual_shell.setdefault("target_policy", "affected_agents_only")

    if primary_steps:
        if windows_target_kb and (os_markers or os_like_package_name):
            notes.append(f"Derived target KB for fallback remediation: {windows_target_kb}.")
        if os_update_step_added and not (mapped_package_step_added or generated_package_step_added):
            strategy = "os_update"
            summary = "OS-level vulnerability: run OS update workflow on affected endpoints."
            confidence = "medium" if os_markers else "low"
            coverage = "automated"
        elif generated_package_step_added and not mapped_package_step_added:
            strategy = "generated_package_update"
            summary = "No direct package map found; generated package update target(s) from vulnerability metadata."
            confidence = "medium"
            coverage = "automated"
            notes.append("Auto-generated package target(s) were used; verify package identity from execution evidence.")
            tags.append("generated-target")
        else:
            strategy = "package_update"
            summary = "Package-level vulnerability: update only software explicitly reported by the vulnerability feed."
            confidence = "high" if package_name else "medium"
            coverage = "automated"
        if os_markers and not os_update_step_added:
            notes.append(
                "OS-level markers detected, but remediation is constrained to vulnerability-mapped package targets."
            )
            tags.append("os-marker")
    else:
        strategy = "investigate_manual_patch"
        summary = "No direct package mapping available; run hunt + manual remediation."
        confidence = "low"
        coverage = "manual"
        manual_steps.append("Apply vendor patch or mitigation guidance manually for this software.")
        manual_steps.append("Track remediation in change record and rerun vulnerability scan.")
        if os_markers:
            manual_steps.append(
                "No auto-mapped OS update target resolved; trigger Windows/Linux OS patch action from UI and re-run vulnerability scan."
            )

    verify = _make_step(
        label="Endpoint healthcheck",
        action_id="endpoint-healthcheck",
        args={},
        agent_ids=all_ids,
        mode="recommended",
        reason="Validate endpoint connectivity/state after remediation.",
    )
    if verify:
        verification_steps.append(verify)

    if severity in {"critical", "high", "medium"}:
        sca_step = _make_step(
            label="Rescan compliance/SCA",
            action_id="sca-rescan",
            args={},
            agent_ids=all_ids,
            mode="recommended",
            reason="Refresh endpoint security posture after remediation.",
        )
        if sca_step:
            verification_steps.append(sca_step)

    if high_risk or kev or remote_exploit:
        ioc_step = _make_step(
            label="Run IOC scan",
            action_id="ioc-scan",
            args={},
            agent_ids=all_ids,
            mode="recommended",
            reason="High-risk vulnerability may already be exploited.",
        )
        if ioc_step:
            investigation_steps.append(ioc_step)

        persistence_step = _make_step(
            label="Run persistence hunt",
            action_id="threat-hunt-persistence",
            args={},
            agent_ids=all_ids,
            mode="recommended",
            reason="Check for post-exploitation persistence artifacts.",
        )
        if persistence_step:
            investigation_steps.append(persistence_step)
        tags.append("threat-hunt")

    if severity == "critical" or kev:
        forensics_step = _make_step(
            label="Collect forensic triage",
            action_id="collect-forensics",
            args={},
            agent_ids=all_ids,
            mode="optional",
            reason="Capture endpoint evidence for IR workflow.",
        )
        if forensics_step:
            optional_steps.append(forensics_step)
        memory_step = _make_step(
            label="Collect memory snapshot",
            action_id="collect-memory",
            args={},
            agent_ids=all_ids,
            mode="optional",
            reason="Capture volatile indicators for critical risk analysis.",
        )
        if memory_step:
            optional_steps.append(memory_step)
        tags.append("forensics")

    if local_priv:
        notes.append("This vulnerability pattern suggests privilege escalation risk; review privileged/local admin accounts.")
        tags.append("priv-esc")
    if remote_exploit:
        notes.append("Remote exploitation indicators detected in CVE text; prioritize urgent patching/hunt.")
        tags.append("remote-exploit")
    if kev:
        notes.append("Reference indicates CISA KEV/public exploitation; treat as emergency.")
        tags.append("kev")

    # Service restart suggestion when package likely backs a long-running service.
    windows_service = _resolve_service_name(package_name, "windows") if windows_ids else ""
    linux_service = _resolve_service_name(package_name, "linux") if linux_ids else ""
    if primary_steps and windows_service:
        step = _make_step(
            label=f"Restart Windows service ({windows_service})",
            action_id="service-restart",
            args={"service": windows_service},
            agent_ids=windows_ids,
            mode="optional",
            reason="Service restart may be required to load patched binaries.",
        )
        if step:
            optional_steps.append(step)
    if primary_steps and linux_service:
        step = _make_step(
            label=f"Restart Linux service ({linux_service})",
            action_id="service-restart",
            args={"service": linux_service},
            agent_ids=linux_ids,
            mode="optional",
            reason="Service restart may be required to load patched binaries.",
        )
        if step:
            optional_steps.append(step)

    primary_steps = _dedupe_steps(primary_steps)
    verification_steps = _dedupe_steps(verification_steps)
    investigation_steps = _dedupe_steps(investigation_steps)
    optional_steps = _dedupe_steps(optional_steps)
    fallback_steps = _dedupe_steps(fallback_steps)

    auto_executable = bool(primary_steps)
    if auto_executable and (manual_steps or investigation_steps or optional_steps):
        coverage = "partial"
    elif auto_executable:
        coverage = "automated"
    elif investigation_steps:
        coverage = "investigate-first"
        if not manual_steps:
            manual_steps.append("No guaranteed automated patch path; escalate to manual remediation after hunt results.")

    all_auto_steps = primary_steps

    return {
        "strategy": strategy,
        "summary": summary,
        "confidence": confidence,
        "coverage": coverage,
        "auto_executable": auto_executable,
        "steps": all_auto_steps,
        "primary_steps": primary_steps,
        "verification_steps": verification_steps,
        "investigation_steps": investigation_steps,
        "optional_steps": optional_steps,
        "fallback_steps": fallback_steps,
        "manual_steps": manual_steps,
        "manual_shell": manual_shell,
        "notes": notes,
        "tags": sorted(set(tags)),
    }


def _normalize_severity(value: Any, score: float | None) -> str:
    text = str(value or "").strip().lower()
    if "critical" in text:
        return "critical"
    if "high" in text:
        return "high"
    if "medium" in text:
        return "medium"
    if "low" in text:
        return "low"
    if score is not None:
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    return "unknown"


def _is_resolved_status(value: Any) -> bool:
    key = _normalize_key(value)
    if not key:
        return False
    resolved_markers = (
        "resolved",
        "fixed",
        "closed",
        "solved",
        "inactive",
        "remediated",
        "mitigated",
        "not affected",
    )
    return any(marker in key for marker in resolved_markers)


def _normalize_severity_filter(value: str | None) -> Set[str]:
    if not value:
        return set()
    aliases = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
    }
    selected: Set[str] = set()
    for chunk in str(value).split(","):
        key = aliases.get(chunk.strip().lower())
        if key:
            selected.add(key)
    return selected


def _parse_references(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(",")]
        return [p for p in parts if p]
    return []


def _resolve_scope_agent_ids(
    *,
    agent_id: str | None,
    agent_ids: str | None,
    group: str | None,
) -> List[str]:
    resolved: List[str] = []
    if group:
        resolved.extend(client.get_agent_ids(group=group))
    if agent_id:
        resolved.append(agent_id)
    if agent_ids:
        resolved.extend([part.strip() for part in str(agent_ids).split(",") if part.strip()])
    return _normalize_agent_ids(resolved)


def _load_local_closure_map() -> Dict[tuple[str, str], Dict[str, Any]]:
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT vulnerability_id, agent_id, state, reason, execution_id, closed_by, updated_at
                FROM vulnerability_local_closures
                WHERE state = 'closed'
                """
            )
        ).fetchall()
    except Exception:
        return {}
    finally:
        db.close()

    out: Dict[tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        item = serialize_row(row) or {}
        vulnerability_id = str(item.get("vulnerability_id") or "").strip()
        agent_id = _normalize_agent_id(item.get("agent_id"))
        if not vulnerability_id or not agent_id:
            continue
        out[(vulnerability_id, agent_id)] = {
            "state": str(item.get("state") or "closed"),
            "reason": str(item.get("reason") or "").strip(),
            "execution_id": item.get("execution_id"),
            "closed_by": str(item.get("closed_by") or "").strip(),
            "updated_at": str(item.get("updated_at") or "").strip(),
        }
    return out


@router.post("/local-close")
def close_local_vulnerability(
    payload: Dict[str, Any],
    user=Depends(require_role("analyst")),
):
    vulnerability_id = str(payload.get("vulnerability_id") or "").strip()
    if not vulnerability_id:
        raise HTTPException(status_code=400, detail="vulnerability_id is required")

    raw_agent_ids = payload.get("agent_ids")
    if isinstance(raw_agent_ids, str):
        agent_ids = _normalize_agent_ids([part.strip() for part in raw_agent_ids.split(",") if part.strip()])
    elif isinstance(raw_agent_ids, list):
        agent_ids = _normalize_agent_ids(raw_agent_ids)
    else:
        agent_ids = _normalize_agent_ids([payload.get("agent_id")]) if payload.get("agent_id") else []
    if not agent_ids:
        raise HTTPException(status_code=400, detail="agent_ids (or agent_id) is required")

    reason = str(payload.get("reason") or "").strip()
    actor = user.get("sub") if isinstance(user, dict) else str(user)
    execution_id_raw = payload.get("execution_id")
    try:
        execution_id = int(execution_id_raw) if execution_id_raw is not None else None
    except Exception:
        execution_id = None

    db = connect()
    try:
        for aid in agent_ids:
            exists = db.execute(
                text(
                    """
                    SELECT id
                    FROM vulnerability_local_closures
                    WHERE vulnerability_id=:vulnerability_id AND agent_id=:agent_id
                    LIMIT 1
                    """
                ),
                {"vulnerability_id": vulnerability_id, "agent_id": aid},
            ).scalar()
            if exists:
                db.execute(
                    text(
                        """
                        UPDATE vulnerability_local_closures
                        SET state='closed',
                            reason=:reason,
                            execution_id=:execution_id,
                            closed_by=:closed_by,
                            updated_at=CURRENT_TIMESTAMP
                        WHERE id=:id
                        """
                    ),
                    {
                        "id": exists,
                        "reason": reason,
                        "execution_id": execution_id,
                        "closed_by": actor,
                    },
                )
            else:
                db.execute(
                    text(
                        """
                        INSERT INTO vulnerability_local_closures
                        (vulnerability_id, agent_id, state, reason, execution_id, closed_by)
                        VALUES (:vulnerability_id, :agent_id, 'closed', :reason, :execution_id, :closed_by)
                        """
                    ),
                    {
                        "vulnerability_id": vulnerability_id,
                        "agent_id": aid,
                        "reason": reason,
                        "execution_id": execution_id,
                        "closed_by": actor,
                    },
                )
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to persist local closure: {exc}") from exc
    finally:
        db.close()

    return {
        "ok": True,
        "vulnerability_id": vulnerability_id,
        "closed_agents": agent_ids,
        "count": len(agent_ids),
    }


def _load_agent_catalog() -> Dict[str, Dict[str, Any]]:
    catalog: Dict[str, Dict[str, Any]] = {}
    try:
        rows = _extract_items(client.get_agents())
    except HTTPException:
        rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        aid = _normalize_agent_id(row.get("id") or row.get("agent_id"))
        if not aid:
            continue
        groups = row.get("group") or row.get("groups") or []
        if isinstance(groups, str):
            groups = [groups]
        elif not isinstance(groups, list):
            groups = []
        catalog[aid] = {
            "id": aid,
            "name": str(row.get("name") or row.get("hostname") or aid),
            "ip": str(row.get("ip") or ""),
            "status": str(row.get("status") or ""),
            "groups": [str(g) for g in groups if str(g).strip()],
            "platform": _platform_name(
                _pick(
                    _dict(row.get("os")).get("platform"),
                    _dict(row.get("os")).get("name"),
                    row.get("os_name"),
                    row.get("platform"),
                )
            ),
        }
    return catalog


def _extract_vuln_record(record: Dict[str, Any]) -> Dict[str, Any]:
    data = _dict(record.get("data"))
    vuln_data = _dict(data.get("vulnerability"))
    vuln = _dict(_pick(record.get("vulnerability"), vuln_data))
    package = _dict(_pick(vuln.get("package"), _dict(record.get("package")), _dict(data.get("package"))))
    score_block = _dict(vuln.get("score"))
    cvss_block = _dict(vuln.get("cvss"))
    cvss3_block = _dict(cvss_block.get("cvss3"))

    score = (
        _to_float(_pick(score_block.get("base"), score_block.get("base_score")))
        or _to_float(_pick(cvss3_block.get("base_score"), cvss_block.get("score")))
        or _to_float(_pick(data.get("score"), vuln_data.get("score")))
        or _to_float(record.get("score"))
    )
    severity = _normalize_severity(
        _pick(
            vuln.get("severity"),
            cvss_block.get("severity"),
            score_block.get("severity"),
            vuln_data.get("severity"),
            data.get("severity"),
            record.get("severity"),
        ),
        score,
    )
    cve = str(
        _pick(
            vuln.get("cve"),
            vuln_data.get("cve"),
            data.get("cve"),
            record.get("cve"),
        )
        or ""
    ).strip()
    title = str(
        _pick(
            vuln.get("title"),
            vuln_data.get("title"),
            data.get("title"),
            record.get("title"),
            cve,
            "Vulnerability",
        )
    ).strip()
    condition = str(_pick(package.get("condition"), vuln.get("condition"), record.get("condition")) or "").strip()
    package_source = str(
        _pick(
            package.get("source"),
            vuln.get("source"),
            vuln_data.get("source"),
            data.get("source"),
            record.get("source"),
        )
        or ""
    ).strip()
    package_name = str(
        _pick(
            package.get("name"),
            vuln.get("package_name"),
            vuln_data.get("package_name"),
            data.get("package_name"),
            record.get("package_name"),
            record.get("name"),
        )
        or ""
    ).strip()
    package_version = str(
        _pick(
            package.get("version"),
            vuln.get("version"),
            vuln_data.get("version"),
            data.get("version"),
            record.get("version"),
        )
        or ""
    ).strip()
    references = _parse_references(_pick(vuln.get("reference"), data.get("reference"), record.get("reference")))
    scanner_reference = str(
        _pick(
            _dict(vuln.get("scanner")).get("reference"),
            _dict(vuln_data.get("scanner")).get("reference"),
            _dict(data.get("scanner")).get("reference"),
        )
        or ""
    ).strip()
    timestamp = str(_pick(record.get("@timestamp"), record.get("timestamp"), data.get("timestamp")) or "").strip()
    doc_id = str(_pick(record.get("_doc_id"), record.get("id"), cve) or "").strip()
    return {
        "cve": cve,
        "title": title,
        "severity": severity,
        "score": score,
        "package_name": package_name,
        "package_version": package_version,
        "condition": condition,
        "package_source": package_source,
        "references": references,
        "scanner_reference": scanner_reference,
        "classification": str(_pick(vuln.get("classification"), vuln_data.get("classification")) or "").strip(),
        "type": str(_pick(vuln.get("type"), vuln_data.get("type")) or "").strip(),
        "rationale": str(_pick(vuln.get("rationale"), vuln_data.get("rationale"), data.get("rationale")) or "").strip(),
        "cwe_reference": str(_pick(vuln.get("cwe_reference"), vuln_data.get("cwe_reference")) or "").strip(),
        "assigner": str(_pick(vuln.get("assigner"), vuln_data.get("assigner")) or "").strip(),
        "status": str(_pick(vuln.get("status"), vuln_data.get("status"), record.get("status")) or "").strip(),
        "published": str(_pick(vuln.get("published"), vuln_data.get("published"), data.get("published")) or "").strip(),
        "updated": str(_pick(vuln.get("updated"), vuln_data.get("updated"), data.get("updated")) or "").strip(),
        "timestamp": timestamp,
        "doc_id": doc_id,
    }


@router.get("")
def list_vulnerabilities(
    severity: str | None = Query(default=None, description="Comma-separated: critical,high,medium,low"),
    group: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    agent_ids: str | None = Query(default=None, description="Comma-separated agent IDs"),
    include_resolved: bool = Query(default=False, description="Include resolved/fixed vulnerabilities"),
    limit: int = Query(default=10000, ge=1, le=100000),
    user=Depends(require_role("analyst")),
):
    if not indexer.enabled:
        return {
            "items": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0, "records": 0, "affected_agents": 0},
            "query_limit": limit,
            "truncated": False,
            "target_agents": {s: [] for s in _KNOWN_SEVERITIES},
            "source": "indexer",
            "error": "Indexer is disabled",
            "recommended_action": _specific_software_action_id(),
        }

    severity_filter = _normalize_severity_filter(severity)
    scoped_agents = _resolve_scope_agent_ids(agent_id=agent_id, agent_ids=agent_ids, group=group)
    scoped_set = set(scoped_agents)

    try:
        raw = indexer.search_vulnerabilities_fleet(limit=limit, agent_ids=scoped_agents or None)
        rows = indexer.extract_vulnerabilities(raw)
    except HTTPException as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc.detail) if getattr(exc, "detail", None) else "Wazuh indexer unavailable",
        ) from exc

    agent_catalog = _load_agent_catalog()
    source_rows = len(rows)
    local_closures = _load_local_closure_map()
    entries: Dict[str, Dict[str, Any]] = {}
    target_agents: Dict[str, Set[str]] = {s: set() for s in _KNOWN_SEVERITIES}
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    affected_agents_global: Set[str] = set()
    records_count = 0
    latest_agent_vuln_rows: Dict[str, Dict[str, Any]] = {}

    for row in rows:
        if not isinstance(row, dict):
            continue
        agent_obj = row.get("agent") if isinstance(row.get("agent"), dict) else {}
        row_agent_id = _normalize_agent_id(agent_obj.get("id") or row.get("agent_id") or row.get("agent.id"))
        if not row_agent_id:
            continue
        if scoped_set and row_agent_id not in scoped_set:
            continue

        parsed = _extract_vuln_record(row)

        key_seed = [
            parsed["cve"],
            parsed["title"] if parsed["title"] != "Vulnerability" else "",
            parsed["package_name"],
            parsed["condition"],
        ]
        vuln_key = "|".join([str(v or "").strip() for v in key_seed if str(v or "").strip()])
        if not vuln_key:
            vuln_key = f"doc:{parsed.get('doc_id') or row_agent_id}"
        agent_vuln_key = f"{row_agent_id}|{vuln_key}"
        if agent_vuln_key in latest_agent_vuln_rows:
            # Indexer rows are sorted desc by timestamp; first hit is the newest state.
            continue
        latest_agent_vuln_rows[agent_vuln_key] = {
            "agent_id": row_agent_id,
            "parsed": parsed,
            "vuln_key": vuln_key,
        }

    for rec in latest_agent_vuln_rows.values():
        row_agent_id = rec["agent_id"]
        parsed = rec["parsed"]
        key = rec["vuln_key"]
        sev_key = parsed["severity"]
        local_close = local_closures.get((key, row_agent_id))
        if local_close and not include_resolved:
            continue
        if severity_filter and sev_key not in severity_filter:
            continue
        if not include_resolved and _is_resolved_status(parsed.get("status")):
            continue
        if local_close and not parsed.get("status"):
            parsed["status"] = "locally_closed"

        records_count += 1
        affected_agents_global.add(row_agent_id)
        if sev_key in target_agents:
            target_agents[sev_key].add(row_agent_id)

        entry = entries.get(key)
        if not entry:
            summary[sev_key] = summary.get(sev_key, 0) + 1
            entry = {
                "id": key,
                "cve": parsed["cve"],
                "title": parsed["title"],
                "severity": sev_key,
                "score": parsed["score"],
                "package": {
                    "name": parsed["package_name"],
                    "version": parsed["package_version"],
                    "condition": parsed["condition"],
                    "source": parsed["package_source"],
                },
                "classification": parsed["classification"],
                "type": parsed["type"],
                "rationale": parsed["rationale"],
                "cwe_reference": parsed["cwe_reference"],
                "assigner": parsed["assigner"],
                "status": parsed["status"],
                "published": parsed["published"],
                "updated": parsed["updated"],
                "last_seen": parsed["timestamp"],
                "references": parsed["references"],
                "scanner_reference": parsed["scanner_reference"],
                "affected_agents": [],
                "affected_count": 0,
                "_agent_seen": set(),
            }
            entries[key] = entry
        else:
            if _is_resolved_status(entry.get("status")) and not _is_resolved_status(parsed.get("status")):
                entry["status"] = parsed.get("status")
        if parsed["timestamp"] and (
            not entry.get("last_seen") or str(parsed["timestamp"]) > str(entry.get("last_seen"))
        ):
            entry["last_seen"] = parsed["timestamp"]

        if row_agent_id not in entry["_agent_seen"]:
            meta = agent_catalog.get(row_agent_id) or {
                "id": row_agent_id,
                "name": row_agent_id,
                "ip": str(agent_obj.get("ip") or ""),
                "status": "",
                "groups": [],
                "platform": _platform_name(_pick(_dict(agent_obj.get("os")).get("platform"), agent_obj.get("os_name"), agent_obj.get("platform"))),
            }
            if local_close:
                meta["local_closure"] = local_close
            entry["_agent_seen"].add(row_agent_id)
            entry["affected_agents"].append(meta)

    items: List[Dict[str, Any]] = []
    for entry in entries.values():
        entry.pop("_agent_seen", None)
        entry["affected_agents"] = sorted(
            entry.get("affected_agents") or [],
            key=lambda agent: str(agent.get("id") or ""),
        )
        entry["affected_count"] = len(entry["affected_agents"])
        entry["remediation"] = _build_remediation(entry)
        items.append(entry)

    items.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity") or "unknown"), 4),
            -(item.get("affected_count") or 0),
            -(_to_float(item.get("score")) or 0),
            str(item.get("cve") or item.get("title") or ""),
        )
    )

    return {
        "items": items,
        "summary": {
            **summary,
            "total": len(items),
            "records": records_count,
            "affected_agents": len(affected_agents_global),
        },
        "query_limit": limit,
        "truncated": source_rows >= limit,
        "target_agents": {k: sorted(v) for k, v in target_agents.items()},
        "source": "indexer",
        "error": None,
        "recommended_action": _specific_software_action_id(),
    }

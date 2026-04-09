from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.security_monitoring import record_security_event
from core.settings import SETTINGS


@dataclass(frozen=True)
class SecurityFinding:
    code: str
    severity: str
    detail: str
    recommendation: str
    metadata: dict[str, Any] | None = None


_FINDING_LOCK = threading.Lock()
_LAST_RECORDED: dict[str, float] = {}


def _security_cfg() -> dict[str, Any]:
    return SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def _resolve_repo_root() -> Path | None:
    try:
        return Path(__file__).resolve().parents[2]
    except Exception:
        return None


def _load_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return []
    return [line.strip() for line in text.splitlines()]


def _requirements_findings(root: Path | None) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    if root is None:
        return findings
    req_path = root / "backend" / "requirements.txt"
    lock_path = root / "backend" / "requirements.lock"
    if not req_path.exists():
        return findings

    req_lines = [line for line in _load_lines(req_path) if line and not line.startswith("#") and not line.startswith("-r")]
    if not lock_path.exists():
        findings.append(
            SecurityFinding(
                code="supply_chain.missing_python_lockfile",
                severity="warning",
                detail="backend/requirements.lock is missing.",
                recommendation="Generate and commit a pinned requirements.lock for production installs.",
            )
        )
        return findings

    lock_lines = [line for line in _load_lines(lock_path) if line and not line.startswith("#") and not line.startswith("-r")]
    missing: list[str] = []
    unpinned: list[str] = []
    lock_names: set[str] = set()

    for line in lock_lines:
        if "==" not in line:
            unpinned.append(line)
            continue
        name = line.split("==", 1)[0].strip().lower().replace("-", "_")
        if name:
            lock_names.add(name)

    for line in req_lines:
        raw = line.split(";", 1)[0].strip()
        if not raw:
            continue
        name = raw.split("==", 1)[0]
        for token in (">=", "<=", "~=", "!=", ">", "<", "@", "["):
            if token in name:
                name = name.split(token, 1)[0]
                break
        norm = name.strip().lower().replace("-", "_")
        if norm and norm not in lock_names:
            missing.append(name.strip())

    if unpinned or missing:
        detail = []
        if missing:
            detail.append(f"{len(missing)} requirements missing from lockfile")
        if unpinned:
            detail.append(f"{len(unpinned)} lockfile entries are not pinned")
        findings.append(
            SecurityFinding(
                code="supply_chain.python_lock_mismatch",
                severity="warning",
                detail="; ".join(detail) or "requirements.lock does not match requirements.txt",
                recommendation="Regenerate requirements.lock from requirements.txt and ensure all entries are pinned.",
                metadata={"missing": missing[:10], "unpinned": unpinned[:10]},
            )
        )
    return findings


def _frontend_lockfile_findings(root: Path | None) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    if root is None:
        return findings
    pkg_path = root / "frontend" / "package.json"
    lock_path = root / "frontend" / "package-lock.json"
    if pkg_path.exists() and not lock_path.exists():
        findings.append(
            SecurityFinding(
                code="supply_chain.missing_frontend_lockfile",
                severity="warning",
                detail="frontend/package.json exists but package-lock.json is missing.",
                recommendation="Commit a lockfile to ensure repeatable frontend installs.",
            )
        )
    return findings


def assess_supply_chain() -> dict[str, Any]:
    root = _resolve_repo_root()
    findings = []
    findings.extend(_requirements_findings(root))
    findings.extend(_frontend_lockfile_findings(root))
    return {
        "findings": [finding.__dict__ for finding in findings],
        "ok": not findings,
    }


def _config_findings() -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    cfg = _security_cfg()
    jwt_secret = str(cfg.get("jwt_secret") or "").strip()
    if not jwt_secret or jwt_secret in {"CHANGE_ME", "CHANGE_ME_TO_A_LONG_RANDOM_VALUE"}:
        findings.append(
            SecurityFinding(
                code="config.jwt_secret_missing",
                severity="critical",
                detail="JWT secret is unset or still using the default placeholder.",
                recommendation="Set JWT_SECRET to a 32+ character random value before launch.",
            )
        )
    elif len(jwt_secret) < 32:
        findings.append(
            SecurityFinding(
                code="config.jwt_secret_short",
                severity="warning",
                detail="JWT secret is shorter than 32 characters.",
                recommendation="Use a 32+ character random JWT secret for production.",
            )
        )

    if cfg.get("allow_demo_users") is True:
        findings.append(
            SecurityFinding(
                code="config.demo_users_enabled",
                severity="critical",
                detail="Demo users are enabled.",
                recommendation="Disable demo users before launch.",
            )
        )

    if cfg.get("cookie_secure") is False:
        findings.append(
            SecurityFinding(
                code="config.cookie_secure_disabled",
                severity="warning",
                detail="Auth cookies are configured as non-secure.",
                recommendation="Enable secure cookies for HTTPS deployments.",
            )
        )

    cors_origins = cfg.get("cors_origins") if isinstance(cfg.get("cors_origins"), list) else []
    if any(str(origin).strip() == "*" for origin in cors_origins):
        findings.append(
            SecurityFinding(
                code="config.cors_wildcard",
                severity="warning",
                detail="CORS configuration includes wildcard origins.",
                recommendation="Restrict CORS origins to approved domains.",
            )
        )

    trusted_hosts = cfg.get("trusted_hosts") if isinstance(cfg.get("trusted_hosts"), list) else []
    if not trusted_hosts:
        findings.append(
            SecurityFinding(
                code="config.trusted_hosts_empty",
                severity="warning",
                detail="Trusted host allowlist is empty.",
                recommendation="Set trusted hosts to known domains before launch.",
            )
        )
    if any(str(host).strip() == "*" for host in trusted_hosts):
        findings.append(
            SecurityFinding(
                code="config.trusted_hosts_wildcard",
                severity="warning",
                detail="Trusted hosts allowlist includes a wildcard entry.",
                recommendation="Restrict trusted hosts to explicit domains.",
            )
        )

    v2_abac = cfg.get("v2_abac") if isinstance(cfg.get("v2_abac"), dict) else {}
    opa_url = str(v2_abac.get("opa_url") or "").strip()
    opa_fail_closed = _as_bool(v2_abac.get("opa_fail_closed"), False)
    if opa_url and not opa_fail_closed:
        findings.append(
            SecurityFinding(
                code="config.opa_fail_open",
                severity="warning",
                detail="OPA policy is configured but fail-closed mode is disabled.",
                recommendation="Enable opa_fail_closed to prevent policy bypass on outages.",
            )
        )

    return findings


def assess_security_posture() -> dict[str, Any]:
    config_findings = _config_findings()
    supply_chain = assess_supply_chain()
    ok = not config_findings and bool(supply_chain.get("ok"))
    return {
        "ok": bool(ok),
        "config_findings": [finding.__dict__ for finding in config_findings],
        "supply_chain": supply_chain,
    }


def record_posture_findings(
    posture: dict[str, Any],
    *,
    min_interval_seconds: int = 3600,
) -> None:
    findings = []
    for item in posture.get("config_findings") or []:
        if isinstance(item, dict):
            findings.append(item)
    for item in (posture.get("supply_chain") or {}).get("findings") or []:
        if isinstance(item, dict):
            findings.append(item)

    now = time.time()
    with _FINDING_LOCK:
        for finding in findings:
            code = str(finding.get("code") or "").strip().lower()
            if not code:
                continue
            last = _LAST_RECORDED.get(code, 0.0)
            if now - last < min_interval_seconds:
                continue
            _LAST_RECORDED[code] = now
            record_security_event(
                f"security.posture.{code}",
                severity=str(finding.get("severity") or "warning"),
                detail=str(finding.get("detail") or "Security posture finding detected"),
                metadata={
                    "recommendation": finding.get("recommendation"),
                    "metadata": finding.get("metadata") or {},
                },
                persist=True,
            )

from __future__ import annotations

import json
import re
from typing import Any, Dict, List


_TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

_TACTIC_CANONICAL = {
    "initial access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege escalation": "Privilege Escalation",
    "defense evasion": "Defense Evasion",
    "credential access": "Credential Access",
    "discovery": "Discovery",
    "lateral movement": "Lateral Movement",
    "collection": "Collection",
    "command and control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "resource development": "Resource Development",
    "reconnaissance": "Reconnaissance",
}

_SOURCE_PRIORITY = {
    "native_mitre": 5,
    "rule_id_map": 4,
    "keyword_heuristic": 3,
    "group_heuristic": 2,
    "severity_fallback": 1,
}

_RULE_ID_MAP: Dict[str, List[Dict[str, Any]]] = {
    "100100": [
        {
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter",
            "technique_id": "T1059",
            "confidence": 78,
        }
    ],
    "100200": [
        {
            "tactic": "Credential Access",
            "technique": "OS Credential Dumping",
            "technique_id": "T1003",
            "confidence": 84,
        }
    ],
}

_GROUP_HEURISTICS: Dict[str, List[Dict[str, Any]]] = {
    "authentication_failed": [
        {
            "tactic": "Credential Access",
            "technique": "Brute Force",
            "technique_id": "T1110",
            "confidence": 66,
        }
    ],
    "authentication_success": [
        {
            "tactic": "Initial Access",
            "technique": "Valid Accounts",
            "technique_id": "T1078",
            "confidence": 58,
        }
    ],
    "web": [
        {
            "tactic": "Initial Access",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190",
            "confidence": 54,
        }
    ],
}

_KEYWORD_HEURISTICS: List[Dict[str, Any]] = [
    {
        "pattern": re.compile(r"\b(mimikatz|sekurlsa|lsass\s+dump|credential\s+dump)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Credential Access",
                "technique": "OS Credential Dumping",
                "technique_id": "T1003",
                "confidence": 92,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(pass[- ]the[- ]hash|ntlm\s+relay)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Credential Access",
                "technique": "Use Alternate Authentication Material: Pass the Hash",
                "technique_id": "T1550.002",
                "confidence": 88,
            },
            {
                "tactic": "Lateral Movement",
                "technique": "Remote Services: SMB/Windows Admin Shares",
                "technique_id": "T1021.002",
                "confidence": 72,
            },
        ],
    },
    {
        "pattern": re.compile(r"\b(powershell|pwsh)\b.*\b(-enc|encodedcommand|frombase64string|iex)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Execution",
                "technique": "PowerShell",
                "technique_id": "T1059.001",
                "confidence": 86,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(cmd\.exe|powershell|wscript|cscript|bash)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Execution",
                "technique": "Command and Scripting Interpreter",
                "technique_id": "T1059",
                "confidence": 65,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(rundll32|regsvr32|mshta|installutil)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Defense Evasion",
                "technique": "Signed Binary Proxy Execution",
                "technique_id": "T1218",
                "confidence": 80,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(schtasks|at\.exe|cron|systemd)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Persistence",
                "technique": "Scheduled Task/Job",
                "technique_id": "T1053",
                "confidence": 72,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(winrm|wmi|wmic|psexec|remote\s+logon|rdp)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Lateral Movement",
                "technique": "Remote Services",
                "technique_id": "T1021",
                "confidence": 70,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(certutil|bitsadmin|invoke-webrequest|curl\s+https?://|wget\s+https?://)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Command and Control",
                "technique": "Ingress Tool Transfer",
                "technique_id": "T1105",
                "confidence": 73,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(vssadmin\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Impact",
                "technique": "Inhibit System Recovery",
                "technique_id": "T1490",
                "confidence": 86,
            }
        ],
    },
    {
        "pattern": re.compile(r"\b(logon failure|unknown user or bad password|failed password|brute force)\b", re.IGNORECASE),
        "mappings": [
            {
                "tactic": "Credential Access",
                "technique": "Brute Force",
                "technique_id": "T1110",
                "confidence": 70,
            }
        ],
    },
]


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _to_text_list(value: Any) -> List[str]:
    out: List[str] = []
    for item in _as_list(value):
        if item is None:
            continue
        text = str(item).strip()
        if not text:
            continue
        if "," in text and len(text) > 6 and not _TECHNIQUE_ID_RE.search(text):
            out.extend([chunk.strip() for chunk in text.split(",") if chunk.strip()])
            continue
        out.append(text)
    return out


def _normalize_tactic(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    return _TACTIC_CANONICAL.get(raw.lower(), raw.title())


def _normalize_technique_id(value: Any) -> str:
    match = _TECHNIQUE_ID_RE.search(str(value or ""))
    if not match:
        return ""
    return match.group(0).upper()


def _candidate(
    tactic: str,
    technique: str,
    technique_id: str,
    confidence: int,
    source: str,
) -> Dict[str, Any] | None:
    tactic_norm = _normalize_tactic(tactic)
    technique_norm = str(technique or "").strip()
    technique_id_norm = _normalize_technique_id(technique_id)
    if not tactic_norm and not technique_norm and not technique_id_norm:
        return None
    return {
        "tactic": tactic_norm or "Execution",
        "technique": technique_norm or "Unknown Technique",
        "technique_id": technique_id_norm,
        "confidence": max(1, min(100, int(confidence or 1))),
        "source": source,
    }


def _extract_native_mitre(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    mitre_raw = rule.get("mitre")
    if mitre_raw is None:
        return []

    mappings: List[Dict[str, Any]] = []
    for item in _as_list(mitre_raw):
        if isinstance(item, str):
            candidate = _candidate(
                tactic="",
                technique="",
                technique_id=item,
                confidence=96,
                source="native_mitre",
            )
            if candidate:
                mappings.append(candidate)
            continue

        if not isinstance(item, dict):
            continue

        technique_ids = _to_text_list(item.get("id") or item.get("technique_id") or item.get("technique_ids"))
        tactics = _to_text_list(item.get("tactic") or item.get("tactics"))
        techniques = _to_text_list(item.get("technique") or item.get("techniques"))

        if technique_ids:
            for idx, tech_id in enumerate(technique_ids):
                tactic = tactics[idx] if idx < len(tactics) else (tactics[0] if tactics else "")
                technique = techniques[idx] if idx < len(techniques) else (techniques[0] if techniques else "")
                candidate = _candidate(
                    tactic=tactic,
                    technique=technique,
                    technique_id=tech_id,
                    confidence=96,
                    source="native_mitre",
                )
                if candidate:
                    mappings.append(candidate)
            continue

        if techniques:
            for idx, technique in enumerate(techniques):
                tactic = tactics[idx] if idx < len(tactics) else (tactics[0] if tactics else "")
                candidate = _candidate(
                    tactic=tactic,
                    technique=technique,
                    technique_id="",
                    confidence=90,
                    source="native_mitre",
                )
                if candidate:
                    mappings.append(candidate)

    return mappings


def _extract_rule_groups(rule: Dict[str, Any]) -> List[str]:
    groups = _to_text_list(rule.get("groups"))
    return [g.strip().lower() for g in groups if g.strip()]


def _alert_text(alert: Dict[str, Any]) -> str:
    fragments: List[str] = []
    rule = alert.get("rule") if isinstance(alert, dict) else {}
    if isinstance(rule, dict):
        fragments.extend(_to_text_list(rule.get("description")))
        fragments.extend(_to_text_list(rule.get("id")))
        fragments.extend(_to_text_list(rule.get("groups")))

    for key in ("full_log", "decoder", "location", "input"):
        fragments.extend(_to_text_list(alert.get(key)))

    data = alert.get("data")
    if data is not None:
        try:
            fragments.append(json.dumps(data, default=str))
        except Exception:
            fragments.append(str(data))

    try:
        fragments.append(json.dumps(alert, default=str))
    except Exception:
        fragments.append(str(alert))

    return " ".join(fragments).lower()


def _add_rule_id_candidates(rule_id: str, out: List[Dict[str, Any]]) -> None:
    for mapping in _RULE_ID_MAP.get(rule_id, []):
        candidate = _candidate(
            tactic=mapping.get("tactic", ""),
            technique=mapping.get("technique", ""),
            technique_id=mapping.get("technique_id", ""),
            confidence=int(mapping.get("confidence", 75)),
            source="rule_id_map",
        )
        if candidate:
            out.append(candidate)


def _add_group_candidates(groups: List[str], out: List[Dict[str, Any]]) -> None:
    for group in groups:
        for mapping in _GROUP_HEURISTICS.get(group, []):
            candidate = _candidate(
                tactic=mapping.get("tactic", ""),
                technique=mapping.get("technique", ""),
                technique_id=mapping.get("technique_id", ""),
                confidence=int(mapping.get("confidence", 55)),
                source="group_heuristic",
            )
            if candidate:
                out.append(candidate)


def _add_keyword_candidates(alert_text: str, out: List[Dict[str, Any]]) -> None:
    for heuristic in _KEYWORD_HEURISTICS:
        pattern = heuristic.get("pattern")
        if not pattern or not pattern.search(alert_text):
            continue
        for mapping in heuristic.get("mappings", []):
            candidate = _candidate(
                tactic=mapping.get("tactic", ""),
                technique=mapping.get("technique", ""),
                technique_id=mapping.get("technique_id", ""),
                confidence=int(mapping.get("confidence", 60)),
                source="keyword_heuristic",
            )
            if candidate:
                out.append(candidate)


def _add_severity_fallback(rule_level: int, out: List[Dict[str, Any]]) -> None:
    if rule_level >= 12:
        candidate = _candidate(
            tactic="Impact",
            technique="Data Destruction or Service Disruption",
            technique_id="T1485",
            confidence=35,
            source="severity_fallback",
        )
        if candidate:
            out.append(candidate)
    elif rule_level >= 8:
        candidate = _candidate(
            tactic="Execution",
            technique="Suspicious Command Execution",
            technique_id="T1059",
            confidence=28,
            source="severity_fallback",
        )
        if candidate:
            out.append(candidate)


def _dedupe_and_rank(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_key: Dict[tuple, Dict[str, Any]] = {}
    for item in candidates:
        technique_id = str(item.get("technique_id") or "").upper()
        tactic = str(item.get("tactic") or "").lower()
        technique = str(item.get("technique") or "").lower()
        key = (technique_id, tactic) if technique_id else (technique, tactic)
        existing = by_key.get(key)
        if not existing:
            by_key[key] = item
            continue
        if int(item.get("confidence", 0)) > int(existing.get("confidence", 0)):
            by_key[key] = item
            continue
        if int(item.get("confidence", 0)) == int(existing.get("confidence", 0)):
            if _SOURCE_PRIORITY.get(str(item.get("source")), 0) > _SOURCE_PRIORITY.get(
                str(existing.get("source")), 0
            ):
                by_key[key] = item

    ranked = list(by_key.values())
    ranked.sort(
        key=lambda item: (
            -int(item.get("confidence", 0)),
            -_SOURCE_PRIORITY.get(str(item.get("source")), 0),
            str(item.get("technique_id") or ""),
            str(item.get("tactic") or ""),
        )
    )
    return ranked


class MitreMapper:
    def map_alerts(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not isinstance(alert, dict):
            return []

        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        rule_id = str(rule.get("id") or "").strip()
        rule_level = int(rule.get("level") or 0) if str(rule.get("level") or "").isdigit() else 0
        groups = _extract_rule_groups(rule)
        text_blob = _alert_text(alert)

        candidates: List[Dict[str, Any]] = []
        candidates.extend(_extract_native_mitre(rule))
        if rule_id:
            _add_rule_id_candidates(rule_id, candidates)
        if groups:
            _add_group_candidates(groups, candidates)
        _add_keyword_candidates(text_blob, candidates)
        if not candidates and rule_level > 0:
            _add_severity_fallback(rule_level, candidates)

        return _dedupe_and_rank(candidates)

    def map_alert(self, alert: Dict[str, Any]) -> Dict[str, Any] | None:
        ranked = self.map_alerts(alert)
        return ranked[0] if ranked else None

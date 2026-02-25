from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

import requests
from requests import RequestException
from requests.adapters import HTTPAdapter
from sqlalchemy import text

from core.settings import SETTINGS
from db.database import connect

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _verdict_from_score(score: int) -> str:
    if score >= 80:
        return "malicious"
    if score >= 50:
        return "suspicious"
    if score > 0:
        return "low_confidence"
    return "unknown"


class IOCEnricher:
    def __init__(self):
        cfg = SETTINGS.get("threat_intel", {}) if isinstance(SETTINGS, dict) else {}
        self.enabled = _to_bool(cfg.get("enabled", True), True)
        self.timeout_seconds = max(2, _to_int(cfg.get("timeout_seconds", 8), 8))
        self.otx_enabled = _to_bool(cfg.get("otx_enabled", True), True)
        self.abuse_enabled = _to_bool(cfg.get("abuse_ch_enabled", True), True)
        self.otx_base = str(cfg.get("otx_base_url", "https://otx.alienvault.com")).rstrip("/")
        self.abuse_base = str(cfg.get("abuse_ch_base_url", "https://threatfox-api.abuse.ch")).rstrip("/")
        self.otx_api_key = os.getenv("OTX_API_KEY", str(cfg.get("otx_api_key", "") or "")).strip()
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=100)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def extract(self, alert: Any) -> Dict[str, List[str]]:
        text_value = json.dumps(alert, default=str) if isinstance(alert, dict) else str(alert or "")
        ips = sorted(set(_IPV4_RE.findall(text_value)))
        hashes = sorted(set(_SHA256_RE.findall(text_value)))
        return {
            "ip": ips,
            "hash": hashes,
        }

    def _query_otx(self, ioc: str, ioc_type: str) -> Dict[str, Any] | None:
        if not self.otx_enabled:
            return None
        endpoint = ""
        if ioc_type == "ip":
            endpoint = f"/api/v1/indicators/IPv4/{ioc}/general"
        elif ioc_type == "hash":
            endpoint = f"/api/v1/indicators/file/{ioc}/general"
        else:
            return None
        headers = {"Accept": "application/json"}
        if self.otx_api_key:
            headers["X-OTX-API-KEY"] = self.otx_api_key
        try:
            response = self.session.get(
                f"{self.otx_base}{endpoint}",
                headers=headers,
                timeout=self.timeout_seconds,
            )
            if response.status_code >= 400:
                return None
            data = response.json() if response.text else {}
            pulse_info = data.get("pulse_info", {}) if isinstance(data, dict) else {}
            pulse_count = _to_int(pulse_info.get("count", 0), 0)
            reputation = _to_int(data.get("reputation", 0) if isinstance(data, dict) else 0, 0)
            score = max(0, min(100, (pulse_count * 15) + max(0, reputation)))
            return {
                "source": "alienvault_otx",
                "score": score,
                "verdict": _verdict_from_score(score),
                "details": {
                    "pulse_count": pulse_count,
                    "reputation": reputation,
                },
            }
        except (RequestException, ValueError):
            return None

    def _query_abuse_ch(self, ioc: str, ioc_type: str) -> Dict[str, Any] | None:
        if not self.abuse_enabled:
            return None
        if ioc_type == "hash":
            payload = {"query": "search_hash", "hash": ioc}
        elif ioc_type == "ip":
            payload = {"query": "search_ioc", "search_term": ioc}
        else:
            return None
        try:
            response = self.session.post(
                f"{self.abuse_base}/api/v1/",
                json=payload,
                timeout=self.timeout_seconds,
            )
            if response.status_code >= 400:
                return None
            data = response.json() if response.text else {}
            if not isinstance(data, dict):
                return None
            if data.get("query_status") in {"no_result", "unknown_query", "bad_query"}:
                return {
                    "source": "abuse_ch_threatfox",
                    "score": 0,
                    "verdict": "unknown",
                    "details": {"query_status": data.get("query_status")},
                }
            rows = data.get("data")
            if not isinstance(rows, list):
                rows = []
            confidence_scores: List[int] = []
            malware_families = set()
            for row in rows:
                if not isinstance(row, dict):
                    continue
                confidence_scores.append(_to_int(row.get("confidence_level", 0), 0))
                family = str(row.get("malware") or row.get("malware_printable") or "").strip()
                if family:
                    malware_families.add(family)
            score = max(confidence_scores) if confidence_scores else 0
            return {
                "source": "abuse_ch_threatfox",
                "score": max(0, min(100, score)),
                "verdict": _verdict_from_score(max(0, min(100, score))),
                "details": {
                    "matches": len(rows),
                    "families": sorted(malware_families),
                },
            }
        except (RequestException, ValueError):
            return None

    def _enrich_indicator(self, ioc: str, ioc_type: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        otx = self._query_otx(ioc, ioc_type)
        if otx:
            findings.append(otx)
        abuse = self._query_abuse_ch(ioc, ioc_type)
        if abuse:
            findings.append(abuse)
        if not findings:
            return [
                {
                    "source": "community_feeds",
                    "score": 0,
                    "verdict": "unknown",
                    "details": {"reason": "no_feed_response"},
                }
            ]
        avg_score = int(round(sum(item["score"] for item in findings) / max(1, len(findings))))
        findings.append(
            {
                "source": "normalized_combined",
                "score": max(0, min(100, avg_score)),
                "verdict": _verdict_from_score(avg_score),
                "details": {"sources": [item["source"] for item in findings]},
            }
        )
        return findings

    def enrich_alert(self, alert_id: str, alert: Any) -> None:
        if not self.enabled:
            return
        iocs = self.extract(alert)
        db = connect()
        try:
            for ioc_type, values in iocs.items():
                for ioc in values:
                    findings = self._enrich_indicator(ioc, ioc_type)
                    for finding in findings:
                        source = str(finding.get("source") or "")
                        exists = db.execute(
                            text(
                                """
                                SELECT 1
                                FROM ioc_enrichments
                                WHERE alert_id=:alert_id
                                  AND ioc=:ioc
                                  AND ioc_type=:ioc_type
                                  AND source=:source
                                LIMIT 1
                                """
                            ),
                            {
                                "alert_id": alert_id,
                                "ioc": ioc,
                                "ioc_type": ioc_type,
                                "source": source,
                            },
                        ).fetchone()
                        if exists:
                            continue
                        db.execute(
                            text(
                                """
                                INSERT INTO ioc_enrichments
                                (alert_id, ioc, ioc_type, source, score, verdict, details)
                                VALUES (:alert_id, :ioc, :ioc_type, :source, :score, :verdict, :details)
                                """
                            ),
                            {
                                "alert_id": alert_id,
                                "ioc": ioc,
                                "ioc_type": ioc_type,
                                "source": source,
                                "score": int(finding.get("score") or 0),
                                "verdict": str(finding.get("verdict") or "unknown"),
                                "details": _safe_json(finding.get("details") or {}),
                            },
                        )
            db.commit()
        finally:
            db.close()

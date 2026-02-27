from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import quote, urlsplit

import requests
from requests import RequestException
from requests.adapters import HTTPAdapter
from sqlalchemy import text

from core.settings import SETTINGS
from core.time_utils import utc_now_naive
from db.database import connect

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

_IP_HINTS = {
    "ip",
    "srcip",
    "dstip",
    "sourceip",
    "destinationip",
    "src_ip",
    "dst_ip",
    "remoteip",
    "clientip",
    "ipaddress",
}
_HASH_HINTS = {"hash", "sha256", "sha1", "md5", "checksum", "filehash"}
_DOMAIN_HINTS = {"domain", "hostname", "dns", "query", "fqdn"}
_URL_HINTS = {"url", "uri", "request", "link"}

_VERDICT_RANK = {
    "unknown": 0,
    "low_confidence": 1,
    "suspicious": 2,
    "malicious": 3,
}


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


def _to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _verdict_from_score(score: int) -> str:
    if score >= 85:
        return "malicious"
    if score >= 55:
        return "suspicious"
    if score > 0:
        return "low_confidence"
    return "unknown"


def _preferred_verdict(existing: Any, incoming: Any) -> str:
    existing_text = str(existing or "unknown").strip().lower() or "unknown"
    incoming_text = str(incoming or "unknown").strip().lower() or "unknown"
    if _VERDICT_RANK.get(incoming_text, 0) > _VERDICT_RANK.get(existing_text, 0):
        return incoming_text
    return existing_text


def _walk_values(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _walk_values(item, child)
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            child = f"{path}[{idx}]"
            yield from _walk_values(item, child)
        return
    yield path, value


def _path_tokens(path: str) -> Set[str]:
    raw = str(path or "").replace("[", ".").replace("]", "")
    tokens = re.split(r"[^a-zA-Z0-9_]+", raw.lower())
    return {t for t in tokens if t}


def _clean_scalar(value: Any) -> str:
    text_value = str(value or "").strip().strip("\"'")
    return text_value


def _normalize_ipv4(value: Any) -> str | None:
    candidate = _clean_scalar(value)
    if not candidate:
        return None
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except Exception:
        return None
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return None
    if not ip_obj.is_global:
        return None
    return str(ip_obj)


def _normalize_hash(value: Any) -> str | None:
    candidate = _clean_scalar(value).lower()
    if not candidate:
        return None
    if len(candidate) not in {32, 40, 64}:
        return None
    if not re.fullmatch(r"[a-f0-9]+", candidate):
        return None
    if len(set(candidate)) == 1:
        return None
    return candidate


def _normalize_url(value: Any) -> str | None:
    candidate = _clean_scalar(value)
    if not candidate:
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None
    normalized = parsed.geturl().rstrip(".,;)")
    return normalized


def _normalize_domain(value: Any) -> str | None:
    candidate = _clean_scalar(value).lower()
    if not candidate:
        return None
    if "@" in candidate:
        return None

    if "://" in candidate:
        parsed = urlsplit(candidate)
        candidate = parsed.hostname or ""

    candidate = candidate.split("/")[0].split(":")[0].strip(".")
    if not candidate or candidate in {"localhost", "localdomain"}:
        return None
    if candidate.endswith((".local", ".lan", ".home", ".internal")):
        return None

    try:
        ipaddress.ip_address(candidate)
        return None
    except Exception:
        pass

    if not _DOMAIN_RE.fullmatch(candidate):
        return None
    return candidate


def _append_indicators(target: Dict[str, Set[str]], ioc_type: str, values: Iterable[str]) -> None:
    bucket = target.setdefault(ioc_type, set())
    for value in values:
        if value:
            bucket.add(value)


class IOCEnricher:
    def __init__(self):
        cfg = SETTINGS.get("threat_intel", {}) if isinstance(SETTINGS, dict) else {}
        self.enabled = _to_bool(cfg.get("enabled", True), True)
        self.timeout_seconds = max(2, _to_int(cfg.get("timeout_seconds", 8), 8))
        self.otx_enabled = _to_bool(cfg.get("otx_enabled", True), True)
        self.abuse_enabled = _to_bool(cfg.get("abuse_ch_enabled", True), True)
        self.max_indicators_per_type = max(1, _to_int(cfg.get("max_indicators_per_type", 25), 25))
        self.otx_base = str(cfg.get("otx_base_url", "https://otx.alienvault.com")).rstrip("/")
        self.abuse_base = str(cfg.get("abuse_ch_base_url", "https://threatfox-api.abuse.ch")).rstrip("/")
        self.otx_api_key = os.getenv("OTX_API_KEY", str(cfg.get("otx_api_key", "") or "")).strip()
        configured_weights = cfg.get("source_weights", {}) if isinstance(cfg.get("source_weights"), dict) else {}
        self.source_weights = {
            "alienvault_otx": max(0.1, _to_float(configured_weights.get("alienvault_otx", 0.95), 0.95)),
            "abuse_ch_threatfox": max(0.1, _to_float(configured_weights.get("abuse_ch_threatfox", 1.0), 1.0)),
        }
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=100, max_retries=2)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self._cache: Dict[tuple[str, str], List[Dict[str, Any]]] = {}

    def extract(self, alert: Any) -> Dict[str, List[str]]:
        indicators: Dict[str, Set[str]] = {
            "ip": set(),
            "hash": set(),
            "domain": set(),
            "url": set(),
        }

        for path, value in _walk_values(alert):
            if value is None:
                continue
            if isinstance(value, (dict, list, tuple)):
                continue
            scalar = _clean_scalar(value)
            if not scalar or len(scalar) > 4096:
                continue

            tokens = _path_tokens(path)
            if tokens & _IP_HINTS:
                ip_value = _normalize_ipv4(scalar)
                if ip_value:
                    indicators["ip"].add(ip_value)

            if tokens & _HASH_HINTS:
                hash_value = _normalize_hash(scalar)
                if hash_value:
                    indicators["hash"].add(hash_value)

            if tokens & _DOMAIN_HINTS:
                domain_value = _normalize_domain(scalar)
                if domain_value:
                    indicators["domain"].add(domain_value)

            if tokens & _URL_HINTS:
                url_value = _normalize_url(scalar)
                if url_value:
                    indicators["url"].add(url_value)
                    domain_value = _normalize_domain(url_value)
                    if domain_value:
                        indicators["domain"].add(domain_value)

        text_value = json.dumps(alert, default=str) if isinstance(alert, dict) else str(alert or "")

        _append_indicators(indicators, "ip", filter(None, (_normalize_ipv4(match) for match in _IPV4_RE.findall(text_value))))
        _append_indicators(indicators, "hash", filter(None, (_normalize_hash(match) for match in _SHA256_RE.findall(text_value))))
        _append_indicators(indicators, "hash", filter(None, (_normalize_hash(match) for match in _SHA1_RE.findall(text_value))))
        _append_indicators(indicators, "hash", filter(None, (_normalize_hash(match) for match in _MD5_RE.findall(text_value))))

        for url_match in _URL_RE.findall(text_value):
            normalized_url = _normalize_url(url_match)
            if normalized_url:
                indicators["url"].add(normalized_url)
                domain_value = _normalize_domain(normalized_url)
                if domain_value:
                    indicators["domain"].add(domain_value)

        for domain_match in _DOMAIN_RE.findall(text_value):
            normalized_domain = _normalize_domain(domain_match)
            if normalized_domain:
                indicators["domain"].add(normalized_domain)

        result: Dict[str, List[str]] = {}
        for ioc_type, values in indicators.items():
            ordered = sorted(values)
            if self.max_indicators_per_type > 0:
                ordered = ordered[: self.max_indicators_per_type]
            result[ioc_type] = ordered
        return result

    def _query_otx(self, ioc: str, ioc_type: str) -> Dict[str, Any] | None:
        if not self.otx_enabled:
            return None

        endpoint = ""
        if ioc_type == "ip":
            endpoint = f"/api/v1/indicators/IPv4/{ioc}/general"
        elif ioc_type == "hash":
            endpoint = f"/api/v1/indicators/file/{ioc}/general"
        elif ioc_type == "domain":
            endpoint = f"/api/v1/indicators/domain/{ioc}/general"
        elif ioc_type == "url":
            endpoint = f"/api/v1/indicators/url/{quote(ioc, safe='')}/general"
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
            if not isinstance(data, dict):
                return None

            pulse_info = data.get("pulse_info") if isinstance(data.get("pulse_info"), dict) else {}
            pulse_count = _to_int(pulse_info.get("count", 0), 0)
            reputation = _to_int(data.get("reputation", 0), 0)
            malware_count = _to_int((data.get("malware") or {}).get("count", 0), 0)

            score = max(0, min(100, (pulse_count * 10) + max(0, reputation) + (malware_count * 8)))
            return {
                "source": "alienvault_otx",
                "score": score,
                "verdict": _verdict_from_score(score),
                "details": {
                    "pulse_count": pulse_count,
                    "reputation": reputation,
                    "malware_count": malware_count,
                },
            }
        except (RequestException, ValueError):
            return None

    def _query_abuse_ch(self, ioc: str, ioc_type: str) -> Dict[str, Any] | None:
        if not self.abuse_enabled:
            return None

        if ioc_type == "hash":
            payload = {"query": "search_hash", "hash": ioc}
        elif ioc_type in {"ip", "domain", "url"}:
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

            status = str(data.get("query_status") or "").strip().lower()
            if status in {"no_result", "unknown_query", "bad_query"}:
                return None

            rows = data.get("data") if isinstance(data.get("data"), list) else []
            if not rows:
                return None

            confidence_scores: List[int] = []
            malware_families: Set[str] = set()
            for row in rows:
                if not isinstance(row, dict):
                    continue
                confidence_scores.append(_to_int(row.get("confidence_level", 0), 0))
                family = str(row.get("malware") or row.get("malware_printable") or "").strip()
                if family:
                    malware_families.add(family)

            max_confidence = max(confidence_scores) if confidence_scores else 0
            score = max(0, min(100, max_confidence + min(len(rows) * 2, 10)))
            return {
                "source": "abuse_ch_threatfox",
                "score": score,
                "verdict": _verdict_from_score(score),
                "details": {
                    "matches": len(rows),
                    "families": sorted(malware_families),
                },
            }
        except (RequestException, ValueError):
            return None

    def _enrich_indicator(self, ioc: str, ioc_type: str) -> List[Dict[str, Any]]:
        cache_key = (ioc_type, ioc)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        findings: List[Dict[str, Any]] = []

        otx = self._query_otx(ioc, ioc_type)
        if otx:
            findings.append(otx)

        abuse = self._query_abuse_ch(ioc, ioc_type)
        if abuse:
            findings.append(abuse)

        if findings:
            scores = [int(item.get("score") or 0) for item in findings]
            max_score = max(scores)
            avg_score = int(round(sum(scores) / max(1, len(scores))))
            weighted_sum = 0.0
            weight_total = 0.0
            for item in findings:
                source = str(item.get("source") or "").strip()
                score = int(item.get("score") or 0)
                weight = float(self.source_weights.get(source, 1.0))
                weighted_sum += score * weight
                weight_total += weight
            weighted_avg = int(round(weighted_sum / weight_total)) if weight_total > 0 else avg_score
            corroboration_bonus = min(10, max(0, (len(findings) - 1) * 4))
            combined_score = int(
                round((max_score * 0.45) + (weighted_avg * 0.45) + (corroboration_bonus * 0.10))
            )
            findings.append(
                {
                    "source": "normalized_combined",
                    "score": max(0, min(100, combined_score)),
                    "verdict": _verdict_from_score(combined_score),
                    "details": {
                        "sources": [item.get("source") for item in findings],
                        "max_score": max_score,
                        "avg_score": avg_score,
                        "weighted_avg": weighted_avg,
                        "source_weights": {
                            source: self.source_weights.get(source, 1.0)
                            for source in [item.get("source") for item in findings]
                            if source
                        },
                        "corroboration_bonus": corroboration_bonus,
                    },
                }
            )

        self._cache[cache_key] = findings
        return findings

    def enrich_alert(self, alert_id: str, alert: Any) -> None:
        if not self.enabled:
            return

        iocs = self.extract(alert)
        db = connect()
        try:
            observed_at = utc_now_naive()
            for ioc_type, values in iocs.items():
                for ioc in values:
                    findings = self._enrich_indicator(ioc, ioc_type)
                    for finding in findings:
                        source = str(finding.get("source") or "").strip()
                        if not source:
                            continue
                        existing = db.execute(
                            text(
                                """
                                SELECT id, score, verdict, details
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
                        score = int(finding.get("score") or 0)
                        verdict = str(finding.get("verdict") or "unknown")
                        details = _safe_json(finding.get("details") or {})
                        effective_score = score
                        effective_verdict = verdict
                        if existing:
                            existing_id = existing[0]
                            existing_score = _to_int(existing[1], 0)
                            existing_verdict = str(existing[2] or "unknown")
                            existing_details = str(existing[3] or "")
                            merged_score = max(existing_score, score)
                            merged_verdict = _preferred_verdict(existing_verdict, verdict)
                            effective_score = merged_score
                            effective_verdict = merged_verdict
                            if (
                                merged_score != existing_score
                                or merged_verdict != existing_verdict
                                or (details and details != existing_details)
                            ):
                                db.execute(
                                    text(
                                        """
                                        UPDATE ioc_enrichments
                                        SET score=:score, verdict=:verdict, details=:details
                                        WHERE id=:id
                                        """
                                    ),
                                    {
                                        "id": existing_id,
                                        "score": merged_score,
                                        "verdict": merged_verdict,
                                        "details": details,
                                    },
                                )
                        else:
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
                                    "score": score,
                                    "verdict": verdict,
                                    "details": details,
                                },
                            )
                        try:
                            db.execute(
                                text(
                                    """
                                    INSERT INTO ioc_enrichment_records
                                    (alert_id, ioc, ioc_type, source, score, confidence, verdict, evidence_json,
                                     observed_at, org_id, created_by, created_at, updated_at)
                                    VALUES
                                    (:alert_id, :ioc, :ioc_type, :source, :score, :confidence, :verdict, :evidence_json,
                                     :observed_at, :org_id, :created_by, :created_at, :updated_at)
                                    ON CONFLICT (alert_id, ioc, ioc_type, source)
                                    DO UPDATE SET
                                        score=EXCLUDED.score,
                                        confidence=EXCLUDED.confidence,
                                        verdict=EXCLUDED.verdict,
                                        evidence_json=EXCLUDED.evidence_json,
                                        observed_at=EXCLUDED.observed_at,
                                        updated_at=EXCLUDED.updated_at
                                    """
                                ),
                                {
                                    "alert_id": alert_id,
                                    "ioc": ioc,
                                    "ioc_type": ioc_type,
                                    "source": source,
                                    "score": int(effective_score),
                                    "confidence": int(effective_score),
                                    "verdict": effective_verdict,
                                    "evidence_json": details,
                                    "observed_at": observed_at,
                                    "org_id": None,
                                    "created_by": "system",
                                    "created_at": observed_at,
                                    "updated_at": observed_at,
                                },
                            )
                        except Exception:
                            # Keep enrichment resilient even if v1.1 mirror table is unavailable.
                            pass
            db.commit()
        finally:
            db.close()

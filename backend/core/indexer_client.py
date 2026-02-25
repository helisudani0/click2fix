import os
import warnings
from typing import Any, Dict, List

import json
import requests
import urllib3
from fastapi import HTTPException
from requests import RequestException
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

from core.settings import SETTINGS


class IndexerClient:
    def __init__(self):
        cfg = SETTINGS.get("indexer", {}) if isinstance(SETTINGS, dict) else {}
        self.enabled = cfg.get("enabled", True)
        self.base = os.getenv("INDEXER_URL", cfg.get("url", "")).rstrip("/")
        self.user = os.getenv("INDEXER_USER", cfg.get("user", ""))
        self.password = os.getenv("INDEXER_PASSWORD", cfg.get("password", ""))
        self.verify = cfg.get("verify_ssl", True)
        self.timeout = cfg.get("timeout", 10)
        self.short_timeout = min(self.timeout, 3)
        session_cfg = cfg.get("session", {}) if isinstance(cfg.get("session", {}), dict) else {}
        self.pool_connections = max(
            1,
            int(
                os.getenv(
                    "INDEXER_SESSION_POOL_CONNECTIONS",
                    session_cfg.get("pool_connections", 20),
                )
            ),
        )
        self.pool_maxsize = max(
            1,
            int(
                os.getenv(
                    "INDEXER_SESSION_POOL_MAXSIZE",
                    session_cfg.get("pool_maxsize", 100),
                )
            ),
        )
        if not self.verify:
            urllib3.disable_warnings(InsecureRequestWarning)
            warnings.simplefilter("ignore", InsecureRequestWarning)
        self.session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=self.pool_connections,
            pool_maxsize=self.pool_maxsize,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.alerts_index = cfg.get("alerts_index", "wazuh-alerts-*")
        self.vuln_index = cfg.get("vulnerability_index", "wazuh-states-vulnerabilities-*")
        self.syscollector_index = cfg.get("syscollector_index", "wazuh-states-inventory-{resource}-*")
        self.sca_index = cfg.get("sca_index", "wazuh-states-sca-*")

    def _auth(self):
        if self.user:
            return (self.user, self.password)
        return None

    def search_alerts(
        self,
        limit: int = 100,
        query: str | None = None,
        agent_id: str | None = None,
        agent_only: bool = False,
        start: str | None = None,
        end: str | None = None,
    ) -> Dict[str, Any]:
        if not self.enabled or not self.base:
            return {}

        must: List[Dict[str, Any]] = []
        filters: List[Dict[str, Any]] = []
        must_not: List[Dict[str, Any]] = []

        if query:
            must.append({"query_string": {"query": query}})
        else:
            must.append({"match_all": {}})

        if agent_id:
            raw_id = str(agent_id).strip()
            padded_id = raw_id.zfill(3) if raw_id.isdigit() and len(raw_id) < 3 else raw_id
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"agent.id": raw_id}},
                            {"term": {"agent.id.keyword": raw_id}},
                            {"term": {"agent.id": padded_id}},
                            {"term": {"agent.id.keyword": padded_id}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        if agent_only:
            filters.append({"exists": {"field": "agent.id"}})
            must_not.append({"term": {"agent.id": "000"}})

        if start or end:
            range_filter: Dict[str, Any] = {}
            if start:
                start_val = str(start).strip()
                if start_val:
                    range_filter["gte"] = start_val
            if end:
                end_val = str(end).strip()
                if end_val:
                    range_filter["lte"] = end_val
            if range_filter:
                filters.append({"range": {"@timestamp": range_filter}})

        payload: Dict[str, Any] = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": must,
                    "filter": filters,
                    "must_not": must_not,
                }
            },
        }

        url = f"{self.base}/{self.alerts_index}/_search"
        try:
            r = self.session.post(
                url,
                json=payload,
                auth=self._auth(),
                verify=self.verify,
                timeout=self.short_timeout,
            )
            r.raise_for_status()
            return r.json()
        except RequestException as exc:
            raise HTTPException(
                status_code=503,
                detail="Wazuh indexer unavailable",
            ) from exc

    def _split_indices(self, value: str) -> List[str]:
        if not value:
            return []
        parts = [p.strip() for p in value.split(",")]
        return [p for p in parts if p]

    def _post_search(self, index: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base}/{index}/_search"
        try:
            r = self.session.post(
                url,
                json=payload,
                auth=self._auth(),
                verify=self.verify,
                timeout=self.short_timeout,
                params={
                    "ignore_unavailable": "true",
                    "allow_no_indices": "true",
                    "expand_wildcards": "all",
                },
            )
            if r.status_code >= 400:
                self._raise_search_http_error(r, index)
            return r.json()
        except RequestException as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    def _raise_search_http_error(self, response, index: str) -> None:
        detail = response.text or f"HTTP {response.status_code}"
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                err = parsed.get("error")
                if isinstance(err, dict):
                    root = err.get("root_cause") or []
                    if isinstance(root, list) and root:
                        reason = root[0].get("reason") or root[0].get("type")
                        if reason:
                            detail = str(reason)
                    else:
                        detail = json.dumps(err)
                elif err:
                    detail = str(err)
        except Exception:
            pass
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Indexer search failed on '{index}': {detail}",
        )

    def _scroll_search(self, index: str, payload: Dict[str, Any], max_hits: int, page_size: int = 1000) -> Dict[str, Any]:
        if max_hits <= 0:
            return {"hits": {"hits": [], "total": {"value": 0, "relation": "eq"}}}

        first_payload = dict(payload)
        first_payload["size"] = min(page_size, max_hits)
        search_url = f"{self.base}/{index}/_search"
        scroll_id = None
        all_hits: List[Dict[str, Any]] = []
        params = {
            "ignore_unavailable": "true",
            "allow_no_indices": "true",
            "expand_wildcards": "all",
            "scroll": "2m",
        }

        try:
            first = self.session.post(
                search_url,
                json=first_payload,
                auth=self._auth(),
                verify=self.verify,
                timeout=self.short_timeout,
                params=params,
            )
            if first.status_code >= 400:
                self._raise_search_http_error(first, index)
            payload_json = first.json()
            scroll_id = payload_json.get("_scroll_id")
            hits = payload_json.get("hits", {}).get("hits", []) if isinstance(payload_json, dict) else []
            if isinstance(hits, list):
                all_hits.extend(hits[:max_hits])

            while scroll_id and hits and len(all_hits) < max_hits:
                scroll_resp = self.session.post(
                    f"{self.base}/_search/scroll",
                    json={"scroll": "2m", "scroll_id": scroll_id},
                    auth=self._auth(),
                    verify=self.verify,
                    timeout=self.short_timeout,
                )
                if scroll_resp.status_code >= 400:
                    self._raise_search_http_error(scroll_resp, index)
                scroll_json = scroll_resp.json()
                scroll_id = scroll_json.get("_scroll_id") or scroll_id
                hits = scroll_json.get("hits", {}).get("hits", []) if isinstance(scroll_json, dict) else []
                if not isinstance(hits, list) or not hits:
                    break
                remaining = max_hits - len(all_hits)
                all_hits.extend(hits[:remaining])
                if len(hits) < page_size:
                    break
        except RequestException as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        finally:
            if scroll_id:
                try:
                    self.session.delete(
                        f"{self.base}/_search/scroll",
                        json={"scroll_id": [scroll_id]},
                        auth=self._auth(),
                        verify=self.verify,
                        timeout=self.short_timeout,
                    )
                except Exception:
                    pass

        return {
            "hits": {
                "hits": all_hits,
                "total": {"value": len(all_hits), "relation": "eq"},
            }
        }

    def _agent_id_variants(self, agent_ids: List[str]) -> List[str]:
        values: set[str] = set()
        for agent_id in agent_ids:
            raw = str(agent_id or "").strip()
            if not raw:
                continue
            values.add(raw)
            if raw.isdigit() and len(raw) < 3:
                values.add(raw.zfill(3))
        return sorted(values)

    def search_vulnerabilities(self, agent_id: str, limit: int = 200) -> Dict[str, Any]:
        if not self.enabled or not self.base:
            return {}

        raw_id = str(agent_id).strip()
        padded_id = raw_id.zfill(3) if raw_id.isdigit() and len(raw_id) < 3 else raw_id
        indices = self._split_indices(self.vuln_index) or [self.vuln_index]
        base_query: Dict[str, Any] = {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {"term": {"agent.id": raw_id}},
                                {"term": {"agent.id.keyword": raw_id}},
                                {"term": {"agent.id": padded_id}},
                                {"term": {"agent.id.keyword": padded_id}},
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                ]
            }
        }
        payloads: List[Dict[str, Any]] = [
            {
                "size": limit,
                "sort": [
                    {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
                ],
                "query": base_query,
            },
            {
                "size": limit,
                "query": base_query,
            },
        ]
        last_error: Exception | None = None
        for index in indices:
            if not index:
                continue
            for payload in payloads:
                try:
                    return self._post_search(index, payload)
                except HTTPException as exc:
                    last_error = exc
                    if exc.status_code == 400:
                        continue
                    break
        if last_error:
            raise HTTPException(
                status_code=last_error.status_code if isinstance(last_error, HTTPException) else 503,
                detail=str(last_error.detail) if isinstance(last_error, HTTPException) else "Wazuh indexer unavailable",
            ) from last_error
        return {}

    def search_vulnerabilities_fleet(self, limit: int = 5000, agent_ids: List[str] | None = None) -> Dict[str, Any]:
        if not self.enabled or not self.base:
            return {}

        safe_limit = max(1, min(int(limit or 1), 100000))
        indices = self._split_indices(self.vuln_index) or [self.vuln_index]
        filters: List[Dict[str, Any]] = []
        variants = self._agent_id_variants(agent_ids or [])
        if variants:
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"terms": {"agent.id": variants}},
                            {"terms": {"agent.id.keyword": variants}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        base_query: Dict[str, Any] = {
            "bool": {
                "must": [{"match_all": {}}],
                "filter": filters,
            }
        }
        payload = {
            "sort": [
                {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
            ],
            "query": base_query,
        }

        last_error: HTTPException | None = None
        for index in indices:
            if not index:
                continue
            try:
                return self._scroll_search(index, payload, safe_limit)
            except HTTPException as exc:
                last_error = exc
                # Fallback to normal search for clusters where scroll may be restricted.
                try:
                    return self._post_search(index, {"size": safe_limit, **payload})
                except HTTPException as fallback_exc:
                    last_error = fallback_exc
                    continue
        if last_error:
            raise HTTPException(
                status_code=last_error.status_code if isinstance(last_error, HTTPException) else 503,
                detail=str(last_error.detail),
            ) from last_error
        return {}

    def extract_vulnerabilities(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = data.get("hits", {}).get("hits", []) if isinstance(data, dict) else []
        records: List[Dict[str, Any]] = []
        for doc in hits:
            if not isinstance(doc, dict):
                continue
            source = doc.get("_source") or {}
            if not isinstance(source, dict):
                continue
            row = dict(source)
            if doc.get("_id") and "_doc_id" not in row:
                row["_doc_id"] = str(doc.get("_id"))
            records.append(row)
        return records

    def search_syscollector(self, agent_id: str, resource: str | None, limit: int = 100) -> Dict[str, Any]:
        if not self.enabled or not self.base:
            return {}

        raw_id = str(agent_id).strip()
        padded_id = raw_id.zfill(3) if raw_id.isdigit() and len(raw_id) < 3 else raw_id
        base_indices = self._split_indices(self.syscollector_index) or [self.syscollector_index]
        indices: List[str] = []
        for index in base_indices:
            if resource and "{resource}" in index:
                indices.append(index.replace("{resource}", resource))
            else:
                indices.append(index)

        payload: Dict[str, Any] = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"agent.id": raw_id}},
                                    {"term": {"agent.id.keyword": raw_id}},
                                    {"term": {"agent.id": padded_id}},
                                    {"term": {"agent.id.keyword": padded_id}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            },
        }
        last_error: HTTPException | None = None
        for index in indices:
            if not index:
                continue
            try:
                return self._post_search(index, payload)
            except HTTPException as exc:
                last_error = exc
                continue
        if last_error:
            raise HTTPException(status_code=503, detail=str(last_error.detail)) from last_error
        return {}

    def extract_syscollector(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = data.get("hits", {}).get("hits", []) if isinstance(data, dict) else []
        records: List[Dict[str, Any]] = []
        for doc in hits:
            if not isinstance(doc, dict):
                continue
            source = doc.get("_source") or {}
            if not isinstance(source, dict):
                continue
            payload = source.get("data") or source.get("syscollector") or source
            if not isinstance(payload, dict):
                continue
            if "type" not in payload and source.get("type"):
                payload = dict(payload)
                payload["type"] = source.get("type")
            if "scan" in source and "scan" not in payload:
                payload = dict(payload)
                payload["scan"] = source.get("scan")
            records.append(payload)
        return records

    def filter_syscollector(self, items: List[Dict[str, Any]], resource: str) -> List[Dict[str, Any]]:
        if not resource:
            return items
        filtered: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type") or item.get("data", {}).get("type")
            if item_type == resource:
                filtered.append(item)
                continue
            if resource == "hardware":
                if any(key in item for key in ("cpu", "ram", "board", "memory", "serial", "host")):
                    filtered.append(item)
                    continue
                host = item.get("host", {})
                if isinstance(host, dict) and any(
                    key in host for key in ("cpu", "memory", "serial_number", "hostname")
                ):
                    filtered.append(item)
            elif resource == "os":
                if any(key in item for key in ("os", "os_name", "platform", "kernel", "version")):
                    filtered.append(item)
                    continue
                host = item.get("host", {})
                if isinstance(host, dict) and isinstance(host.get("os"), dict):
                    filtered.append(item)
            elif resource == "packages":
                if any(key in item for key in ("name", "vendor", "architecture", "install_time", "format", "package")):
                    filtered.append(item)
                    continue
                if isinstance(item.get("package"), dict):
                    filtered.append(item)
        return filtered

    def search_alert_histogram(self, agent_id: str, hours: int = 24, interval_minutes: int = 30):
        if not self.enabled or not self.base:
            return {}

        raw_id = str(agent_id).strip()
        padded_id = raw_id.zfill(3) if raw_id.isdigit() and len(raw_id) < 3 else raw_id
        payload = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"agent.id": raw_id}},
                                    {"term": {"agent.id.keyword": raw_id}},
                                    {"term": {"agent.id": padded_id}},
                                    {"term": {"agent.id.keyword": padded_id}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                    ]
                }
            },
            "aggs": {
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": f"{interval_minutes}m",
                    }
                }
            },
        }
        return self._post_search(self.alerts_index, payload)

    def search_fim_events(self, agent_id: str, limit: int = 50):
        if not self.enabled or not self.base:
            return {}

        raw_id = str(agent_id).strip()
        padded_id = raw_id.zfill(3) if raw_id.isdigit() and len(raw_id) < 3 else raw_id
        payload = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"agent.id": raw_id}},
                                    {"term": {"agent.id.keyword": raw_id}},
                                    {"term": {"agent.id": padded_id}},
                                    {"term": {"agent.id.keyword": padded_id}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {"term": {"rule.groups": "syscheck"}},
                                    {"term": {"rule.groups": "syscheck_integrity_changed"}},
                                    {"term": {"rule.groups": "fim"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            },
        }
        return self._post_search(self.alerts_index, payload)

    def search_mitre(self, agent_id: str, limit: int = 20, hours: int = 24):
        if not self.enabled or not self.base:
            return {}

        raw_id = str(agent_id).strip()
        padded_id = raw_id.zfill(3) if raw_id.isdigit() and len(raw_id) < 3 else raw_id
        def build_payload(field_tactic: str, field_technique: str):
            return {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "bool": {
                                    "should": [
                                        {"term": {"agent.id": raw_id}},
                                        {"term": {"agent.id.keyword": raw_id}},
                                        {"term": {"agent.id": padded_id}},
                                        {"term": {"agent.id.keyword": padded_id}},
                                    ],
                                    "minimum_should_match": 1,
                                }
                            },
                            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                            {"exists": {"field": "rule.mitre.tactic"}},
                            {"exists": {"field": "rule.mitre.id"}},
                        ]
                    }
                },
                "aggs": {
                    "tactics": {"terms": {"field": field_tactic, "size": limit}},
                    "techniques": {"terms": {"field": field_technique, "size": limit}},
                },
            }

        fields = [
            ("rule.mitre.tactic.keyword", "rule.mitre.technique.keyword"),
            ("rule.mitre.tactic", "rule.mitre.technique"),
        ]
        last_error: HTTPException | None = None
        for tactic_field, technique_field in fields:
            try:
                data = self._post_search(self.alerts_index, build_payload(tactic_field, technique_field))
                buckets = data.get("aggregations", {}).get("tactics", {}).get("buckets", [])
                if buckets:
                    return data
            except HTTPException as exc:
                last_error = exc
                continue
        if last_error:
            raise last_error
        return {}

    def search_sca(self, agent_id: str, limit: int = 10):
        if not self.enabled or not self.base:
            return {}

        raw_id = str(agent_id).strip()
        padded_id = raw_id.zfill(3) if raw_id.isdigit() and len(raw_id) < 3 else raw_id
        indices = self._split_indices(self.sca_index) or [self.sca_index]
        payload = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"agent.id": raw_id}},
                                    {"term": {"agent.id.keyword": raw_id}},
                                    {"term": {"agent.id": padded_id}},
                                    {"term": {"agent.id.keyword": padded_id}},
                                ],
                                "minimum_should_match": 1,
                            }
                        }
                    ]
                }
            },
        }
        last_error: HTTPException | None = None
        for index in indices:
            if not index:
                continue
            try:
                return self._post_search(index, payload)
            except HTTPException as exc:
                last_error = exc
                continue
        if last_error:
            raise HTTPException(status_code=503, detail=str(last_error.detail)) from last_error
        return {}

    def extract_sca(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = data.get("hits", {}).get("hits", []) if isinstance(data, dict) else []
        records: List[Dict[str, Any]] = []
        for doc in hits:
            if not isinstance(doc, dict):
                continue
            source = doc.get("_source") or {}
            if not isinstance(source, dict):
                continue
            records.append(source)
        return records

    def extract_alerts(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = data.get("hits", {}).get("hits", []) if isinstance(data, dict) else []
        alerts: List[Dict[str, Any]] = []
        for doc in hits:
            if not isinstance(doc, dict):
                continue
            source = doc.get("_source") or {}
            if not isinstance(source, dict):
                continue
            alert = dict(source)
            if doc.get("_id"):
                alert.setdefault("_id", doc.get("_id"))
            if "@timestamp" in alert and "timestamp" not in alert:
                alert["timestamp"] = alert.get("@timestamp")
            alerts.append(alert)
        return alerts

    def status(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"ok": False, "error": "Indexer disabled"}
        if not self.base:
            return {"ok": False, "error": "Indexer not configured"}

        url = f"{self.base}/_cluster/health"
        try:
            r = self.session.get(
                url,
                auth=self._auth(),
                verify=self.verify,
                timeout=self.short_timeout,
            )
            r.raise_for_status()
            data = r.json()
            return {
                "ok": True,
                "status": data.get("status"),
                "cluster": data.get("cluster_name"),
            }
        except RequestException as exc:
            return {"ok": False, "error": str(exc)}

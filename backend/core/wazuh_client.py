import os
import json
import time
import threading
import warnings
from typing import Any, Dict, Iterable, List, Optional

import requests
import urllib3
from fastapi import HTTPException
from requests import RequestException
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

from core.settings import SETTINGS


class WazuhClient:
    def __init__(self):
        cfg = SETTINGS.get("wazuh", {}) if isinstance(SETTINGS, dict) else {}
        self.base = os.getenv("WAZUH_URL", cfg.get("url", "")).rstrip("/")
        self.user = os.getenv("WAZUH_USER", cfg.get("user", ""))
        self.password = os.getenv("WAZUH_PASSWORD", cfg.get("password", ""))
        self.verify = cfg.get("verify_ssl", True)
        self.timeout = cfg.get("timeout", 10)
        self.short_timeout = min(self.timeout, 3)
        session_cfg = cfg.get("session", {}) if isinstance(cfg.get("session", {}), dict) else {}
        self.pool_connections = max(
            1,
            int(
                os.getenv(
                    "WAZUH_SESSION_POOL_CONNECTIONS",
                    session_cfg.get("pool_connections", 20),
                )
            ),
        )
        self.pool_maxsize = max(
            1,
            int(
                os.getenv(
                    "WAZUH_SESSION_POOL_MAXSIZE",
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

        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._cache_lock = threading.Lock()
        self.agents_cache_ttl_seconds = max(
            1.0,
            float(
                os.getenv(
                    "WAZUH_AGENTS_CACHE_TTL_SECONDS",
                    cfg.get("agents_cache_ttl_seconds", 5),
                )
            ),
        )
        self._agents_cache: Dict[str, Dict[str, Any]] = {}

    def _normalize_agent_id(self, agent_id: str) -> str:
        raw = str(agent_id).strip()
        if raw.isdigit() and len(raw) < 3:
            return raw.zfill(3)
        return raw

    def _agents_cache_key(self, group: str | None = None) -> str:
        value = str(group or "").strip().lower()
        return f"group:{value}" if value else "__all__"

    def _get_cached_agents(self, key: str) -> Any:
        now = time.time()
        with self._cache_lock:
            entry = self._agents_cache.get(key)
            if not entry:
                return None
            ts = float(entry.get("ts") or 0)
            if now - ts > self.agents_cache_ttl_seconds:
                self._agents_cache.pop(key, None)
                return None
            return entry.get("data")

    def _set_cached_agents(self, key: str, data: Any) -> None:
        with self._cache_lock:
            self._agents_cache[key] = {"ts": time.time(), "data": data}

    def _filter_agents_by_group(self, source: Any, group: str) -> List[Dict[str, Any]]:
        items = self._extract_agent_items(source)
        if not isinstance(items, list):
            return []

        def in_group(agent: Any) -> bool:
            if not isinstance(agent, dict):
                return False
            values: List[str] = []
            for key in (
                "group",
                "groups",
                "group_name",
                "group_id",
                "group_config_status",
                "group_config",
            ):
                val = agent.get(key)
                if isinstance(val, list):
                    values.extend([str(v) for v in val])
                elif isinstance(val, str):
                    values.append(val)
            return group in values

        return [agent for agent in items if in_group(agent)]

    def _auth(self):
        if self.user:
            return (self.user, self.password)
        return None

    def _authenticate(self) -> Optional[str]:
        if not self.base or not self.user:
            return None

        url = f"{self.base}/security/user/authenticate"
        try:
            r = self.session.get(
                url,
                auth=self._auth(),
                verify=self.verify,
                timeout=self.short_timeout,
            )
            if r.status_code == 401:
                return None
            r.raise_for_status()
            data = r.json()
            token = (
                data.get("data", {}).get("token")
                or data.get("data", {}).get("jwt")
                or data.get("token")
            )
            if token:
                self._token = token
                # Wazuh tokens typically expire after ~15m. Refresh early.
                self._token_expiry = time.time() + 12 * 60
            return token
        except RequestException:
            return None

    def _get_token(self, force: bool = False) -> Optional[str]:
        if force or not self._token or time.time() > self._token_expiry:
            return self._authenticate()
        return self._token

    def _headers(self) -> Dict[str, str]:
        token = self._get_token()
        headers: Dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _request(self, method: str, path: str, **kwargs) -> Any:
        if not self.base:
            raise HTTPException(status_code=500, detail="Wazuh manager not configured")

        url = f"{self.base}{path}"
        headers = kwargs.pop("headers", {})
        skip_token = kwargs.pop("skip_token", False)
        if not skip_token:
            headers.update(self._headers())

        auth = None if headers.get("Authorization") else self._auth()
        timeout = kwargs.pop("timeout", self.timeout)

        try:
            r = self.session.request(
                method,
                url,
                headers=headers,
                auth=auth,
                verify=self.verify,
                timeout=timeout,
                **kwargs,
            )
            if r.status_code == 401 and headers.get("Authorization"):
                # Refresh token once and retry
                token = self._get_token(force=True)
                headers = dict(headers)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                else:
                    headers.pop("Authorization", None)
                auth = None if headers.get("Authorization") else self._auth()
                r = self.session.request(
                    method,
                    url,
                    headers=headers,
                    auth=auth,
                    verify=self.verify,
                    timeout=timeout,
                    **kwargs,
                )

            r.raise_for_status()
            if r.text:
                return r.json()
            return {}
        except RequestException as exc:
            raise HTTPException(
                status_code=503,
                detail="Wazuh manager unavailable",
            ) from exc

    def get_agents(self, group: str | None = None, use_cache: bool = True):
        key = self._agents_cache_key(group)
        if use_cache:
            cached = self._get_cached_agents(key)
            if cached is not None:
                return cached

        if not group:
            data = self._request("GET", "/agents", timeout=self.short_timeout)
            if use_cache:
                self._set_cached_agents(key, data)
            return data

        try:
            data = self._request("GET", "/agents", params={"group": group}, timeout=self.short_timeout)
            if use_cache:
                self._set_cached_agents(key, data)
            return data
        except HTTPException:
            # Fallback: fetch all agents and filter locally.
            all_key = self._agents_cache_key(None)
            all_agents = self._get_cached_agents(all_key) if use_cache else None
            if all_agents is None:
                all_agents = self._request("GET", "/agents", timeout=self.short_timeout)
                if use_cache:
                    self._set_cached_agents(all_key, all_agents)
            filtered = self._filter_agents_by_group(all_agents, group)
            if use_cache:
                self._set_cached_agents(key, filtered)
            return filtered

    def get_alerts(self, limit: int = 100):
        return self._request("GET", "/alerts", params={"limit": limit}, timeout=self.short_timeout)

    def get_groups(self):
        return self._request("GET", "/groups", timeout=self.short_timeout)

    def get_agent(self, agent_id: str):
        norm = self._normalize_agent_id(agent_id)
        cached_all = self._get_cached_agents(self._agents_cache_key(None))
        if cached_all is not None:
            items = self._extract_agent_items(cached_all)
            for item in items:
                if not isinstance(item, dict):
                    continue
                candidate = self._normalize_agent_id(item.get("id") or item.get("agent_id") or "")
                if candidate == norm:
                    return {"data": {"affected_items": [item]}}
        return self._request("GET", f"/agents/{norm}", timeout=self.short_timeout)

    def get_syscollector(self, agent_id: str, resource: str, limit: int = 100):
        norm = self._normalize_agent_id(agent_id)
        return self._request(
            "GET",
            f"/syscollector/{norm}/{resource}",
            params={"limit": limit},
            timeout=self.short_timeout,
        )

    def get_agent_vulnerabilities(self, agent_id: str, limit: int = 200):
        # Wazuh API may expose vulnerability endpoints depending on modules enabled.
        norm = self._normalize_agent_id(agent_id)
        endpoints = [
            f"/vulnerability/{norm}",
            f"/vulnerability/{norm}/summary",
        ]
        for path in endpoints:
            try:
                return self._request(
                    "GET",
                    path,
                    params={"limit": limit},
                    timeout=self.short_timeout,
                )
            except HTTPException:
                continue
        return []

    def get_agent_sca(self, agent_id: str, limit: int = 10):
        # Security Configuration Assessment (SCA) summary for an agent.
        norm = self._normalize_agent_id(agent_id)
        endpoints = [
            f"/sca/{norm}",
        ]
        for path in endpoints:
            try:
                return self._request(
                    "GET",
                    path,
                    params={"limit": limit},
                    timeout=self.short_timeout,
                )
            except HTTPException:
                continue
        return []

    def get_agent_sca_checks(self, agent_id: str, policy_id: str, limit: int = 10000):
        # Full SCA checks for a specific policy on an agent.
        norm = self._normalize_agent_id(agent_id)
        policy = str(policy_id or "").strip()
        if not policy:
            return []
        last_error: HTTPException | None = None
        endpoints = [
            f"/sca/{norm}/checks/{policy}",
        ]
        for path in endpoints:
            try:
                return self._request(
                    "GET",
                    path,
                    params={"limit": limit},
                    timeout=self.short_timeout,
                )
            except HTTPException as exc:
                last_error = exc
                continue
        if last_error:
            raise last_error
        return []

    def _extract_agent_items(self, data):
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

    def get_agent_ids(self, group: str | None = None):
        data = self.get_agents(group=group)
        items = self._extract_agent_items(data)
        ids = []
        for agent in items:
            if not isinstance(agent, dict):
                continue
            agent_id = agent.get("id") or agent.get("agent_id")
            if agent_id:
                ids.append(str(agent_id))
        return ids

    def status(self):
        if not self.base:
            return {"ok": False, "error": "Wazuh manager not configured"}

        errors = []
        for attempt in ("status", "info"):
            try:
                if attempt == "status":
                    data = self._request(
                        "GET",
                        "/manager/status",
                        timeout=self.short_timeout,
                    )
                else:
                    data = self._request(
                        "GET",
                        "/manager/info",
                        timeout=self.short_timeout,
                    )
                return {"ok": True, "source": attempt, "data": data}
            except HTTPException as exc:
                errors.append(str(exc.detail))

        return {"ok": False, "error": "; ".join(errors) or "Wazuh manager unavailable"}

    def run_active_response(
        self,
        command: str,
        agents: Iterable[str],
        arguments: Optional[List[str]] = None,
        custom: bool = False,
    ):
        if not self.base:
            raise HTTPException(status_code=500, detail="Wazuh manager not configured")

        agents_list = list(agents)
        args = arguments or []

        url = f"{self.base}/active-response"
        headers = self._headers()
        auth = None if headers.get("Authorization") else self._auth()

        payload = {
            "command": command,
            "arguments": args,
            "agents": agents_list,
        }
        put_params: Dict[str, Any] = {"agents_list": ",".join(agents_list)}
        put_payload: Dict[str, Any] = {
            "command": command,
            "arguments": args,
        }
        if custom:
            payload["custom"] = True
            put_payload["custom"] = True

        def _request_active_response(current_headers, current_auth, body, put_body):
            resp = self.session.post(
                url,
                json=body,
                headers=current_headers,
                auth=current_auth,
                verify=self.verify,
                timeout=self.timeout,
            )
            if resp.status_code in {404, 405}:
                resp = self.session.put(
                    url,
                    params=put_params,
                    json=put_body,
                    headers=current_headers,
                    auth=current_auth,
                    verify=self.verify,
                    timeout=self.timeout,
                )
            return resp

        def _response_detail(resp) -> str:
            detail = resp.text or "Unknown error"
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    detail = (
                        parsed.get("detail")
                        or parsed.get("error")
                        or parsed.get("message")
                        or parsed.get("title")
                        or json.dumps(parsed)
                    )
                elif isinstance(parsed, list):
                    detail = json.dumps(parsed)
            except Exception:
                pass
            return str(detail)

        try:
            r = _request_active_response(headers, auth, payload, put_payload)

            if r.status_code == 401 and headers.get("Authorization"):
                token = self._get_token(force=True)
                headers = dict(headers)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                else:
                    headers.pop("Authorization", None)
                auth = None if headers.get("Authorization") else self._auth()
                r = _request_active_response(headers, auth, payload, put_payload)

            # Compatibility fallback for Wazuh API schemas that reject "custom".
            if r.status_code == 400 and "custom" in payload:
                detail = _response_detail(r).lower()
                if "invalid field" in detail and "custom" in detail:
                    payload_no_custom = dict(payload)
                    payload_no_custom.pop("custom", None)
                    put_payload_no_custom = dict(put_payload)
                    put_payload_no_custom.pop("custom", None)
                    r = _request_active_response(headers, auth, payload_no_custom, put_payload_no_custom)

            r.raise_for_status()
            data = r.json() if r.text else {}
            failed_items = []
            if isinstance(data, dict):
                failed_items = (
                    data.get("data", {}).get("failed_items")
                    or data.get("failed_items")
                    or []
                )
            if failed_items:
                first = failed_items[0]
                if isinstance(first, dict):
                    first = (
                        first.get("error")
                        or first.get("message")
                        or first.get("detail")
                        or json.dumps(first)
                    )
                raise HTTPException(
                    status_code=400,
                    detail=f"Active response rejected: {first}",
                )
            return data
        except RequestException as exc:
            response = getattr(exc, "response", None)
            if response is not None:
                detail = _response_detail(response)
                status_code = response.status_code or 503
                raise HTTPException(
                    status_code=status_code,
                    detail=f"Active response failed ({status_code}): {detail}",
                ) from exc
            transport_detail = str(exc) or exc.__class__.__name__
            raise HTTPException(
                status_code=503,
                detail=f"Active response transport failure: {transport_detail}",
            ) from exc

    def restart_agents(self, agents: Iterable[str]):
        if not self.base:
            raise HTTPException(status_code=500, detail="Wazuh manager not configured")

        raw_ids = [self._normalize_agent_id(str(a)) for a in (agents or []) if str(a).strip()]
        agents_list: List[str] = []
        seen = set()
        for aid in raw_ids:
            if aid in {"000", "0"}:
                continue
            if aid in seen:
                continue
            seen.add(aid)
            agents_list.append(aid)

        if not agents_list:
            raise HTTPException(status_code=400, detail="No valid agents provided")

        url = f"{self.base}/agents/restart"
        headers = self._headers()
        auth = None if headers.get("Authorization") else self._auth()

        def _response_detail(resp) -> str:
            detail = resp.text or "Unknown error"
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    detail = (
                        parsed.get("detail")
                        or parsed.get("error")
                        or parsed.get("message")
                        or parsed.get("title")
                        or json.dumps(parsed)
                    )
                elif isinstance(parsed, list):
                    detail = json.dumps(parsed)
            except Exception:
                pass
            return str(detail)

        attempts = [
            {"method": "PUT", "params": {"agents_list": ",".join(agents_list)}, "json": None},
            {"method": "POST", "params": {"agents_list": ",".join(agents_list)}, "json": None},
            {"method": "PUT", "params": None, "json": {"agents_list": agents_list}},
            {"method": "POST", "params": None, "json": {"agents_list": agents_list}},
        ]

        errors: List[str] = []
        for attempt in attempts:
            method = attempt["method"]
            params = attempt["params"]
            body = attempt["json"]
            try:
                r = self.session.request(
                    method,
                    url,
                    params=params,
                    json=body,
                    headers=headers,
                    auth=auth,
                    verify=self.verify,
                    timeout=self.timeout,
                )
                if r.status_code == 401 and headers.get("Authorization"):
                    token = self._get_token(force=True)
                    retry_headers = dict(headers)
                    if token:
                        retry_headers["Authorization"] = f"Bearer {token}"
                    else:
                        retry_headers.pop("Authorization", None)
                    retry_auth = None if retry_headers.get("Authorization") else self._auth()
                    r = self.session.request(
                        method,
                        url,
                        params=params,
                        json=body,
                        headers=retry_headers,
                        auth=retry_auth,
                        verify=self.verify,
                        timeout=self.timeout,
                    )

                if 200 <= r.status_code < 300:
                    data = r.json() if r.text else {}
                    if isinstance(data, dict):
                        failed_items = (
                            data.get("data", {}).get("failed_items")
                            or data.get("failed_items")
                            or []
                        )
                        if failed_items:
                            first = failed_items[0]
                            if isinstance(first, dict):
                                first = (
                                    first.get("error")
                                    or first.get("message")
                                    or first.get("detail")
                                    or json.dumps(first)
                                )
                            errors.append(f"{method} rejected: {first}")
                            continue
                    return data

                detail = _response_detail(r)
                errors.append(f"{method} failed ({r.status_code}): {detail}")
            except RequestException as exc:
                errors.append(f"{method} transport failure: {exc}")

        raise HTTPException(
            status_code=400,
            detail="Agent restart failed via manager API: " + " | ".join(errors),
        )

from __future__ import annotations

import os
from typing import Any

import requests
from fastapi import HTTPException

from core.secrets import resolve_secret_env


class IngestGatewayClient:
    def __init__(self):
        self.base = str(os.getenv("C2F_INGEST_GATEWAY_URL", "")).strip().rstrip("/")
        self.token = resolve_secret_env("C2F_INGEST_GATEWAY_TOKEN")
        self.timeout_seconds = max(2, int(os.getenv("C2F_INGEST_GATEWAY_TIMEOUT_SECONDS", "10")))
        self.session = requests.Session()

    @property
    def enabled(self) -> bool:
        return bool(self.base and self.token)

    def _request(self, method: str, path: str, **kwargs) -> Any:
        if not self.enabled:
            raise HTTPException(status_code=503, detail="ingest-gateway integration not configured")
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("X-Ingest-Gateway-Token", self.token)
        url = f"{self.base}{path}"
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                timeout=self.timeout_seconds,
                **kwargs,
            )
            response.raise_for_status()
            if response.text:
                return response.json()
            return {}
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            detail = exc.response.text if exc.response is not None else str(exc)
            raise HTTPException(status_code=status, detail=f"ingest-gateway error: {detail}") from exc
        except requests.RequestException as exc:
            raise HTTPException(status_code=503, detail=f"ingest-gateway unavailable: {exc}") from exc

    def ingest_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/ingest", json=payload)

    def ingest_wazuh_alerts(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/ingest/wazuh", json=payload)

    def list_ingestion_queue(self, *, params: dict[str, Any]) -> dict[str, Any]:
        return self._request("GET", "/v1/ingestion/queue", params=params)

    def replay_ingestion_events(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/ingestion/replay", json=payload)

    def run_ingestion_cycle(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/ingestion/run", json=payload)

from __future__ import annotations

import time
from typing import Dict, Optional

import requests

from core.settings import SETTINGS


_DISCOVERY_CACHE: Dict[str, Dict] = {}
_DISCOVERY_TTL = 3600
_DISCOVERY_TS: Dict[str, float] = {}


def _config() -> Dict:
    return SETTINGS.get("auth", {}).get("oidc", {}) if isinstance(SETTINGS, dict) else {}


def enabled() -> bool:
    return bool(_config().get("enabled"))


def _discovery_url() -> Optional[str]:
    cfg = _config()
    return cfg.get("discovery_url") or (
        f"{cfg.get('issuer_url').rstrip('/')}/.well-known/openid-configuration"
        if cfg.get("issuer_url")
        else None
    )


def get_discovery() -> Optional[Dict]:
    url = _discovery_url()
    if not url:
        return None

    now = time.time()
    if url in _DISCOVERY_CACHE and now - _DISCOVERY_TS.get(url, 0) < _DISCOVERY_TTL:
        return _DISCOVERY_CACHE[url]

    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    _DISCOVERY_CACHE[url] = data
    _DISCOVERY_TS[url] = now
    return data


def build_auth_url(state: str, nonce: str) -> str:
    cfg = _config()
    discovery = get_discovery()
    if not discovery:
        raise RuntimeError("OIDC discovery not configured")
    auth_endpoint = discovery.get("authorization_endpoint")
    params = {
        "client_id": cfg.get("client_id"),
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": cfg.get("redirect_uri"),
        "state": state,
        "nonce": nonce,
    }
    query = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in params.items() if v)
    return f"{auth_endpoint}?{query}"


def exchange_code(code: str) -> Dict:
    cfg = _config()
    discovery = get_discovery()
    if not discovery:
        raise RuntimeError("OIDC discovery not configured")
    token_endpoint = discovery.get("token_endpoint")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.get("redirect_uri"),
        "client_id": cfg.get("client_id"),
    }
    auth = None
    if cfg.get("client_secret"):
        auth = (cfg.get("client_id"), cfg.get("client_secret"))
    resp = requests.post(token_endpoint, data=data, auth=auth, timeout=10)
    resp.raise_for_status()
    return resp.json()


def fetch_userinfo(access_token: str) -> Dict:
    discovery = get_discovery()
    if not discovery:
        raise RuntimeError("OIDC discovery not configured")
    userinfo_endpoint = discovery.get("userinfo_endpoint")
    resp = requests.get(
        userinfo_endpoint,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()

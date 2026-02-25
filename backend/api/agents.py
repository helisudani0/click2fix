from fastapi import APIRouter, Depends, HTTPException, Query
from core.wazuh_client import WazuhClient
from core.indexer_client import IndexerClient
from core.security import current_user

router = APIRouter()
client = WazuhClient()
indexer = IndexerClient()

def _extract_items(data):
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


def _normalize_agent_id(agent_id: str) -> str:
    raw = str(agent_id).strip()
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _normalize_agent_payload(agent):
    if not isinstance(agent, dict):
        return agent
    normalized = dict(agent)
    keepalive = (
        normalized.get("last_keepalive")
        or normalized.get("lastKeepAlive")
        or normalized.get("last_keep_alive")
        or normalized.get("last_seen")
        or normalized.get("lastSeen")
        or normalized.get("status_time")
    )
    if keepalive:
        normalized["last_keepalive"] = keepalive
    if normalized.get("id") and not normalized.get("agent_id"):
        normalized["agent_id"] = normalized.get("id")
    if normalized.get("agent_id") and not normalized.get("id"):
        normalized["id"] = normalized.get("agent_id")
    return normalized


def _agent_status_value(agent: dict) -> str:
    status = ""
    if isinstance(agent, dict):
        status = str(agent.get("status") or "").strip().lower()
        if not status and isinstance(agent.get("agent"), dict):
            status = str(agent.get("agent", {}).get("status") or "").strip().lower()
    return status


def _agent_platform_value(agent: dict) -> str:
    if not isinstance(agent, dict):
        return ""
    os_node = agent.get("os")
    if isinstance(os_node, dict):
        name = str(os_node.get("name") or os_node.get("platform") or os_node.get("full") or "")
    else:
        name = str(agent.get("os_name") or agent.get("os") or "")
    lowered = name.strip().lower()
    if "windows" in lowered:
        return "windows"
    if any(token in lowered for token in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "suse", "alpine")):
        return "linux"
    return "unknown"


def _compact_agent_payload(agent: dict) -> dict:
    normalized = _normalize_agent_payload(agent)
    groups = normalized.get("groups")
    if not groups:
        group_value = normalized.get("group") or normalized.get("group_name")
        if isinstance(group_value, list):
            groups = group_value
        elif isinstance(group_value, str) and group_value.strip():
            groups = [group_value]
        else:
            groups = []
    elif isinstance(groups, str):
        groups = [groups]
    elif not isinstance(groups, list):
        groups = []

    return {
        "id": normalized.get("id") or normalized.get("agent_id") or "",
        "agent_id": normalized.get("agent_id") or normalized.get("id") or "",
        "name": normalized.get("name") or normalized.get("hostname") or "",
        "hostname": normalized.get("hostname") or normalized.get("name") or "",
        "ip": normalized.get("ip") or normalized.get("registerIP") or normalized.get("ip_address") or "",
        "status": normalized.get("status") or "",
        "platform": _agent_platform_value(normalized),
        "group": normalized.get("group") or normalized.get("group_name") or "",
        "groups": [str(g) for g in groups if str(g).strip()],
        "last_keepalive": normalized.get("last_keepalive") or "",
    }


@router.get("")
def list_agents(
    group: str | None = None,
    compact: bool = Query(default=True),
    status: str | None = Query(default=None, description="Comma-separated status filter"),
    platform: str | None = Query(default=None, description="windows|linux"),
    limit: int = Query(default=2000, ge=1, le=100000),
    user=Depends(current_user),
):
    try:
        data = client.get_agents(group=group)
    except HTTPException:
        return []
    items = _extract_items(data)
    if isinstance(items, list):
        normalized_items = [_normalize_agent_payload(item) for item in items]

        if status:
            allowed = {s.strip().lower() for s in str(status).split(",") if s.strip()}
            if allowed:
                normalized_items = [item for item in normalized_items if _agent_status_value(item) in allowed]

        if platform:
            allowed_platform = {s.strip().lower() for s in str(platform).split(",") if s.strip()}
            if allowed_platform:
                normalized_items = [
                    item for item in normalized_items if _agent_platform_value(item) in allowed_platform
                ]

        if compact:
            normalized_items = [_compact_agent_payload(item) for item in normalized_items]

        return normalized_items[:limit]
    return []


@router.get("/groups")
def list_groups(user=Depends(current_user)):
    try:
        data = client.get_groups()
    except HTTPException:
        data = []

    if isinstance(data, dict):
        groups = (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
        if isinstance(groups, list):
            return groups
        return []

    if isinstance(data, list):
        return data

    return []


@router.get("/{agent_id}")
def get_agent(agent_id: str, user=Depends(current_user)):
    norm = _normalize_agent_id(agent_id)
    try:
        data = client.get_agent(norm)
    except HTTPException:
        data = {}

    items = _extract_items(data)
    if isinstance(items, list) and items:
        return _normalize_agent_payload(items[0])
    if isinstance(data, dict):
        if data.get("id") or data.get("agent_id"):
            return _normalize_agent_payload(data)
    try:
        agents = _extract_items(client.get_agents())
    except HTTPException:
        agents = []

    for item in agents:
        if not isinstance(item, dict):
            continue
        candidate = item.get("id") or item.get("agent_id")
        if candidate and _normalize_agent_id(candidate) == norm:
            return _normalize_agent_payload(item)

    if isinstance(data, dict):
        return _normalize_agent_payload(data)
    return {}


@router.get("/{agent_id}/vulnerabilities")
def get_agent_vulnerabilities(agent_id: str, limit: int = Query(default=200, ge=1, le=2000), user=Depends(current_user)):
    def _looks_like_vuln(rows):
        if not isinstance(rows, list):
            return False
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("cve") or row.get("vulnerability") or row.get("package"):
                return True
        return False

    items = []
    source = "api"
    error = None

    if indexer.enabled:
        try:
            data = indexer.search_vulnerabilities(agent_id=agent_id, limit=limit)
            items = indexer.extract_vulnerabilities(data)
            source = "indexer"
        except HTTPException as exc:
            error = str(exc.detail) if getattr(exc, "detail", None) else "Wazuh indexer unavailable"
            items = []

    if not items:
        try:
            data = client.get_agent_vulnerabilities(agent_id, limit=limit)
            items = _extract_items(data)
            if not _looks_like_vuln(items) and indexer.enabled:
                try:
                    data = indexer.search_vulnerabilities(agent_id=agent_id, limit=limit)
                    items = indexer.extract_vulnerabilities(data)
                    source = "indexer"
                    error = None
                except HTTPException:
                    pass
        except HTTPException:
            items = []

    if not isinstance(items, list):
        items = []
    return {"items": items, "total": len(items), "source": source, "error": error}


@router.get("/{agent_id}/inventory")
def get_agent_inventory(agent_id: str, limit: int = Query(default=100, ge=1, le=1000), user=Depends(current_user)):
    inventory = {}
    sources = {}
    for resource in ("hardware", "os", "packages"):
        try:
            data = client.get_syscollector(agent_id, resource, limit=limit)
            inventory[resource] = _extract_items(data)
            sources[resource] = "api"
        except HTTPException:
            inventory[resource] = []
            sources[resource] = "api"

        if not inventory[resource] and indexer.enabled:
            try:
                data = indexer.search_syscollector(agent_id=agent_id, resource=resource, limit=limit)
                items = indexer.extract_syscollector(data)
                inventory[resource] = indexer.filter_syscollector(items, resource)
                sources[resource] = "indexer"
            except HTTPException:
                pass

    inventory["source"] = sources
    return inventory


@router.get("/{agent_id}/events")
def get_agent_events(agent_id: str, hours: int = Query(default=24, ge=1, le=168), user=Depends(current_user)):
    try:
        data = indexer.search_alert_histogram(agent_id=agent_id, hours=hours)
    except HTTPException:
        return {"items": []}

    buckets = data.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    items = [{"ts": b.get("key_as_string"), "count": b.get("doc_count", 0)} for b in buckets]
    return {"items": items}


@router.get("/{agent_id}/fim")
def get_agent_fim(agent_id: str, limit: int = Query(default=50, ge=1, le=200), user=Depends(current_user)):
    try:
        data = indexer.search_fim_events(agent_id=agent_id, limit=limit)
        items = indexer.extract_alerts(data)
    except HTTPException:
        items = []

    return {"items": items}


@router.get("/{agent_id}/mitre")
def get_agent_mitre(agent_id: str, hours: int = Query(default=24, ge=1, le=168), user=Depends(current_user)):
    try:
        data = indexer.search_mitre(agent_id=agent_id, hours=hours)
    except HTTPException:
        return {"tactics": [], "techniques": []}

    aggs = data.get("aggregations", {})
    tactics = aggs.get("tactics", {}).get("buckets", [])
    techniques = aggs.get("techniques", {}).get("buckets", [])
    return {"tactics": tactics, "techniques": techniques}


@router.get("/{agent_id}/sca")
def get_agent_sca(agent_id: str, limit: int = Query(default=10, ge=1, le=100), user=Depends(current_user)):
    items = []
    source = "indexer"
    error = None

    if indexer.enabled:
        try:
            data = indexer.search_sca(agent_id=agent_id, limit=limit)
            items = indexer.extract_sca(data)
        except HTTPException as exc:
            error = str(exc.detail) if getattr(exc, "detail", None) else "Wazuh indexer unavailable"
            items = []

    if not items:
        try:
            data = client.get_agent_sca(agent_id, limit=limit)
            items = _extract_items(data)
            source = "api"
            error = None
        except HTTPException:
            if error is None:
                error = "Wazuh manager unavailable"
            items = []

    return {"items": items, "source": source, "error": error}

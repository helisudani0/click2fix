from typing import Optional, Dict

from ldap3 import Connection, Server

from core.settings import SETTINGS


def authenticate(username: str, password: str) -> Optional[Dict]:
    cfg = SETTINGS.get("auth", {}).get("ldap", {}) if isinstance(SETTINGS, dict) else {}
    if not cfg.get("enabled"):
        return None

    server_uri = cfg.get("server")
    if not server_uri:
        return None

    server = Server(server_uri, use_ssl=bool(cfg.get("use_ssl", False)))

    bind_dn = cfg.get("bind_dn")
    bind_password = cfg.get("bind_password")
    base_dn = cfg.get("base_dn")
    user_filter = cfg.get("user_filter", "(uid={username})")

    try:
        if bind_dn and bind_password and base_dn:
            conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
            search_filter = user_filter.format(username=username)
            conn.search(base_dn, search_filter, attributes=["dn", "cn", "uid", "sAMAccountName", "mail"])
            if not conn.entries:
                conn.unbind()
                return None
            user_dn = conn.entries[0].entry_dn
            conn.unbind()
        else:
            user_dn = f"{username}"

        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        user_conn.unbind()
        return {"username": username, "dn": user_dn}
    except Exception:
        return None

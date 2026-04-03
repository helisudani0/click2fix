import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useCallback, useEffect, useMemo, useState } from "react";
import api, { clearLegacyToken, decodeLegacyTokenPayload, getLegacyToken } from "../api/client";
import { alertSocket } from "../api/socket";
import { getExecutionHealth } from "../api/wazuh";
import { APP_TIMEZONE_LABEL } from "../utils/time";
import { resolveDisplayVersion, UI_APP_VERSION } from "../utils/appVersion";

const OPS_PANEL_COMPACT_STORAGE_KEY = "c2f-ops-panel-compact-v8";
const PRIORITY_QUEUE_STORAGE_KEY = "c2f-priority-queue-v8";
const SIDEBAR_COLLAPSED_STORAGE_KEY = "c2f-sidebar-collapsed-v1";

const ROUTE_LABELS = {
  "/": "Dashboard",
  "/alerts": "Alerts",
  "/sca-fleet": "SCA Fleet",
  "/incidents": "Incidents",
  "/vulnerabilities": "Vulnerabilities",
  "/analytics": "Analytics",
  "/agents": "Agents",
  "/actions": "Actions",
  "/global-shell": "Global Shell",
  "/playbooks": "Playbooks",
  "/approvals": "Approvals",
  "/executions": "Executions",
  "/scheduler": "Scheduler",
  "/cases": "Cases",
  "/changes": "Changes",
  "/governance": "Governance",
  "/audit": "Audit Log",
  "/orgs": "Org Admin",
};

const NAV_SECTIONS = [
  {
    title: "Detection",
    links: [
      { to: "/", label: "Overview", end: true },
      { to: "/alerts", label: "Alerts" },
      { to: "/sca-fleet", label: "SCA Fleet" },
      { to: "/incidents", label: "Incidents" },
      { to: "/agents", label: "Agents" },
      { to: "/vulnerabilities", label: "Vulnerabilities" },
      { to: "/analytics", label: "Analytics" },
    ],
  },
  {
    title: "Response",
    links: [
      { to: "/actions", label: "Actions" },
      { to: "/global-shell", label: "Global Shell" },
      { to: "/playbooks", label: "Playbooks" },
      { to: "/scheduler", label: "Scheduler" },
      { to: "/executions", label: "Executions" },
      { to: "/approvals", label: "Approvals" },
    ],
  },
  {
    title: "Governance",
    links: [
      { to: "/governance", label: "Automation Context" },
      { to: "/cases", label: "Cases" },
      { to: "/changes", label: "Changes" },
      { to: "/audit", label: "Audit Log" },
      { to: "/orgs", label: "Org Admin" },
    ],
  },
];

const PRIORITY_DEFAULT_ENABLED_ROUTES = new Set([
  "/alerts",
  "/vulnerabilities",
  "/actions",
  "/global-shell",
  "/playbooks",
  "/executions",
]);

const PRIORITY_LINKS = NAV_SECTIONS.flatMap((section) => section.links)
  .reduce((acc, link) => {
    if (!acc.some((item) => item.to === link.to)) {
      acc.push({ to: link.to, label: link.label });
    }
    return acc;
  }, []);

const OPS_MODULES = [
  {
    id: "organizations",
    label: "Organizations",
    links: [
      { to: "/orgs", label: "Org Admin" },
      { to: "/cases", label: "Case Desk" },
    ],
  },
  {
    id: "connectors",
    label: "Connectors",
    links: [
      { to: "/actions", label: "Action Connectors" },
      { to: "/agents", label: "Agent Inventory" },
      { to: "/scheduler", label: "Scheduler" },
    ],
  },
  {
    id: "governance",
    label: "Governance",
    links: [
      { to: "/governance", label: "Automation Context" },
      { to: "/approvals", label: "Approvals" },
      { to: "/changes", label: "Changes" },
      { to: "/audit", label: "Audit Log" },
    ],
  },
];

const shortLabel = (value) =>
  String(value || "")
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part[0])
    .join("")
    .slice(0, 3)
    .toUpperCase() || "NAV";

const DEFAULT_PRIORITY_QUEUE = PRIORITY_LINKS.map((item) => ({
  to: item.to,
  enabled: PRIORITY_DEFAULT_ENABLED_ROUTES.has(item.to),
}));

const normalizePriorityQueue = (value) => {
  const fallback = DEFAULT_PRIORITY_QUEUE;
  if (!value) return fallback;
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return fallback;
    const byRoute = new Map(PRIORITY_LINKS.map((item) => [item.to, item]));
    const normalized = [];
    parsed.forEach((entry) => {
      const route = String(entry?.to || "").trim();
      if (!byRoute.has(route) || normalized.some((item) => item.to === route)) return;
      normalized.push({
        to: route,
        enabled: entry?.enabled !== false,
      });
    });
    PRIORITY_LINKS.forEach((item) => {
      if (!normalized.some((entry) => entry.to === item.to)) {
        normalized.push({
          to: item.to,
          enabled: PRIORITY_DEFAULT_ENABLED_ROUTES.has(item.to),
        });
      }
    });
    return normalized;
  } catch {
    return fallback;
  }
};

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [search, setSearch] = useState("");
  const [appVersion, setAppVersion] = useState(UI_APP_VERSION);
  const [priorityQueueItems, setPriorityQueueItems] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_PRIORITY_QUEUE;
    return normalizePriorityQueue(window.localStorage.getItem(PRIORITY_QUEUE_STORAGE_KEY));
  });
  const [opsCompact, setOpsCompact] = useState(() => {
    if (typeof window === "undefined") return false;
    const persisted = window.localStorage.getItem(OPS_PANEL_COMPACT_STORAGE_KEY);
    return persisted === null ? false : persisted === "1";
  });
  const [priorityConfigOpen, setPriorityConfigOpen] = useState(false);
  const [priorityPanelOpen, setPriorityPanelOpen] = useState(false);
  const [opsPanelOpen, setOpsPanelOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(SIDEBAR_COLLAPSED_STORAGE_KEY) === "1";
  });
  const [backendHealth, setBackendHealth] = useState({
    activeExecutions: 0,
    queuedExecutions: 0,
    socketLatencyMs: null,
    socketLive: false,
  });

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(PRIORITY_QUEUE_STORAGE_KEY, JSON.stringify(priorityQueueItems));
  }, [priorityQueueItems]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(OPS_PANEL_COMPACT_STORAGE_KEY, opsCompact ? "1" : "0");
  }, [opsCompact]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(SIDEBAR_COLLAPSED_STORAGE_KEY, sidebarCollapsed ? "1" : "0");
  }, [sidebarCollapsed]);

  useEffect(() => {
    let active = true;
    const tokenPayload = decodeLegacyTokenPayload();
    if (tokenPayload?.sub && active) {
      setUser({
        username: String(tokenPayload.sub || "user"),
        role: String(tokenPayload.role || "analyst"),
      });
    }
    api
      .get("/auth/me")
      .then((res) => {
        if (!active) return;
        const data = res?.data || {};
        setUser({
          username: String(data.username || "user"),
          role: String(data.role || "analyst"),
        });
      })
      .catch((err) => {
        const statusCode = err?.response?.status;
        if ((statusCode === 404 || statusCode === 405) && getLegacyToken()) return;
        if (active) setUser(null);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    api
      .get("/system/version")
      .then((res) => {
        if (!active) return;
        setAppVersion(resolveDisplayVersion(res?.data?.version));
      })
      .catch(() => {
        if (!active) return;
        setAppVersion(UI_APP_VERSION);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    let timerId = null;

    const loadHealth = async () => {
      try {
        const res = await getExecutionHealth();
        if (!active) return;
        setBackendHealth((prev) => ({
          ...prev,
          activeExecutions: Number(res?.data?.active_executions || 0),
          queuedExecutions: Number(res?.data?.queued_executions || 0),
        }));
      } catch {
        if (!active) return;
        setBackendHealth((prev) => ({
          ...prev,
          activeExecutions: 0,
          queuedExecutions: 0,
        }));
      }
    };

    void loadHealth();
    timerId = window.setInterval(() => {
      void loadHealth();
    }, 10000);

    return () => {
      active = false;
      if (timerId) window.clearInterval(timerId);
    };
  }, []);

  useEffect(() => {
    let ws = null;
    let reconnectTimer = null;
    let pingTimer = null;
    let closed = false;
    let lastPingAt = 0;

    const clearTimers = () => {
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      if (pingTimer) window.clearInterval(pingTimer);
      reconnectTimer = null;
      pingTimer = null;
    };

    const connectSocket = () => {
      clearTimers();
      ws = alertSocket();

      ws.onopen = () => {
        setBackendHealth((prev) => ({ ...prev, socketLive: true }));
        const sendPing = () => {
          if (!ws || ws.readyState !== WebSocket.OPEN) return;
          lastPingAt = Date.now();
          ws.send("ping");
        };
        sendPing();
        pingTimer = window.setInterval(sendPing, 12000);
      };

      ws.onmessage = (event) => {
        let payload = null;
        try {
          payload = JSON.parse(event.data);
        } catch {
          return;
        }
        if (!payload || typeof payload !== "object") return;
        if (payload.event === "heartbeat") {
          setBackendHealth((prev) => ({
            ...prev,
            socketLive: true,
            socketLatencyMs: payload.kind === "pong" && lastPingAt ? Date.now() - lastPingAt : prev.socketLatencyMs,
          }));
        }
      };

      ws.onclose = () => {
        if (closed) return;
        setBackendHealth((prev) => ({ ...prev, socketLive: false }));
        clearTimers();
        reconnectTimer = window.setTimeout(connectSocket, 4000);
      };

      ws.onerror = () => {
        setBackendHealth((prev) => ({ ...prev, socketLive: false }));
      };
    };

    connectSocket();

    return () => {
      closed = true;
      clearTimers();
      if (ws && ws.readyState <= WebSocket.OPEN) {
        ws.close(1000, "layout unmounted");
      }
    };
  }, []);

  const logout = async (requireConfirm = false) => {
    if (requireConfirm && typeof window !== "undefined") {
      const confirmed = window.confirm("Sign out of this session?");
      if (!confirmed) return;
    }
    try {
      await api.post("/auth/logout");
    } catch {
      // Continue with local logout even if API logout fails.
    }
    clearLegacyToken();
    setUser(null);
    navigate("/login", { replace: true });
  };

  useEffect(() => {
    if (location.pathname === "/alerts") {
      const params = new URLSearchParams(location.search);
      setSearch(params.get("query") || "");
    }
  }, [location.pathname, location.search]);

  useEffect(() => {
    setPriorityConfigOpen(false);
    setPriorityPanelOpen(false);
    setOpsPanelOpen(false);
  }, [location.pathname]);

  const breadcrumbs = useMemo(() => {
    const path = location.pathname || "/";
    const currentLabel = ROUTE_LABELS[path] || "Workspace";
    return [{ label: "Workspace", href: "/" }, { label: currentLabel, href: path }];
  }, [location.pathname]);

  const currentPageLabel = useMemo(() => ROUTE_LABELS[location.pathname || "/"] || "Workspace", [location.pathname]);

  useEffect(() => {
    if (typeof document === "undefined") return;
    document.title = `Click2Fix | ${currentPageLabel}`;
  }, [currentPageLabel]);

  const submitSearch = (event) => {
    event.preventDefault();
    const term = search.trim();
    if (!term) {
      navigate("/alerts", { replace: false });
      return;
    }
    navigate(`/alerts?query=${encodeURIComponent(term)}`);
  };

  const openOpsConsole = () => {
    if (typeof window === "undefined") return;
    let opsOrigin = window.location.origin;
    try {
      const apiBase = String(api?.defaults?.baseURL || "/api").trim();
      opsOrigin = new URL(apiBase, window.location.origin).origin;
    } catch {
      opsOrigin = window.location.origin;
    }
    window.open(`${opsOrigin}/ops`, "_blank", "noopener,noreferrer");
  };

  const healthTone = backendHealth.socketLive ? "success" : "pending";
  const priorityLinks = useMemo(() => {
    const byRoute = new Map(PRIORITY_LINKS.map((item) => [item.to, item]));
    return priorityQueueItems
      .filter((entry) => entry.enabled !== false)
      .map((entry) => byRoute.get(entry.to))
      .filter(Boolean);
  }, [priorityQueueItems]);

  const dockOpsModules = useMemo(
    () =>
      OPS_MODULES.map((section) => ({
        ...section,
        links: opsCompact ? section.links.slice(0, 2) : section.links,
      })),
    [opsCompact]
  );

  const updatePriorityQueueItem = useCallback((route, patch) => {
    setPriorityQueueItems((current) => current.map((item) => (item.to === route ? { ...item, ...patch } : item)));
  }, []);

  const movePriorityQueueItem = useCallback((route, direction) => {
    setPriorityQueueItems((current) => {
      const index = current.findIndex((item) => item.to === route);
      if (index < 0) return current;
      const nextIndex = index + direction;
      if (nextIndex < 0 || nextIndex >= current.length) return current;
      const next = [...current];
      const [item] = next.splice(index, 1);
      next.splice(nextIndex, 0, item);
      return next;
    });
  }, []);

  const resetPriorityQueue = useCallback(() => {
    setPriorityQueueItems(DEFAULT_PRIORITY_QUEUE);
  }, []);

  return (
    <div className={`app-layout app-shell-v5${sidebarCollapsed ? " is-collapsed" : ""}`}>
      <div className="shell-frame shell-frame-sidenav">
        <aside className="shell-sidebar" aria-label="Primary navigation">
          <div className="shell-sidebar-header">
            <div className="shell-brand">
              <div className="brand-badge brand-badge-logo" aria-hidden="true">
                <img src="/c2f-logo.svg" alt="" loading="lazy" />
              </div>
              <div className="shell-brand-copy">
                <div className="brand-title">Click2Fix</div>
                <div className="brand-subtitle">SOC Operations</div>
              </div>
            </div>
            <button
              type="button"
              className="shell-collapse-toggle"
              onClick={() => setSidebarCollapsed((prev) => !prev)}
              aria-pressed={sidebarCollapsed}
              aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              <span className="shell-collapse-icon">{sidebarCollapsed ? ">>" : "<<"}</span>
              <span className="shell-collapse-text">
                {sidebarCollapsed ? "Expand" : "Collapse"}
              </span>
            </button>
          </div>

          <div className="shell-sidebar-body">
            <div className="shell-quick-access">
              <div className="shell-nav-group-title">Priority Queue</div>
              <div className="shell-quick-grid">
                {priorityLinks.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) => `shell-quick-link${isActive ? " active" : ""}`}
                  >
                    <span className="shell-nav-icon">{shortLabel(item.label)}</span>
                    <span className="shell-quick-text">{item.label}</span>
                  </NavLink>
                ))}
              </div>
              <button
                type="button"
                className="btn secondary shell-quick-button"
                onClick={() => setPriorityPanelOpen(true)}
              >
                Customize
              </button>
            </div>

            {NAV_SECTIONS.map((section) => (
              <div key={section.title} className="shell-nav-group">
                <div className="shell-nav-group-title">{section.title}</div>
                <div className="shell-nav-group-links">
                  {section.links.map((link) => (
                    <NavLink
                      key={link.to}
                      to={link.to}
                      end={Boolean(link.end)}
                      className={({ isActive }) => `shell-nav-link${isActive ? " active" : ""}`}
                      data-label={link.label}
                    >
                      <span className="shell-nav-icon">{shortLabel(link.label)}</span>
                      <span className="shell-nav-text">{link.label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="shell-sidebar-panels">
            <div className="shell-nav-group-title">Panels</div>
            <button type="button" className="btn secondary" onClick={() => setOpsPanelOpen(true)}>
              Backend Ops
            </button>
            <button type="button" className="btn secondary" onClick={openOpsConsole}>
              Open /ops
            </button>
          </div>

          <div className="shell-sidebar-footer">
            <span className="shell-version">v{appVersion}</span>
            <span className="shell-user">{user ? `${user.username} - ${user.role}` : "user"}</span>
            <button
              type="button"
              className="btn secondary shell-logout-safe"
              onClick={() => void logout(true)}
            >
              Sign Out
            </button>
          </div>
        </aside>

        <div className="shell-main">
          <header className="shell-header">
            <div className="shell-context">
              <div className="shell-page-title">{currentPageLabel}</div>
              <div className="shell-breadcrumbs">
                {breadcrumbs.map((item, index) => (
                  <span key={`${item.href}-${item.label}`}>
                    {index > 0 ? " / " : ""}
                    {item.label}
                  </span>
                ))}
                <span> / {APP_TIMEZONE_LABEL}</span>
              </div>
            </div>

            <form className="shell-search" onSubmit={submitSearch}>
              <input
                aria-label="Search alerts, agents, actions"
                placeholder="Search alerts, agents, CVEs, hosts..."
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
              <button type="submit" className="btn secondary">Search</button>
            </form>

            <div className="shell-controls">
              <span className={`shell-health-dot ${healthTone}`} aria-hidden="true" />
              <span className="shell-chip">{backendHealth.socketLive ? "Socket live" : "Reconnecting"}</span>
              <span className="shell-chip">{backendHealth.activeExecutions} active</span>
              <span className="shell-chip">
                {backendHealth.socketLatencyMs !== null ? `${backendHealth.socketLatencyMs} ms` : "Latency --"}
              </span>
              {backendHealth.queuedExecutions > 0 ? (
                <span className="shell-chip">{backendHealth.queuedExecutions} queued</span>
              ) : null}
            </div>
          </header>

          <section className={`shell-content page-route-${(location.pathname || "/").replace(/^\//, "").replace(/\//g, "-") || "home"}`}>
            <Outlet />
          </section>
        </div>
      </div>

      {priorityPanelOpen ? (
        <div className="shell-overlay" role="dialog" aria-modal="true" aria-label="Priority queue panel">
          <button
            type="button"
            className="shell-overlay-backdrop"
            aria-label="Close priority queue"
            onClick={() => setPriorityPanelOpen(false)}
          />
          <aside className="shell-overlay-panel">
            <div className="shell-overlay-header">
              <div>
                <div className="shell-overlay-kicker">Priority Queue</div>
                <h3>Analyst Quick Access</h3>
              </div>
              <div className="page-actions">
                <button
                  type="button"
                  className="btn secondary"
                  onClick={() => setPriorityConfigOpen((prev) => !prev)}
                  aria-pressed={priorityConfigOpen}
                >
                  {priorityConfigOpen ? "Done" : "Customize"}
                </button>
                <button type="button" className="btn secondary" onClick={resetPriorityQueue}>Reset</button>
                <button type="button" className="btn secondary" onClick={() => setPriorityPanelOpen(false)}>Close</button>
              </div>
            </div>

            {priorityConfigOpen ? (
              <div className="priority-config priority-config-dock">
                <div className="priority-config-header">
                  <span className="meta-line">Enable only what you need and reorder for shift-specific triage.</span>
                </div>
                <div className="priority-config-list">
                  {priorityQueueItems.map((item, index) => {
                    const meta = PRIORITY_LINKS.find((link) => link.to === item.to);
                    if (!meta) return null;
                    return (
                      <div key={item.to} className="priority-config-row">
                        <label className="priority-config-toggle">
                          <input
                            type="checkbox"
                            checked={item.enabled !== false}
                            onChange={(event) => updatePriorityQueueItem(item.to, { enabled: event.target.checked })}
                          />
                          <span>{meta.label}</span>
                        </label>
                        <div className="priority-config-actions">
                          <button
                            type="button"
                            className="panel-collapse-btn"
                            onClick={() => movePriorityQueueItem(item.to, -1)}
                            disabled={index === 0}
                            title="Move up"
                          >
                            Up
                          </button>
                          <button
                            type="button"
                            className="panel-collapse-btn"
                            onClick={() => movePriorityQueueItem(item.to, 1)}
                            disabled={index === priorityQueueItems.length - 1}
                            title="Move down"
                          >
                            Down
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}

            <div className="workspace-shortcut-grid">
              {priorityLinks.length ? (
                priorityLinks.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) => `workspace-shortcut-card${isActive ? " active" : ""}`}
                    onClick={() => setPriorityPanelOpen(false)}
                  >
                    <span className="workspace-shortcut-kicker">{shortLabel(item.label)}</span>
                    <span className="workspace-shortcut-title">{item.label}</span>
                  </NavLink>
                ))
              ) : (
                <div className="empty-state priority-empty-state">Enable at least one quick surface.</div>
              )}
            </div>
          </aside>
        </div>
      ) : null}

      {opsPanelOpen ? (
        <div className="shell-overlay" role="dialog" aria-modal="true" aria-label="Backend ops panel">
          <button
            type="button"
            className="shell-overlay-backdrop"
            aria-label="Close backend ops"
            onClick={() => setOpsPanelOpen(false)}
          />
          <aside className="shell-overlay-panel">
            <div className="shell-overlay-header">
              <div>
                <div className="shell-overlay-kicker">Backend Ops</div>
                <h3>Platform Control</h3>
              </div>
              <div className="page-actions">
                <button
                  type="button"
                  className="btn secondary"
                  onClick={() => setOpsCompact((prev) => !prev)}
                  aria-pressed={opsCompact}
                >
                  {opsCompact ? "Expand" : "Compact"}
                </button>
                <button type="button" className="btn secondary" onClick={openOpsConsole}>Open /ops</button>
                <button type="button" className="btn secondary" onClick={() => setOpsPanelOpen(false)}>Close</button>
              </div>
            </div>

            <div className="workspace-ops-groups">
              {dockOpsModules.map((section) => (
                <div key={section.id} className="workspace-ops-group">
                  <div className="workspace-nav-group-label">{section.label}</div>
                  <div className="workspace-ops-links">
                    {section.links.map((link) => (
                      <NavLink
                        key={link.to}
                        to={link.to}
                        className={({ isActive }) => `workspace-ops-link${isActive ? " active" : ""}`}
                        onClick={() => setOpsPanelOpen(false)}
                      >
                        {link.label}
                      </NavLink>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </aside>
        </div>
      ) : null}
    </div>
  );
}

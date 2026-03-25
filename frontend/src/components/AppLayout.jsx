import { NavLink, Outlet, useNavigate, useLocation } from "react-router-dom";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import api, {
  clearLegacyToken,
  decodeLegacyTokenPayload,
  getLegacyToken
} from "../api/client";
import { alertSocket } from "../api/socket";
import { getExecutionHealth } from "../api/wazuh";
import MissionBriefing from "./MissionBriefing";
import { APP_TIMEZONE_LABEL } from "../utils/time";
import { resolveDisplayVersion, UI_APP_VERSION } from "../utils/appVersion";

const SIDEBAR_STORAGE_KEY = "c2f-sidebar-collapsed-v4";
const PRIORITY_PANEL_STORAGE_KEY = "c2f-priority-panel-collapsed-v4";
const PRIORITY_PANEL_HEIGHT_STORAGE_KEY = "c2f-priority-panel-height-v4";
const SIDEBAR_WIDTH_STORAGE_KEY = "c2f-sidebar-width-v4";
const OPS_PANEL_COMPACT_STORAGE_KEY = "c2f-ops-panel-compact-v4";
const PRIORITY_QUEUE_STORAGE_KEY = "c2f-priority-queue-v2";
const MISSION_BRIEFING_STORAGE_KEY = "c2f-mission-briefing-v1";
const DEFAULT_PRIORITY_PANEL_HEIGHT = 288;
const MIN_PRIORITY_PANEL_HEIGHT = 170;
const MAX_PRIORITY_PANEL_HEIGHT = 520;
const DEFAULT_SIDEBAR_WIDTH = 336;
const MIN_SIDEBAR_WIDTH = 260;
const MAX_SIDEBAR_WIDTH = 560;

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

const PRIORITY_LINKS = [
  { to: "/alerts", label: "Alerts" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/actions", label: "Actions" },
  { to: "/global-shell", label: "Global Shell" },
  { to: "/playbooks", label: "Playbooks" },
  { to: "/executions", label: "Execution Monitor" },
];

const NAV_SECTIONS = [
  {
    title: "Detection",
    links: [
      { to: "/", label: "Command Overview", end: true },
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
  enabled: true,
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
        normalized.push({ to: item.to, enabled: true });
      }
    });
    return normalized;
  } catch {
    return fallback;
  }
};

const clampPriorityPanelHeight = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return DEFAULT_PRIORITY_PANEL_HEIGHT;
  return Math.min(MAX_PRIORITY_PANEL_HEIGHT, Math.max(MIN_PRIORITY_PANEL_HEIGHT, Math.round(numeric)));
};

const clampSidebarWidth = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return DEFAULT_SIDEBAR_WIDTH;
  return Math.min(MAX_SIDEBAR_WIDTH, Math.max(MIN_SIDEBAR_WIDTH, Math.round(numeric)));
};

const MISSION_BRIEFING_STEPS = [
  {
    route: null,
    selector: '[data-tour-id="priority-queue"]',
    title: "Priority Queue",
    body: "This queue stays available across the console so we can filter alert noise without leaving the active workspace.",
  },
  {
    route: "/actions",
    selector: '[data-tour-id="action-catalog"]',
    title: "Action Hover",
    body: "Use the action catalog to lock onto the exact remediation ID, validate it, and launch response runs without leaving the table workflow.",
  },
  {
    route: "/global-shell",
    selector: '[data-tour-id="global-shell-drawer"]',
    title: "Global Shell Drawer",
    body: "Global Shell is the pivot point for live debugging. Failed runs can jump here with the command context already prefilled.",
  },
  {
    route: "/executions",
    selector: '[data-tour-id="execution-hud"]',
    title: "Execution HUD",
    body: "The HUD shows fractional fleet progress, lagging targets, and retry-delta actions so we can recover outliers without rerunning the whole fleet.",
  },
];

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const layoutRef = useRef(null);
  const priorityResizeRef = useRef(null);
  const sidebarResizeRef = useRef(null);
  const [user, setUser] = useState(null);
  const [search, setSearch] = useState("");
  const [appVersion, setAppVersion] = useState(UI_APP_VERSION);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === "1";
  });
  const [priorityPanelCollapsed, setPriorityPanelCollapsed] = useState(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(PRIORITY_PANEL_STORAGE_KEY) === "1";
  });
  const [priorityPanelHeight, setPriorityPanelHeight] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_PRIORITY_PANEL_HEIGHT;
    return clampPriorityPanelHeight(window.localStorage.getItem(PRIORITY_PANEL_HEIGHT_STORAGE_KEY));
  });
  const [priorityQueueItems, setPriorityQueueItems] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_PRIORITY_QUEUE;
    return normalizePriorityQueue(window.localStorage.getItem(PRIORITY_QUEUE_STORAGE_KEY));
  });
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_SIDEBAR_WIDTH;
    return clampSidebarWidth(window.localStorage.getItem(SIDEBAR_WIDTH_STORAGE_KEY));
  });
  const [opsCompact, setOpsCompact] = useState(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(OPS_PANEL_COMPACT_STORAGE_KEY) === "1";
  });
  const [openOpsSections, setOpenOpsSections] = useState(() => ({
    organizations: true,
    connectors: true,
    governance: true,
  }));
  const [backendHealth, setBackendHealth] = useState({
    activeExecutions: 0,
    queuedExecutions: 0,
    socketLatencyMs: null,
    socketLive: false,
  });
  const [missionBriefingOpen, setMissionBriefingOpen] = useState(false);
  const [priorityConfigOpen, setPriorityConfigOpen] = useState(false);
  const isGlobalShellRoute = location.pathname.startsWith("/global-shell");

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(SIDEBAR_STORAGE_KEY, sidebarCollapsed ? "1" : "0");
  }, [sidebarCollapsed]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(PRIORITY_PANEL_STORAGE_KEY, priorityPanelCollapsed ? "1" : "0");
  }, [priorityPanelCollapsed]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(PRIORITY_PANEL_HEIGHT_STORAGE_KEY, String(priorityPanelHeight));
  }, [priorityPanelHeight]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(PRIORITY_QUEUE_STORAGE_KEY, JSON.stringify(priorityQueueItems));
  }, [priorityQueueItems]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(SIDEBAR_WIDTH_STORAGE_KEY, String(sidebarWidth));
  }, [sidebarWidth]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(OPS_PANEL_COMPACT_STORAGE_KEY, opsCompact ? "1" : "0");
  }, [opsCompact]);

  useEffect(() => {
    if (priorityPanelCollapsed || sidebarCollapsed) {
      setPriorityConfigOpen(false);
    }
  }, [priorityPanelCollapsed, sidebarCollapsed]);

  const stopPriorityResize = useCallback(() => {
    if (typeof window !== "undefined" && priorityResizeRef.current) {
      window.removeEventListener("mousemove", priorityResizeRef.current.onMove);
      window.removeEventListener("mouseup", priorityResizeRef.current.onUp);
      priorityResizeRef.current = null;
    }
    if (typeof document !== "undefined") {
      document.body.style.removeProperty("cursor");
      document.body.style.removeProperty("user-select");
    }
  }, []);

  useEffect(() => () => stopPriorityResize(), [stopPriorityResize]);

  const stopSidebarResize = useCallback(() => {
    if (typeof window !== "undefined" && sidebarResizeRef.current) {
      window.removeEventListener("mousemove", sidebarResizeRef.current.onMove);
      window.removeEventListener("mouseup", sidebarResizeRef.current.onUp);
      sidebarResizeRef.current = null;
    }
    if (typeof document !== "undefined") {
      document.body.style.removeProperty("cursor");
      document.body.style.removeProperty("user-select");
    }
  }, []);

  useEffect(() => () => stopSidebarResize(), [stopSidebarResize]);

  const startPriorityResize = useCallback((event) => {
    if (sidebarCollapsed || priorityPanelCollapsed || typeof window === "undefined" || window.innerWidth <= 1024) {
      return;
    }
    event.preventDefault();
    stopPriorityResize();
    const startY = event.clientY;
    const startHeight = priorityPanelHeight;
    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - startY;
      setPriorityPanelHeight(clampPriorityPanelHeight(startHeight + delta));
    };
    const onUp = () => stopPriorityResize();
    priorityResizeRef.current = { onMove, onUp };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    if (typeof document !== "undefined") {
      document.body.style.cursor = "row-resize";
      document.body.style.userSelect = "none";
    }
  }, [priorityPanelCollapsed, priorityPanelHeight, sidebarCollapsed, stopPriorityResize]);

  const startSidebarResize = useCallback((event) => {
    if (sidebarCollapsed || typeof window === "undefined" || window.innerWidth <= 1024) {
      return;
    }
    event.preventDefault();
    stopSidebarResize();
    const startX = event.clientX;
    const startWidth = sidebarWidth;
    const onMove = (moveEvent) => {
      const delta = moveEvent.clientX - startX;
      setSidebarWidth(clampSidebarWidth(startWidth + delta));
    };
    const onUp = () => stopSidebarResize();
    sidebarResizeRef.current = { onMove, onUp };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    if (typeof document !== "undefined") {
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }
  }, [sidebarCollapsed, sidebarWidth, stopSidebarResize]);

  useEffect(() => {
    let active = true;
    const tokenPayload = decodeLegacyTokenPayload();
    if (tokenPayload?.sub && active) {
      setUser({
        username: String(tokenPayload.sub || "user"),
        role: String(tokenPayload.role || "user")
      });
    }
    api
      .get("/auth/me")
      .then((res) => {
        if (!active) return;
        const data = res?.data || {};
        setUser({
          username: String(data.username || "user"),
          role: String(data.role || "user"),
        });
      })
      .catch((err) => {
        const statusCode = err?.response?.status;
        if ((statusCode === 404 || statusCode === 405) && getLegacyToken()) {
          return;
        }
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

  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    if (window.localStorage.getItem(MISSION_BRIEFING_STORAGE_KEY) === "1") return undefined;
    const timer = window.setTimeout(() => {
      setMissionBriefingOpen(true);
    }, 900);
    return () => window.clearTimeout(timer);
  }, []);

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      // Always proceed with local logout even if API logout fails.
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

  const breadcrumbs = useMemo(() => {
    const path = location.pathname || "/";
    const currentLabel = ROUTE_LABELS[path] || "Workspace";
    return [{ label: "Workspace", href: "/" }, { label: currentLabel, href: path }];
  }, [location.pathname]);

  const currentPageLabel = useMemo(() => ROUTE_LABELS[location.pathname || "/"] || "Workspace", [location.pathname]);

  const submitSearch = (e) => {
    e.preventDefault();
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
    const opsUrl = `${opsOrigin}/ops`;
    window.open(opsUrl, "_blank", "noopener,noreferrer");
  };

  const completeMissionBriefing = () => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(MISSION_BRIEFING_STORAGE_KEY, "1");
    }
    setMissionBriefingOpen(false);
  };

  const healthTone = backendHealth.socketLive ? "success" : "pending";
  const priorityLinks = useMemo(() => {
    const byRoute = new Map(PRIORITY_LINKS.map((item) => [item.to, item]));
    return priorityQueueItems
      .filter((entry) => entry.enabled !== false)
      .map((entry) => byRoute.get(entry.to))
      .filter(Boolean);
  }, [priorityQueueItems]);

  const updatePriorityQueueItem = useCallback((route, patch) => {
    setPriorityQueueItems((current) =>
      current.map((item) => (item.to === route ? { ...item, ...patch } : item))
    );
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
    <div
      ref={layoutRef}
      className={`app-layout${sidebarCollapsed ? " sidebar-collapsed" : ""}${isGlobalShellRoute ? " route-global-shell" : ""}`}
      style={!sidebarCollapsed ? { "--sidebar-width": `${sidebarWidth}px` } : undefined}
    >

      <aside className="sidebar">
        <div className="sidebar-top">
          <div className="brand">
            <div className="brand-badge">C2F</div>
            <div className="brand-copy">
              <div className="brand-title">Click2Fix</div>
              <div className="brand-subtitle">SOC Operations Platform</div>
              <div className="brand-version">Version {appVersion}</div>
            </div>
          </div>
          <button
            type="button"
            className="sidebar-toggle"
            onClick={() => setSidebarCollapsed((prev) => !prev)}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-pressed={sidebarCollapsed}
          >
            {sidebarCollapsed ? ">" : "<"}
          </button>
        </div>

        <div className="sidebar-workspace">
          <div
            className={`priority-panel${priorityPanelCollapsed ? " collapsed" : " resizable"}`}
            aria-label="Priority navigation"
            data-tour-id="priority-queue"
            style={!priorityPanelCollapsed && !sidebarCollapsed ? { "--priority-panel-height": `${priorityPanelHeight}px` } : undefined}
          >
            <div className="priority-panel-header">
              <div className="priority-title">Priority Queue</div>
              <div className="priority-panel-actions">
                {!priorityPanelCollapsed ? (
                  <button
                    type="button"
                    className="panel-collapse-btn"
                    onClick={() => setPriorityConfigOpen((prev) => !prev)}
                    aria-pressed={priorityConfigOpen}
                    title={priorityConfigOpen ? "Close priority queue settings" : "Customize priority queue"}
                  >
                    {priorityConfigOpen ? "Done" : "Edit"}
                  </button>
                ) : null}
                <button
                  type="button"
                  className="panel-collapse-btn"
                  onClick={() => setPriorityPanelCollapsed((prev) => !prev)}
                  aria-expanded={!priorityPanelCollapsed}
                  aria-label={priorityPanelCollapsed ? "Expand priority queue" : "Collapse priority queue"}
                  title={priorityPanelCollapsed ? "Expand priority queue" : "Collapse priority queue"}
                >
                  {priorityPanelCollapsed ? "+" : "-"}
                </button>
              </div>
            </div>
            {!priorityPanelCollapsed ? (
              <div className="priority-panel-body">
                {priorityConfigOpen ? (
                  <div className="priority-config">
                    <div className="priority-config-header">
                      <span className="meta-line">Choose which shortcuts stay in the queue and reorder them for your workflow.</span>
                      <button type="button" className="panel-collapse-btn" onClick={resetPriorityQueue} title="Reset priority queue">
                        Reset
                      </button>
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
                <div className="priority-links">
                  {priorityLinks.length ? priorityLinks.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      title={item.label}
                      className={({ isActive }) => `priority-link${isActive ? " active" : ""}`}
                    >
                      <span className="nav-link-badge">{shortLabel(item.label)}</span>
                      <span className="nav-link-label">{item.label}</span>
                    </NavLink>
                  )) : (
                    <div className="empty-state priority-empty-state">
                      Enable at least one priority shortcut in Edit mode.
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>

          {!sidebarCollapsed ? (
            <div className={`sidebar-divider${priorityPanelCollapsed ? " disabled" : ""}`} aria-hidden="true">
              <button
                type="button"
                className="sidebar-divider-handle"
                onMouseDown={startPriorityResize}
                onDoubleClick={() => setPriorityPanelHeight(DEFAULT_PRIORITY_PANEL_HEIGHT)}
                disabled={priorityPanelCollapsed}
                title="Drag to resize priority queue. Double-click to reset."
              />
            </div>
          ) : null}

          <div className="sidebar-module-shell">
            <nav className="nav-groups" aria-label="Primary navigation">
              {NAV_SECTIONS.map((section) => (
                <div className="nav-group" key={section.title}>
                  <div className="nav-group-title">{section.title}</div>
                  <div className="nav-group-links">
                    {section.links.map((link) => (
                      <NavLink
                        key={link.to}
                        to={link.to}
                        end={Boolean(link.end)}
                        title={link.label}
                        className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
                      >
                        <span className="nav-link-badge">{shortLabel(link.label)}</span>
                        <span className="nav-link-label">{link.label}</span>
                      </NavLink>
                    ))}
                  </div>
                </div>
              ))}
            </nav>
          </div>

          <div className={`ops-panel${opsCompact ? " compact" : ""}`}>
            <div className="ops-panel-header">
              <div className="priority-title">Backend Ops</div>
              <div className="page-actions gap-6">
                <button
                  type="button"
                  className="panel-collapse-btn"
                  onClick={() => setOpsCompact((prev) => !prev)}
                  aria-pressed={opsCompact}
                  title={opsCompact ? "Expand ops modules" : "Collapse ops modules to icon mode"}
                >
                  {opsCompact ? "Full" : "Mini"}
                </button>
                <button type="button" className="panel-collapse-btn" onClick={openOpsConsole} title="Open backend ops console">
                  Open
                </button>
              </div>
            </div>
            <div className="ops-panel-body">
              <div className="ops-accordion-list">
                {OPS_MODULES.map((section) => {
                  const isOpen = !opsCompact && Boolean(openOpsSections[section.id]);
                  return (
                    <div key={section.id} className={`ops-accordion${isOpen ? " open" : ""}`}>
                      <button
                        type="button"
                        className="ops-accordion-toggle"
                        onClick={() => {
                          if (opsCompact) {
                            setOpsCompact(false);
                            return;
                          }
                          setOpenOpsSections((prev) => ({
                            ...prev,
                            [section.id]: !prev[section.id],
                          }));
                        }}
                        aria-expanded={isOpen}
                        title={section.label}
                      >
                        <span className="nav-link-badge">{shortLabel(section.label)}</span>
                        {!opsCompact ? <span className="ops-accordion-label">{section.label}</span> : null}
                        {!opsCompact ? <span className="ops-accordion-state">{isOpen ? "-" : "+"}</span> : null}
                      </button>
                      {isOpen ? (
                        <div className="ops-accordion-links">
                          {section.links.map((link) => (
                            <NavLink
                              key={link.to}
                              to={link.to}
                              title={link.label}
                              className={({ isActive }) => `ops-link${isActive ? " active" : ""}`}
                            >
                              <span className="nav-link-badge">{shortLabel(link.label)}</span>
                              <span className="nav-link-label">{link.label}</span>
                            </NavLink>
                          ))}
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div className="sidebar-footer">
          <div className="footer-status">
            <div className="status-dot" />
            <span>{user ? `${user.username} - ${user.role}` : "Connected"}</span>
          </div>
          <div className="footer-version">
            Version <span className="version-pill">{appVersion}</span>
          </div>
        </div>
      </aside>
      {!sidebarCollapsed ? (
        <div className="app-layout-divider" aria-hidden="true">
          <button
            type="button"
            className="app-layout-divider-handle"
            onMouseDown={startSidebarResize}
            onDoubleClick={() => setSidebarWidth(DEFAULT_SIDEBAR_WIDTH)}
            title="Drag to resize sidebar. Double-click to reset."
          />
        </div>
      ) : null}

      <main className="main-content">
        <div className="topbar">
          <div className="topbar-left">
            <div className="topbar-title-block">
              <div className="topbar-title-row">
                <div className="topbar-title">{currentPageLabel}</div>
              </div>
              <div className="topbar-subtitle">Security Operations Console</div>
              <div className="topbar-breadcrumbs">
                {breadcrumbs.map((item, index) => (
                  <span key={`${item.href}-${item.label}`}>
                    {index > 0 ? " / " : ""}
                    {item.label}
                  </span>
                ))}{" "}
                | Timezone: {APP_TIMEZONE_LABEL}
              </div>
            </div>
          </div>
          <div className="topbar-right">
            <form className="search" onSubmit={submitSearch}>
              <input
                aria-label="Search alerts, agents, actions"
                placeholder="Search by alert ID, CVE, host, IP, IOC..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <button className="btn secondary" type="submit">Search</button>
            </form>
            <div className="topbar-actions">
              <span className={`topbar-health-dot ${healthTone}`} aria-hidden="true" />
              <span className="topbar-health-inline">
                {backendHealth.socketLive ? "Socket live" : "Reconnecting"}
              </span>
              <span className="topbar-health-inline">{backendHealth.activeExecutions} active</span>
              <span className="topbar-health-inline">
                {backendHealth.socketLatencyMs !== null ? `${backendHealth.socketLatencyMs} ms` : "Latency --"}
              </span>
              {backendHealth.queuedExecutions > 0 ? (
                <span className="topbar-health-inline">{backendHealth.queuedExecutions} queued</span>
              ) : null}
              <button type="button" className="btn secondary" onClick={() => setMissionBriefingOpen(true)} aria-label="Open mission briefing">
                Guide
              </button>
              <button
                type="button"
                className="btn secondary sidebar-toggle-mobile"
                onClick={() => setSidebarCollapsed((prev) => !prev)}
                aria-pressed={sidebarCollapsed}
              >
                {sidebarCollapsed ? "Expand Nav" : "Collapse Nav"}
              </button>
              <button className="btn secondary" onClick={logout}>Logout</button>
            </div>
          </div>
        </div>

        <div className="content">
          <Outlet />
        </div>
      </main>

      <MissionBriefing
        open={missionBriefingOpen}
        steps={MISSION_BRIEFING_STEPS}
        onClose={completeMissionBriefing}
        onComplete={completeMissionBriefing}
      />
    </div>
  );
}

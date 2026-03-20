import { NavLink, Outlet, useNavigate, useLocation } from "react-router-dom";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import api, {
  clearLegacyToken,
  decodeLegacyTokenPayload,
  getLegacyToken
} from "../api/client";
import { APP_TIMEZONE_LABEL } from "../utils/time";
import { resolveDisplayVersion, UI_APP_VERSION } from "../utils/appVersion";

const SIDEBAR_STORAGE_KEY = "c2f-sidebar-collapsed";
const PRIORITY_PANEL_STORAGE_KEY = "c2f-priority-panel-collapsed";
const PRIORITY_PANEL_HEIGHT_STORAGE_KEY = "c2f-priority-panel-height";
const SIDEBAR_WIDTH_STORAGE_KEY = "c2f-sidebar-width";
const OPS_PANEL_COMPACT_STORAGE_KEY = "c2f-ops-panel-compact";
const DEFAULT_PRIORITY_PANEL_HEIGHT = 320;
const MIN_PRIORITY_PANEL_HEIGHT = 170;
const MAX_PRIORITY_PANEL_HEIGHT = 520;
const DEFAULT_SIDEBAR_WIDTH = 352;
const MIN_SIDEBAR_WIDTH = 248;
const MAX_SIDEBAR_WIDTH = 640;

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
    window.localStorage.setItem(SIDEBAR_WIDTH_STORAGE_KEY, String(sidebarWidth));
  }, [sidebarWidth]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(OPS_PANEL_COMPACT_STORAGE_KEY, opsCompact ? "1" : "0");
  }, [opsCompact]);

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
    const token = String(getLegacyToken() || "").trim();
    const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : "";
    const opsUrl = `${window.location.origin}/ops${tokenQuery}`;
    window.open(opsUrl, "_blank", "noopener,noreferrer");
  };

  return (
    <div
      ref={layoutRef}
      className={`app-layout${sidebarCollapsed ? " sidebar-collapsed" : ""}`}
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
            style={!priorityPanelCollapsed && !sidebarCollapsed ? { "--priority-panel-height": `${priorityPanelHeight}px` } : undefined}
          >
            <div className="priority-panel-header">
              <div className="priority-title">Priority Queue</div>
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
            {!priorityPanelCollapsed ? (
              <div className="priority-panel-body">
                <div className="priority-links">
                  {PRIORITY_LINKS.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      title={item.label}
                      className={({ isActive }) => `priority-link${isActive ? " active" : ""}`}
                    >
                      <span className="nav-link-badge">{shortLabel(item.label)}</span>
                      <span className="nav-link-label">{item.label}</span>
                    </NavLink>
                  ))}
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
                  {opsCompact ? "+" : "[]"}
                </button>
                <button type="button" className="panel-collapse-btn" onClick={openOpsConsole} title="Open backend ops console">
                  {"->"}
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
            <div className="topbar-title">{currentPageLabel}</div>
            <div className="topbar-subtitle">
              Security Operations Console |
              {breadcrumbs.map((item, index) => (
                <span key={`${item.href}-${item.label}`}>
                  {index > 0 ? " / " : ""}
                  {item.label}
                </span>
              ))}{" "}
              | Timezone: {APP_TIMEZONE_LABEL}
            </div>
          </div>
          <div className="topbar-right">
            <button
              type="button"
              className="btn secondary sidebar-toggle-mobile"
              onClick={() => setSidebarCollapsed((prev) => !prev)}
              aria-pressed={sidebarCollapsed}
            >
              {sidebarCollapsed ? "Expand Nav" : "Collapse Nav"}
            </button>
            <div className="topbar-version" title="Current frontend version">
              {appVersion}
            </div>
            <div className="topbar-shortcuts" aria-label="Quick navigation">
              <NavLink to="/alerts" className={({ isActive }) => `topbar-shortcut${isActive ? " active" : ""}`}>
                Alerts
              </NavLink>
              <NavLink to="/cases" className={({ isActive }) => `topbar-shortcut${isActive ? " active" : ""}`}>
                Cases
              </NavLink>
              <NavLink to="/approvals" className={({ isActive }) => `topbar-shortcut${isActive ? " active" : ""}`}>
                Approvals
              </NavLink>
            </div>
            <form className="search" onSubmit={submitSearch}>
              <input
                aria-label="Search alerts, agents, actions"
                placeholder="Search by alert ID, CVE, host, IP, IOC..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <button className="btn secondary" type="submit">Search</button>
            </form>
            <button className="btn secondary" onClick={logout}>Logout</button>
          </div>
        </div>

        <div className="content">
          <Outlet />
        </div>
      </main>

    </div>
  );
}

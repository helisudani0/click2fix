import { NavLink, Outlet, useNavigate, useLocation } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import api, {
  clearLegacyToken,
  decodeLegacyTokenPayload,
  getLegacyToken
} from "../api/client";
import { APP_TIMEZONE_LABEL } from "../utils/time";
import { resolveDisplayVersion, UI_APP_VERSION } from "../utils/appVersion";

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

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [search, setSearch] = useState("");
  const [appVersion, setAppVersion] = useState(UI_APP_VERSION);

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
    <div className="app-layout">

      <aside className="sidebar">
        <div className="brand">
          <div className="brand-badge">C2F</div>
          <div>
            <div className="brand-title">Click2Fix</div>
            <div className="brand-subtitle">SOC Operations Platform</div>
            <div className="brand-version">Version {appVersion}</div>
          </div>
        </div>

        <div className="priority-panel" aria-label="Priority navigation">
          <div className="priority-title">Priority Queue</div>
          <div className="priority-links">
            {PRIORITY_LINKS.map((item) => (
              <NavLink key={item.to} to={item.to} className={({ isActive }) => `priority-link${isActive ? " active" : ""}`}>
                {item.label}
              </NavLink>
            ))}
          </div>
        </div>

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
                    className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
                  >
                    {link.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <button type="button" className="nav-link ops-link-btn" onClick={openOpsConsole}>
          Backend Ops
        </button>

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

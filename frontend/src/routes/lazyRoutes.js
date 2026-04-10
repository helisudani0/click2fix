import { lazy } from "react";

const memoizedLoader = (loader) => {
  let promise = null;
  return () => {
    if (!promise) promise = loader();
    return promise;
  };
};

const lazyWithPreload = (loader) => {
  const Component = lazy(loader);
  Component.preload = loader;
  return Component;
};

const loadDashboard = memoizedLoader(() => import("../components/Dashboard"));
const loadAgents = memoizedLoader(() => import("../pages/Agents"));
const loadAgentSca = memoizedLoader(() => import("../pages/AgentSca"));
const loadActions = memoizedLoader(() => import("../pages/Actions"));
const loadAlerts = memoizedLoader(() => import("../pages/Alerts"));
const loadScaFleet = memoizedLoader(() => import("../pages/ScaFleet"));
const loadVulnerabilities = memoizedLoader(() => import("../pages/Vulnerabilities"));
const loadPlaybooks = memoizedLoader(() => import("../pages/Playbooks"));
const loadApprovals = memoizedLoader(() => import("../pages/Approvals"));
const loadExecutions = memoizedLoader(() => import("../pages/Executions"));
const loadCases = memoizedLoader(() => import("../pages/Cases"));
const loadIncidents = memoizedLoader(() => import("../pages/Incidents"));
const loadGovernance = memoizedLoader(() => import("../pages/Governance"));
const loadScheduler = memoizedLoader(() => import("../pages/Scheduler"));
const loadOrgAdmin = memoizedLoader(() => import("../pages/OrgAdmin"));
const loadAnalytics = memoizedLoader(() => import("../pages/Analytics"));
const loadAudit = memoizedLoader(() => import("../pages/Audit"));
const loadChanges = memoizedLoader(() => import("../pages/Changes"));
const loadGlobalShell = memoizedLoader(() => import("../pages/GlobalShell"));
const loadLogin = memoizedLoader(() => import("../pages/Login"));

export const Dashboard = lazyWithPreload(loadDashboard);
export const Agents = lazyWithPreload(loadAgents);
export const AgentSca = lazyWithPreload(loadAgentSca);
export const Actions = lazyWithPreload(loadActions);
export const Alerts = lazyWithPreload(loadAlerts);
export const ScaFleet = lazyWithPreload(loadScaFleet);
export const Vulnerabilities = lazyWithPreload(loadVulnerabilities);
export const Playbooks = lazyWithPreload(loadPlaybooks);
export const Approvals = lazyWithPreload(loadApprovals);
export const Executions = lazyWithPreload(loadExecutions);
export const Cases = lazyWithPreload(loadCases);
export const Incidents = lazyWithPreload(loadIncidents);
export const Governance = lazyWithPreload(loadGovernance);
export const Scheduler = lazyWithPreload(loadScheduler);
export const OrgAdmin = lazyWithPreload(loadOrgAdmin);
export const Analytics = lazyWithPreload(loadAnalytics);
export const Audit = lazyWithPreload(loadAudit);
export const Changes = lazyWithPreload(loadChanges);
export const GlobalShell = lazyWithPreload(loadGlobalShell);
export const Login = lazyWithPreload(loadLogin);

const ROUTE_LOADERS = new Map([
  ["/", loadDashboard],
  ["/agents", loadAgents],
  ["/agents/:agentId/sca", loadAgentSca],
  ["/actions", loadActions],
  ["/alerts", loadAlerts],
  ["/sca-fleet", loadScaFleet],
  ["/incidents", loadIncidents],
  ["/vulnerabilities", loadVulnerabilities],
  ["/playbooks", loadPlaybooks],
  ["/approvals", loadApprovals],
  ["/executions", loadExecutions],
  ["/scheduler", loadScheduler],
  ["/cases", loadCases],
  ["/governance", loadGovernance],
  ["/analytics", loadAnalytics],
  ["/audit", loadAudit],
  ["/changes", loadChanges],
  ["/orgs", loadOrgAdmin],
  ["/global-shell", loadGlobalShell],
  ["/login", loadLogin],
]);

const BACKGROUND_PRELOAD_ROUTES = [
  "/alerts",
  "/agents",
  "/actions",
  "/executions",
  "/cases",
  "/analytics",
  "/vulnerabilities",
  "/playbooks",
  "/incidents",
  "/global-shell",
  "/scheduler",
  "/approvals",
  "/sca-fleet",
  "/governance",
  "/audit",
  "/changes",
  "/orgs",
];

const normalizeRoutePath = (path) => {
  const raw = String(path || "")
    .split("?", 1)[0]
    .split("#", 1)[0]
    .trim();
  if (!raw) return "/";
  if (/^\/agents\/[^/]+\/sca$/i.test(raw)) return "/agents/:agentId/sca";
  return raw;
};

export const preloadRouteByPath = (path) => {
  const route = normalizeRoutePath(path);
  const loader = ROUTE_LOADERS.get(route);
  if (!loader) return Promise.resolve();
  return loader().catch(() => undefined);
};

let backgroundWarmupPromise = null;

export const preloadRoutesInBackground = () => {
  if (backgroundWarmupPromise) return backgroundWarmupPromise;
  backgroundWarmupPromise = BACKGROUND_PRELOAD_ROUTES.reduce(
    (chain, route) =>
      chain
        .then(() => preloadRouteByPath(route))
        .then(
          () =>
            new Promise((resolve) => {
              window.setTimeout(resolve, 0);
            })
        ),
    Promise.resolve()
  );
  return backgroundWarmupPromise;
};


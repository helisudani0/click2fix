import { lazy, Suspense, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import AppLayout from "./components/AppLayout";
import RequireAuth from "./components/RequireAuth";
import "./index-base.css";
import "./styles/console-redesign-v4.css";

const Dashboard = lazy(() => import("./components/Dashboard"));
const Agents = lazy(() => import("./pages/Agents"));
const Actions = lazy(() => import("./pages/Actions"));
const Alerts = lazy(() => import("./pages/Alerts"));
const ScaFleet = lazy(() => import("./pages/ScaFleet"));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities"));
const Playbooks = lazy(() => import("./pages/Playbooks"));
const Approvals = lazy(() => import("./pages/Approvals"));
const Executions = lazy(() => import("./pages/Executions"));
const Cases = lazy(() => import("./pages/Cases"));
const Incidents = lazy(() => import("./pages/Incidents"));
const Governance = lazy(() => import("./pages/Governance"));
const Scheduler = lazy(() => import("./pages/Scheduler"));
const OrgAdmin = lazy(() => import("./pages/OrgAdmin"));
const Analytics = lazy(() => import("./pages/Analytics"));
const Audit = lazy(() => import("./pages/Audit"));
const Changes = lazy(() => import("./pages/Changes"));
const GlobalShell = lazy(() => import("./pages/GlobalShell"));
const Login = lazy(() => import("./pages/Login"));

export default function App() {
  useEffect(() => {
    if (typeof document === "undefined") return undefined;
    document.body.classList.add("console-redesign-v4");
    return () => document.body.classList.remove("console-redesign-v4");
  }, []);

  return (
    <Suspense fallback={<div className="empty-state">Loading workspace...</div>}>
      <Routes>
        <Route path="/login" element={<Login />} />

        <Route element={<RequireAuth />}>
          <Route element={<AppLayout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/actions" element={<Actions />} />
            <Route path="/global-shell" element={<GlobalShell />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/sca-fleet" element={<ScaFleet />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/playbooks" element={<Playbooks />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/executions" element={<Executions />} />
            <Route path="/scheduler" element={<Scheduler />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/governance" element={<Governance />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/changes" element={<Changes />} />
            <Route path="/orgs" element={<OrgAdmin />} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
}

import { lazy, Suspense } from "react";
import { Routes, Route } from "react-router-dom";
import AppLayout from "./components/AppLayout";
import RequireAuth from "./components/RequireAuth";
import "./index.css";

const Dashboard = lazy(() => import("./components/Dashboard"));
const Agents = lazy(() => import("./pages/Agents"));
const Actions = lazy(() => import("./pages/Actions"));
const Alerts = lazy(() => import("./pages/Alerts"));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities"));
const Playbooks = lazy(() => import("./pages/Playbooks"));
const Approvals = lazy(() => import("./pages/Approvals"));
const Executions = lazy(() => import("./pages/Executions"));
const Cases = lazy(() => import("./pages/Cases"));
const Scheduler = lazy(() => import("./pages/Scheduler"));
const OrgAdmin = lazy(() => import("./pages/OrgAdmin"));
const Analytics = lazy(() => import("./pages/Analytics"));
const Audit = lazy(() => import("./pages/Audit"));
const Changes = lazy(() => import("./pages/Changes"));
const GlobalShell = lazy(() => import("./pages/GlobalShell"));
const Login = lazy(() => import("./pages/Login"));

export default function App() {
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
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/playbooks" element={<Playbooks />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/executions" element={<Executions />} />
            <Route path="/scheduler" element={<Scheduler />} />
            <Route path="/cases" element={<Cases />} />
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

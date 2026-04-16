import { Suspense, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import AppLayout from "./components/AppLayout";
import RequireAuth from "./components/RequireAuth";
import {
  Actions,
  AgentSca,
  Agents,
  Alerts,
  Analytics,
  Approvals,
  Audit,
  Cases,
  Changes,
  Dashboard,
  Executions,
  GlobalShell,
  Governance,
  Incidents,
  Login,
  OrgAdmin,
  PatchWorkbench,
  Playbooks,
  Scheduler,
  ScaFleet,
  Vulnerabilities,
  preloadRoutesInBackground,
} from "./routes/lazyRoutes";
import "./index-base.css";
import "./styles/console-overhaul-v1.css";
import "./styles/patch-workbench.css";

export default function App() {
  useEffect(() => {
    if (typeof document === "undefined") return undefined;
    document.body.classList.add("console-redesign-v4");
    return () => document.body.classList.remove("console-redesign-v4");
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    const connection = navigator?.connection;
    const saveData = Boolean(connection?.saveData);
    const slowConnection =
      typeof connection?.effectiveType === "string" &&
      /(^|-)2g$/i.test(connection.effectiveType.trim());
    if (saveData || slowConnection) return undefined;

    let cancelled = false;
    let idleId = null;
    let timerId = null;
    const startWarmup = () => {
      if (cancelled) return;
      void preloadRoutesInBackground();
    };

    if (typeof window.requestIdleCallback === "function") {
      idleId = window.requestIdleCallback(startWarmup, { timeout: 1800 });
    } else {
      timerId = window.setTimeout(startWarmup, 1000);
    }

    return () => {
      cancelled = true;
      if (idleId !== null && typeof window.cancelIdleCallback === "function") {
        window.cancelIdleCallback(idleId);
      }
      if (timerId !== null) {
        window.clearTimeout(timerId);
      }
    };
  }, []);

  return (
    <Suspense fallback={<div className="empty-state">Loading workspace...</div>}>
      <Routes>
        <Route path="/login" element={<Login />} />

        <Route element={<RequireAuth />}>
          <Route element={<AppLayout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/agents/:agentId/sca" element={<AgentSca />} />
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
            <Route path="/patch-workbench" element={<PatchWorkbench />} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
}

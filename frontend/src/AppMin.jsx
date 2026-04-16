import { Suspense, useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import RequireAuth from "./components/RequireAuth";
import { Login, PatchWorkbench } from "./routes/minLazyRoutes";
import "./index-base.css";
import "./styles/patch-workbench.css";

export default function AppMin() {
  useEffect(() => {
    if (typeof document === "undefined") return undefined;
    document.body.classList.remove("console-redesign-v4");
    document.body.classList.add("patch-min-ui");
    return () => document.body.classList.remove("patch-min-ui");
  }, []);

  return (
    <Suspense fallback={<div className="empty-state">Loading patch workspace...</div>}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<RequireAuth />}>
          <Route path="/" element={<PatchWorkbench />} />
          <Route path="/patch-workbench" element={<PatchWorkbench />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}

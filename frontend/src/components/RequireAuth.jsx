import { useEffect, useState } from "react";
import { Navigate, Outlet } from "react-router-dom";
import api, { clearLegacyToken, getLegacyToken } from "../api/client";

export default function RequireAuth() {
  const [status, setStatus] = useState("checking");

  useEffect(() => {
    let active = true;
    api
      .get("/auth/me")
      .then(() => {
        if (active) setStatus("authenticated");
      })
      .catch(async (err) => {
        const statusCode = err?.response?.status;
        if ((statusCode === 404 || statusCode === 405) && getLegacyToken()) {
          if (active) setStatus("authenticated");
          return;
        }
        clearLegacyToken();
        try {
          await api.get("/auth/session/reset");
        } catch {
          // Best-effort stale cookie cleanup before redirecting to login.
        }
        if (active) setStatus("unauthenticated");
      });
    return () => {
      active = false;
    };
  }, []);

  if (status === "checking") {
    return <div className="empty-state">Checking authentication...</div>;
  }

  if (status !== "authenticated") {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}

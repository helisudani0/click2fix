import { useEffect, useState } from "react";
import { Navigate, Outlet } from "react-router-dom";
import api, { decodeLegacyTokenPayload, getLegacyToken } from "../api/client";

export default function RequireAuth() {
  const [status, setStatus] = useState("checking");

  useEffect(() => {
    let active = true;
    const token = getLegacyToken();
    if (token) {
      const payload = decodeLegacyTokenPayload();
      if (payload?.sub) {
        setStatus("authenticated");
        return () => {
          active = false;
        };
      }
    }
    api
      .get("/auth/me")
      .then(() => {
        if (active) setStatus("authenticated");
      })
      .catch((err) => {
        const statusCode = err?.response?.status;
        if ((statusCode === 404 || statusCode === 405) && getLegacyToken()) {
          if (active) setStatus("authenticated");
          return;
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

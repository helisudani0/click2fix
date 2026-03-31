import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api, { clearLegacyToken, getLegacyToken, setLegacyToken } from "../api/client";
import { resolveDisplayVersion, UI_APP_VERSION } from "../utils/appVersion";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [ssoLoading, setSsoLoading] = useState(false);
  const [appVersion, setAppVersion] = useState(UI_APP_VERSION);

  const clearStaleSession = async () => {
    clearLegacyToken();
    try {
      await api.get("/auth/session/reset");
    } catch {
      // Ignore session reset failures; login attempt will still proceed.
    }
  };

  useEffect(() => {
    let active = true;
    api
      .get("/auth/me")
      .then(() => {
        if (active) {
          navigate("/", { replace: true });
        }
      })
      .catch((err) => {
        const statusCode = err?.response?.status;
        if ((statusCode === 404 || statusCode === 405) && getLegacyToken()) {
          navigate("/", { replace: true });
          return;
        }
        if (statusCode === 401) {
          clearLegacyToken();
        }
      });
    return () => {
      active = false;
    };
  }, [navigate]);

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

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await clearStaleSession();
      const submitCredentials = async () => {
        const form = new URLSearchParams();
        form.append("username", username);
        form.append("password", password);
        return api.post("/auth/login", form, {
          headers: { "Content-Type": "application/x-www-form-urlencoded" }
        });
      };

      let res;
      try {
        res = await submitCredentials();
      } catch (firstError) {
        const statusCode = Number(firstError?.response?.status || 0);
        const detail = String(firstError?.response?.data?.detail || "").toLowerCase();
        const csrfRejected = statusCode === 403 && detail.includes("csrf");
        const authRejected = statusCode === 401;
        if (!csrfRejected && !authRejected) {
          throw firstError;
        }
        await clearStaleSession();
        res = await submitCredentials();
      }

      clearLegacyToken();
      const token = String(res?.data?.access_token || "").trim();
      if (token) {
        setLegacyToken(token);
      }
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page page-route-login">
      <div className="login-card">
        <div className="login-brand">
          <div className="brand-badge">C2F</div>
          <div>
            <div className="brand-title">Click2Fix</div>
            <div className="brand-subtitle">SOAR Console</div>
            <div className="brand-version">Version {appVersion}</div>
          </div>
        </div>

        <h2>Log in</h2>
        <p className="muted">Use your SOC credentials to access the console.</p>

        <form className="login-form" onSubmit={handleSubmit}>
          <label>
            Username
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
            />
          </label>
          <label>
            Password
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="admin123"
            />
          </label>
          {error && <div className="empty-state">{error}</div>}
          <button className="btn" type="submit" disabled={loading}>
            {loading ? "Logging in..." : "Log In"}
          </button>
        </form>

        <button
          className="btn secondary"
          type="button"
          disabled={ssoLoading}
          onClick={async () => {
            setSsoLoading(true);
            setError(null);
            try {
              const res = await api.get("/auth/oidc/login");
              if (res.data?.auth_url) {
                window.location.href = res.data.auth_url;
              } else {
                setError("SSO is not configured.");
              }
            } catch (err) {
              setError(err.response?.data?.detail || "SSO unavailable.");
            } finally {
              setSsoLoading(false);
            }
          }}
        >
          {ssoLoading ? "Redirecting..." : "Log in with SSO"}
        </button>

        <div className="login-hint">
          Use your SOC or Wazuh-provided credentials for this environment.
        </div>
      </div>
    </div>
  );
}


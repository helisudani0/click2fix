import axios from "axios";
import { syncServerClock } from "../utils/time";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || "/api",
  withCredentials: true
});

const readCookie = (name) => {
  if (typeof document === "undefined") return "";
  const escaped = String(name || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = document.cookie.match(new RegExp(`(?:^|; )${escaped}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : "";
};

export const getLegacyToken = () => {
  if (typeof localStorage === "undefined") return "";
  return String(localStorage.getItem("token") || "");
};

export const setLegacyToken = (token) => {
  if (typeof localStorage === "undefined") return;
  const value = String(token || "").trim();
  if (!value) return;
  localStorage.setItem("token", value);
};

export const clearLegacyToken = () => {
  if (typeof localStorage === "undefined") return;
  localStorage.removeItem("token");
};

export const decodeLegacyTokenPayload = () => {
  const token = getLegacyToken();
  if (!token || !token.includes(".")) return null;
  try {
    const raw = token.split(".")[1] || "";
    const normalized = raw.replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(normalized);
    return JSON.parse(json);
  } catch {
    return null;
  }
};

api.interceptors.request.use((config) => {
  const token = getLegacyToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  const method = String(config.method || "get").toLowerCase();
  if (["post", "put", "patch", "delete"].includes(method)) {
    const csrf = readCookie("c2f_csrf");
    if (csrf) {
      config.headers["X-CSRF-Token"] = csrf;
    }
  }
  return config;
});

api.interceptors.response.use(
  (response) => {
    const serverTime = response?.headers?.["x-server-time"] || response?.headers?.date;
    if (serverTime) {
      syncServerClock(serverTime);
    }
    return response;
  },
  (error) => {
    const serverTime = error?.response?.headers?.["x-server-time"] || error?.response?.headers?.date;
    if (serverTime) {
      syncServerClock(serverTime);
    }
    if (error?.response?.status === 401) {
      // Keep UI stable: surface auth errors to the current screen instead of hard-refreshing.
      error.authExpired = true;
    }
    return Promise.reject(error);
  }
);

export default api;
export const getForensicsReports = (params = {}) =>
  api.get("/forensics/reports", { params });

export const getForensicsReport = (id) =>
  api.get(`/forensics/reports/${id}`);

export const getForensicsSummary = () =>
  api.get("/forensics/summary");

export const uploadForensicsReport = (agentId, file, metadata = {}) => {
  const form = new FormData();
  form.append("file", file);
  form.append("agent_id", agentId);
  Object.entries(metadata).forEach(([key, value]) => {
    form.append(key, value);
  });
  return api.post("/forensics/reports", form, {
    headers: { "Content-Type": "multipart/form-data" }
  });
};

export const deleteForensicsReport = (id) =>
  api.delete(`/forensics/reports/${id}`);

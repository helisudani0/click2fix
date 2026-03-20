const normalizeBase = (value) => String(value || "").trim().replace(/\/+$/, "");

const toWsBase = (value) => {
  const normalized = normalizeBase(value);
  if (!normalized) return "";
  if (normalized.startsWith("/")) {
    if (typeof window === "undefined") return normalized;
    try {
      return toWsBase(new URL(normalized, window.location.origin).toString());
    } catch {
      return normalized;
    }
  }
  if (normalized.startsWith("https://")) {
    return `wss://${normalized.slice("https://".length)}`;
  }
  if (normalized.startsWith("http://")) {
    return `ws://${normalized.slice("http://".length)}`;
  }
  return normalized;
};

const baseFromApi = () => {
  const apiBase = String(import.meta.env.VITE_API_BASE || "").trim();
  if (!apiBase || typeof window === "undefined") {
    return "";
  }
  try {
    return toWsBase(new URL(apiBase, window.location.origin).origin);
  } catch {
    return "";
  }
};

const wsBase = () => {
  const configuredWsBase = toWsBase(import.meta.env.VITE_WS_BASE);
  if (configuredWsBase) {
    return configuredWsBase;
  }
  const derivedFromApi = baseFromApi();
  if (derivedFromApi) {
    return derivedFromApi;
  }
  if (typeof window === "undefined") {
    return "";
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}`;
};

const buildWsUrl = (path) => {
  const base = wsBase();
  const normalizedPath = `/${String(path || "").replace(/^\/+/, "")}`;
  if (!base) return normalizedPath;
  if (base.endsWith("/ws") && normalizedPath.startsWith("/ws/")) {
    return `${base}${normalizedPath.slice(3)}`;
  }
  return `${base}${normalizedPath}`;
};

export const alertSocket = () =>
  new WebSocket(buildWsUrl("/ws/alerts"));

export const executionSocket = (executionId) =>
  new WebSocket(buildWsUrl(`/ws/executions/${executionId}`));

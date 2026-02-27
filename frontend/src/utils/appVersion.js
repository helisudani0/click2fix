const normalizeVersion = (raw) => {
  const text = String(raw || "").trim();
  if (!text) return "";
  if (text.toLowerCase() === "dev") return "dev";
  if (text.toLowerCase() === "latest") return "latest";
  return text.toLowerCase().startsWith("v") ? text : `v${text}`;
};

const rawVersion = String(import.meta.env.VITE_APP_VERSION || "").trim();
export const UI_APP_VERSION = normalizeVersion(rawVersion) || "dev";

export const resolveDisplayVersion = (serverVersion) =>
  normalizeVersion(serverVersion) || UI_APP_VERSION;

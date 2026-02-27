const rawVersion = String(import.meta.env.VITE_APP_VERSION || "").trim();

export const UI_APP_VERSION = rawVersion
  ? (rawVersion.toLowerCase().startsWith("v") ? rawVersion : `v${rawVersion}`)
  : "dev";


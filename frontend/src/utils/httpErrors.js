const normalizeDetail = (value) => {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value
      .map((entry) => {
        if (typeof entry === "string") return entry;
        if (entry && typeof entry === "object") {
          if (typeof entry.msg === "string" && entry.msg.trim()) return entry.msg;
          if (typeof entry.message === "string" && entry.message.trim()) return entry.message;
          if (typeof entry.error === "string" && entry.error.trim()) return entry.error;
          try {
            return JSON.stringify(entry);
          } catch {
            return String(entry);
          }
        }
        return String(entry ?? "");
      })
      .filter((entry) => entry && entry.trim())
      .join("; ");
  }
  if (value && typeof value === "object") {
    if (typeof value.message === "string" && value.message.trim()) return value.message;
    if (typeof value.error === "string" && value.error.trim()) return value.error;
    if (typeof value.msg === "string" && value.msg.trim()) return value.msg;
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value ?? "");
};

const extractDetail = (error, fallback = "") => (
  normalizeDetail(error?.response?.data?.detail)
  || normalizeDetail(error?.recentLoginMessage)
  || normalizeDetail(error?.message)
  || normalizeDetail(fallback)
  || "Request failed."
);

export const isRecentLoginError = (error) => {
  if (error?.requiresRecentLogin) return true;
  const detail = String(extractDetail(error, "") || "").toLowerCase();
  return detail.includes("recent login required");
};

export const formatApiError = (error, fallback = "Request failed.") => {
  const detail = String(extractDetail(error, fallback) || fallback || "Request failed.");
  if (!isRecentLoginError(error)) return detail;
  if (detail.toLowerCase().includes("sign in again")) {
    return `${detail} Open the Login page in another tab if needed, then retry here.`;
  }
  return `${detail} Sign in again, then retry here.`;
};

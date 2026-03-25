const extractDetail = (error, fallback = "") => (
  error?.response?.data?.detail
  || error?.recentLoginMessage
  || error?.message
  || fallback
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

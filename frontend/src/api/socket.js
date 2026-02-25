const wsBase = () => {
  if (import.meta.env.VITE_WS_BASE) {
    return import.meta.env.VITE_WS_BASE;
  }
  if (typeof window === "undefined") {
    return "";
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}`;
};

export const alertSocket = () =>
  new WebSocket(`${wsBase()}/ws/alerts`);

export const executionSocket = (executionId) =>
  new WebSocket(`${wsBase()}/ws/executions/${executionId}`);

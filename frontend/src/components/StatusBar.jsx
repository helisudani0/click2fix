import { useEffect, useState } from "react";

export default function StatusBar({ isConnected = true }) {
  const [connectionStatus, setConnectionStatus] = useState(isConnected);

  useEffect(() => {
    setConnectionStatus(isConnected);
  }, [isConnected]);

  return (
    <div
      className={`status-bar pulse-status ${
        !connectionStatus ? "disconnected" : ""
      }`}
      role="status"
      aria-label={connectionStatus ? "Connected" : "Disconnected"}
      style={{
        background: connectionStatus
          ? "var(--status-green)"
          : "var(--status-red)",
      }}
    />
  );
}

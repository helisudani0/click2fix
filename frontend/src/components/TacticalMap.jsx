import { useMemo, useState } from "react";

const styles = `
.tactical-map {
  display: flex;
  flex-direction: column;
  height: 100%;
  border-right: 1px solid var(--border);
}

.tactical-header {
  padding: var(--space-4);
  border-bottom: 1px solid var(--border);
  background: var(--panel-soft);
}

.tactical-title {
  font-size: var(--font-size-sm);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 0;
}

.tactical-description {
  font-size: var(--font-size-xs);
  color: var(--muted);
  margin-top: var(--space-2);
}

.agents-table-container {
  flex: 1;
  overflow: auto;
}

.agents-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--font-size-sm);
}

.agents-table thead {
  position: sticky;
  top: 0;
  background: var(--panel-strong);
  border-bottom: 1px solid var(--border);
  z-index: 10;
}

.agents-table th {
  padding: var(--space-3) var(--space-4);
  text-align: left;
  font-weight: 600;
  text-transform: uppercase;
  font-size: var(--font-size-xs);
  letter-spacing: 0.05em;
  color: var(--muted);
  border-right: 1px solid var(--border);
}

.agents-table th:last-child {
  border-right: none;
}

.agents-table tbody tr {
  border-bottom: 1px solid var(--border);
  transition: background-color 150ms cubic-bezier(0.4, 0, 0.2, 1);
}

.agents-table tbody tr:hover {
  background: var(--panel-soft);
}

.agents-table tbody tr.is-selected {
  background: rgba(59, 130, 246, 0.12);
}

.agents-table td {
  padding: var(--space-3) var(--space-4);
  border-right: 1px solid var(--border);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-xs);
}

.agents-table td:last-child {
  border-right: none;
}

.agent-id {
  color: var(--accent);
  font-weight: 600;
}

.agent-status {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
}

.agent-status.online {
  background: rgba(16, 185, 129, 0.1);
  color: var(--status-green);
}

.agent-status.offline {
  background: rgba(239, 68, 68, 0.1);
  color: var(--status-red);
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
}

.agent-status.online .status-dot {
  background: var(--status-green);
}

.agent-status.offline .status-dot {
  background: var(--status-red);
}

.agent-latency {
  color: var(--muted);
}

.agent-latency.good {
  color: var(--status-green);
}

.agent-latency.fair {
  color: var(--status-yellow);
}

.agent-latency.poor {
  color: var(--status-red);
}

.empty-state {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  flex-direction: column;
  gap: var(--space-4);
  color: var(--muted);
}

.empty-state-icon {
  font-size: 48px;
  opacity: 0.5;
}

.empty-state-text {
  font-size: var(--font-size-sm);
  text-align: center;
}
`;

const isOnline = (status) => {
  const value = String(status || "").toLowerCase();
  return value.includes("online") || value.includes("active") || value.includes("connected");
};

export default function TacticalMap({
  agents = [],
  selectedAgents = [],
  onToggleAgent = () => {},
}) {
  const [sortBy, setSortBy] = useState("id");

  const selectedIds = useMemo(() => new Set(selectedAgents), [selectedAgents]);

  const sortedAgents = useMemo(() => {
    const nextAgents = [...agents];
    return nextAgents.sort((left, right) => {
      if (sortBy === "id") {
        return String(left.id || "").localeCompare(String(right.id || ""));
      }
      if (sortBy === "status") {
        return String(left.status || "").localeCompare(String(right.status || ""));
      }
      if (sortBy === "latency") {
        return (left.latency || 0) - (right.latency || 0);
      }
      return 0;
    });
  }, [agents, sortBy]);

  const getLatencyClass = (latency) => {
    if (!latency) return "";
    if (latency < 100) return "good";
    if (latency < 300) return "fair";
    return "poor";
  };

  const formatLatency = (latency) => {
    if (!latency) return "N/A";
    return `${latency}ms`;
  };

  return (
    <>
      <style>{styles}</style>
      <div className="tactical-map">
        <div className="tactical-header">
          <h3 className="tactical-title">Tactical Map</h3>
          <p className="tactical-description">
            Live agent health and latency monitoring. Click rows to target agents.
          </p>
        </div>

        <div className="agents-table-container">
          {agents.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">[ ]</div>
              <div className="empty-state-text">
                No agents available
                <br />
                Connect to start monitoring
              </div>
            </div>
          ) : (
            <table className="agents-table">
              <thead>
                <tr>
                  <th style={{ cursor: "pointer" }} onClick={() => setSortBy("id")}>
                    Agent ID {sortBy === "id" ? "v" : ""}
                  </th>
                  <th>Hostname</th>
                  <th style={{ cursor: "pointer" }} onClick={() => setSortBy("status")}>
                    Status {sortBy === "status" ? "v" : ""}
                  </th>
                  <th style={{ cursor: "pointer" }} onClick={() => setSortBy("latency")}>
                    Latency {sortBy === "latency" ? "v" : ""}
                  </th>
                  <th>OS</th>
                </tr>
              </thead>
              <tbody>
                {sortedAgents.map((agent) => {
                  const online = isOnline(agent.status);
                  const selected = selectedIds.has(agent.id);
                  return (
                    <tr
                      key={agent.id}
                      className={selected ? "is-selected" : ""}
                      onClick={() => onToggleAgent(agent.id)}
                      style={{ cursor: "pointer" }}
                    >
                      <td className="agent-id">{agent.id || "N/A"}</td>
                      <td>{agent.hostname || agent.name || "N/A"}</td>
                      <td>
                        <span className={`agent-status ${online ? "online" : "offline"}`}>
                          <span className="status-dot" />
                          {online ? "Online" : "Offline"}
                        </span>
                      </td>
                      <td className={`agent-latency ${getLatencyClass(agent.latency)}`}>
                        {formatLatency(agent.latency)}
                      </td>
                      <td>{agent.os || "N/A"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}

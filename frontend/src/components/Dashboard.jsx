import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import { getAlerts, getIntegrationStatus } from "../api/wazuh";
import { alertSocket } from "../api/socket";
import { APP_TIMEZONE_LABEL, formatWazuhTimestamp, nowUtcIso, parseWazuhTimestamp } from "../utils/time";

const normalizeAlerts = (data) => {
  let items = [];
  if (Array.isArray(data)) {
    items = data;
  } else if (data?.data?.affected_items) {
    items = data.data.affected_items;
  } else if (data?.affected_items) {
    items = data.affected_items;
  } else if (data?.data?.items) {
    items = data.data.items;
  } else if (data?.items) {
    items = data.items;
  }

  return items
    .map((alert) => {
      const rule = alert.rule || {};
      const agent = alert.agent || {};
      const idRaw = [alert.id, alert.alert_id].find(
        (value) => value !== null && value !== undefined && typeof value !== "object"
      );
      const id = String(idRaw || "").trim();
      if (!id) return null;
      return {
        id,
        rule: rule.description || rule.id || alert.message || "Alert",
        level: rule.level || rule.severity || alert.level || "n/a",
        agentName: agent.name || agent.id || agent.hostname || alert.agent || "unknown",
        timestampRaw: alert.timestamp || alert.time || alert["@timestamp"] || alert.date || "-",
      };
    })
    .filter(Boolean);
};

const byNewestAlert = (left, right) => {
  const l = parseWazuhTimestamp(left?.timestampRaw)?.getTime() || 0;
  const r = parseWazuhTimestamp(right?.timestampRaw)?.getTime() || 0;
  return r - l;
};

const formatEvent = (event) => {
  if (!event || typeof event !== "object") {
    return { title: "Event", agent: "-", level: "-", time: "-" };
  }
  const rule = event.rule || {};
  const agent = event.agent || {};
  return {
    title: rule.description || event.message || event.title || "Alert event",
    agent: agent.name || agent.id || event.agent || "-",
    level: rule.level || event.level || "-",
    time: formatWazuhTimestamp(event.timestamp || event.time || event["@timestamp"] || "-"),
  };
};

const severityClass = (level) => {
  const num = Number(level);
  if (Number.isNaN(num)) return "neutral";
  if (num >= 12) return "failed";
  if (num >= 7) return "pending";
  return "success";
};

const caseRow = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      title: row[1],
      status: row[3],
      createdAt: row[5],
    };
  }
  return {
    id: row?.id,
    title: row?.title,
    status: row?.status,
    createdAt: row?.created_at,
  };
};

const approvalRow = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      agent: row[1],
      action: row[2],
      createdAt: row[4],
      required: row[6] || 0,
      approved: row[7] || 0,
    };
  }
  return {
    id: row?.id,
    agent: row?.agent,
    action: row?.action || row?.playbook,
    createdAt: row?.created_at,
    required: row?.required_total || 0,
    approved: row?.approved_total || 0,
  };
};

const executionRow = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      agent: row[1],
      action: row[2],
      status: row[3],
      startedAt: row[5],
    };
  }
  return {
    id: row?.id,
    agent: row?.agent,
    action: row?.action || row?.playbook,
    status: row?.status,
    startedAt: row?.started_at,
  };
};

const executionTone = (status) => {
  const key = String(status || "").toUpperCase();
  if (key === "SUCCESS") return "success";
  if (["FAILED", "ERROR", "KILLED"].includes(key)) return "failed";
  if (["RUNNING", "PAUSED", "CANCELLED", "PENDING", "QUEUED"].includes(key)) return "pending";
  return "neutral";
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState([]);
  const [summary, setSummary] = useState({
    approvals_pending: 0,
    executions_total: 0,
    cases_total: 0,
    cases_open: 0,
    scheduled_total: 0,
    scheduled_enabled: 0,
    mitre_heatmap: [],
  });
  const [integration, setIntegration] = useState({
    wazuh_manager: { ok: false },
    indexer: { ok: false },
  });
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [recentCases, setRecentCases] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [recentExecutions, setRecentExecutions] = useState([]);
  const [queueLoading, setQueueLoading] = useState(false);
  const [lastRefreshAt, setLastRefreshAt] = useState(null);
  const [liveStreamEnabled, setLiveStreamEnabled] = useState(false);

  useEffect(() => {
    if (!liveStreamEnabled) {
      return undefined;
    }
    const ws = alertSocket();
    ws.onmessage = (msg) => {
      try {
        const payload = JSON.parse(msg.data);
        if (payload?.event === "heartbeat") return;
        if (payload?.event === "alert" && payload?.data) {
          setEvents((prev) => [...prev.slice(-39), payload.data]);
          return;
        }
        if (payload && typeof payload === "object") {
          setEvents((prev) => [...prev.slice(-39), payload]);
        }
      } catch {
        // Ignore malformed socket messages
      }
    };
    return () => ws.close();
  }, [liveStreamEnabled]);

  const loadSummary = useCallback(() => {
    api
      .get("/dashboard/summary")
      .then((r) => {
        setSummary(r.data);
        setStats(r.data.mitre_heatmap || []);
        setLastRefreshAt(nowUtcIso());
      })
      .catch(() => {
        setSummary({
          approvals_pending: 0,
          executions_total: 0,
          cases_total: 0,
          cases_open: 0,
          scheduled_total: 0,
          scheduled_enabled: 0,
          mitre_heatmap: [],
        });
        setStats([]);
      });
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  const loadIntegration = useCallback(() => {
    getIntegrationStatus()
      .then((r) => {
        setIntegration(r.data);
      })
      .catch(() => {
        setIntegration({
          wazuh_manager: { ok: false },
          indexer: { ok: false },
        });
      });
  }, []);

  useEffect(() => {
    loadIntegration();
  }, [loadIntegration]);

  const loadQueue = useCallback((silent = false) => {
    if (!silent) {
      setQueueLoading(true);
    }
    Promise.all([getAlerts("", 12), api.get("/cases"), api.get("/approvals/pending"), api.get("/approvals/executions")])
      .then(([alertsRes, casesRes, approvalsRes, executionsRes]) => {
        setRecentAlerts(normalizeAlerts(alertsRes.data).sort(byNewestAlert).slice(0, 12));
        setRecentCases((casesRes.data || []).slice(0, 10));
        setPendingApprovals((approvalsRes.data || []).slice(0, 10));
        setRecentExecutions((executionsRes.data || []).slice(0, 12));
      })
      .catch(() => {
        setRecentAlerts([]);
        setRecentCases([]);
        setPendingApprovals([]);
        setRecentExecutions([]);
      })
      .finally(() => {
        if (!silent) {
          setQueueLoading(false);
        }
      });
  }, []);

  useEffect(() => {
    loadQueue();
  }, [loadQueue]);

  const parsedApprovals = useMemo(() => pendingApprovals.map((row) => approvalRow(row)), [pendingApprovals]);
  const parsedCases = useMemo(() => recentCases.map((row) => caseRow(row)), [recentCases]);
  const parsedExecutions = useMemo(() => recentExecutions.map((row) => executionRow(row)), [recentExecutions]);

  const totalTactics = stats.length;
  const totalAlerts = stats.reduce((acc, row) => acc + Number(row[1] || 0), 0);
  const managerError = integration.wazuh_manager?.error;
  const indexerError = integration.indexer?.error;

  const mitreRows = useMemo(() => {
    if (!stats.length) return [];
    return [...stats].sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0)).slice(0, 10);
  }, [stats]);

  const mitreBarRows = useMemo(() => {
    if (!mitreRows.length) return [];
    const max = Math.max(...mitreRows.map((row) => Number(row[1] || 0)), 1);
    return mitreRows.map((row) => ({
      label: row[0],
      count: Number(row[1] || 0),
      width: Math.max(6, Math.round((Number(row[1] || 0) / max) * 100)),
    }));
  }, [mitreRows]);

  const alertLevelSummary = useMemo(() => {
    const bucket = { critical: 0, high: 0, medium: 0, low: 0 };
    recentAlerts.forEach((alert) => {
      const level = Number(alert.level);
      if (Number.isNaN(level)) return;
      if (level >= 12) bucket.critical += 1;
      else if (level >= 10) bucket.high += 1;
      else if (level >= 7) bucket.medium += 1;
      else bucket.low += 1;
    });
    return bucket;
  }, [recentAlerts]);

  const severityRows = useMemo(() => {
    const rows = [
      { label: "Critical", value: alertLevelSummary.critical, cls: "danger" },
      { label: "High", value: alertLevelSummary.high, cls: "warn" },
      { label: "Medium", value: alertLevelSummary.medium, cls: "" },
      { label: "Low", value: alertLevelSummary.low, cls: "success" },
    ];
    const max = Math.max(...rows.map((r) => r.value), 1);
    return rows.map((row) => ({
      ...row,
      width: Math.max(6, Math.round((row.value / max) * 100)),
    }));
  }, [alertLevelSummary]);

  const runningCount = useMemo(
    () =>
      parsedExecutions.filter((row) =>
        ["RUNNING", "PAUSED", "PENDING", "QUEUED"].includes(String(row.status || "").toUpperCase())
      ).length,
    [parsedExecutions]
  );
  const failedCount = useMemo(
    () => parsedExecutions.filter((row) => ["FAILED", "ERROR", "KILLED"].includes(String(row.status || "").toUpperCase())).length,
    [parsedExecutions]
  );
  const highPriorityAlerts = alertLevelSummary.critical + alertLevelSummary.high;
  const integrationsOnline = Number(Boolean(integration.wazuh_manager.ok)) + Number(Boolean(integration.indexer.ok));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Operations Command Board</h2>
          <p className="muted">
            Active SOC picture for triage, approvals, and response. Last sync {formatWazuhTimestamp(lastRefreshAt)} (
            {APP_TIMEZONE_LABEL}).
          </p>
        </div>
        <div className="page-actions">
          <button
            className="btn secondary"
            onClick={() => {
              loadSummary();
              loadQueue();
              loadIntegration();
            }}
          >
            Refresh Board
          </button>
          <button className="btn secondary" onClick={() => navigate("/alerts")}>
            Open Alert Queue
          </button>
          <button className="btn secondary" onClick={() => navigate("/approvals")}>
            Review Approvals
          </button>
          <button className="btn" onClick={() => navigate("/executions")}>
            Monitor Runs
          </button>
        </div>
      </div>

      <div className="mission-grid">
        <button className="mission-card" onClick={() => navigate("/alerts")} type="button">
          <div className="mission-label">Priority Alerts</div>
          <div className="mission-value">{highPriorityAlerts}</div>
          <div className="mission-meta">Critical + high severity items</div>
        </button>
        <button className="mission-card" onClick={() => navigate("/approvals")} type="button">
          <div className="mission-label">Pending Approvals</div>
          <div className="mission-value">{summary.approvals_pending}</div>
          <div className="mission-meta">Analyst decisions required</div>
        </button>
        <button className="mission-card" onClick={() => navigate("/executions")} type="button">
          <div className="mission-label">Runs In Progress</div>
          <div className="mission-value">{runningCount}</div>
          <div className="mission-meta">{failedCount} failed in current queue</div>
        </button>
        <button className="mission-card" onClick={() => navigate("/cases")} type="button">
          <div className="mission-label">Open Cases</div>
          <div className="mission-value">{summary.cases_open}</div>
          <div className="mission-meta">{summary.cases_total} total investigations</div>
        </button>
        <div className="mission-card">
          <div className="mission-label">Platform Health</div>
          <div className="mission-value">
            {integrationsOnline}/2
          </div>
          <div className="mission-meta">Manager + indexer integrations online</div>
        </div>
      </div>

      <div className="split-view">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Alert Triage Queue</h3>
              <p className="muted">Newest detection events requiring analyst triage.</p>
            </div>
            <button className="btn secondary" onClick={() => navigate("/alerts")}>
              Full Queue
            </button>
          </div>
          {queueLoading ? (
            <div className="empty-state">Loading alert queue...</div>
          ) : recentAlerts.length === 0 ? (
            <div className="empty-state">No alerts in queue.</div>
          ) : (
            <div className="table-scroll">
              <table className="table compact readable">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Rule</th>
                    <th>Agent</th>
                    <th>Severity</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.map((alert) => (
                    <tr key={alert.id} className="clickable" onClick={() => navigate(`/alerts?query=${encodeURIComponent(alert.id)}`)}>
                      <td>{alert.id}</td>
                      <td>{alert.rule}</td>
                      <td>{alert.agentName}</td>
                      <td>
                        <span className={`status-pill ${severityClass(alert.level)}`}>{alert.level}</span>
                      </td>
                      <td>{formatWazuhTimestamp(alert.timestampRaw)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="panel-stack">
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Approval Workbench</h3>
                <p className="muted">Authorization backlog and reviewer progress.</p>
              </div>
              <button className="btn secondary" onClick={() => navigate("/approvals")}>
                Open
              </button>
            </div>
            {queueLoading ? (
              <div className="empty-state">Loading approvals...</div>
            ) : parsedApprovals.length === 0 ? (
              <div className="empty-state">No approvals pending.</div>
            ) : (
              <div className="table-scroll">
                <table className="table compact readable">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Action</th>
                      <th>Agent</th>
                      <th>Votes</th>
                      <th>Submitted</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parsedApprovals.map((item) => (
                      <tr key={item.id} className="clickable" onClick={() => navigate("/approvals")}>
                        <td>{item.id}</td>
                        <td>{item.action}</td>
                        <td>{item.agent}</td>
                        <td>
                          {item.approved}/{item.required}
                        </td>
                        <td>{formatWazuhTimestamp(item.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <h3>Execution Activity</h3>
                <p className="muted">Latest automation outcomes and active run states.</p>
              </div>
              <button className="btn secondary" onClick={() => navigate("/executions")}>
                Open
              </button>
            </div>
            {queueLoading ? (
              <div className="empty-state">Loading executions...</div>
            ) : parsedExecutions.length === 0 ? (
              <div className="empty-state">No recent executions.</div>
            ) : (
              <div className="table-scroll">
                <table className="table compact readable">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Agent</th>
                      <th>Action</th>
                      <th>Status</th>
                      <th>Started</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parsedExecutions.map((item) => (
                      <tr key={item.id} className="clickable" onClick={() => navigate("/executions")}>
                        <td>{item.id}</td>
                        <td>{item.agent}</td>
                        <td>{item.action}</td>
                        <td>
                          <span className={`status-pill ${executionTone(item.status)}`}>{item.status}</span>
                        </td>
                        <td>{formatWazuhTimestamp(item.startedAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Threat Landscape</h3>
              <p className="muted">Severity distribution and ATT&CK tactic concentration.</p>
            </div>
            <button className="btn secondary" onClick={() => navigate("/analytics")}>
              Open Analytics
            </button>
          </div>
          <div className="chart-grid">
            <div className="muted">Severity mix (current queue)</div>
            <div className="bar-chart">
              {severityRows.map((row) => (
                <div key={row.label} className="bar-row">
                  <span className="bar-label">{row.label}</span>
                  <div className="bar-track">
                    <div className={`bar-fill ${row.cls}`} style={{ width: `${row.width}%` }} />
                  </div>
                  <span className="bar-value">{row.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="chart-grid mt-12">
            <div className="muted">Top MITRE tactics ({totalTactics} tactics, {totalAlerts} matches)</div>
            {!mitreBarRows.length ? (
              <div className="empty-state">No MITRE data in current horizon.</div>
            ) : (
              <div className="bar-chart">
                {mitreBarRows.map((row, index) => (
                  <div key={`${row.label}-${index}`} className="bar-row">
                    <span className="bar-label">{row.label}</span>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${row.width}%` }} />
                    </div>
                    <span className="bar-value">{row.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Live Telemetry Stream</h3>
              <p className="muted">Realtime alert events from the socket feed.</p>
            </div>
            <button className="btn secondary" onClick={() => setLiveStreamEnabled((prev) => !prev)}>
              {liveStreamEnabled ? "Pause Stream" : "Enable Stream"}
            </button>
          </div>
          {events.length === 0 ? (
            <div className="empty-state">No streamed events yet.</div>
          ) : (
            <div className="list-scroll tall">
              <ul className="list">
                {events.map((evt, idx) => {
                  const info = formatEvent(evt);
                  return (
                    <li key={`${info.title}-${idx}`} className="list-item">
                      <div>{info.title}</div>
                      <div className="meta-line">
                        {info.agent} | level {info.level} | {info.time}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Integration & Governance Health</h3>
            <p className="muted">Core pipeline status and governance workflow handoff.</p>
          </div>
          <div className="page-actions">
            <button className="btn secondary" onClick={() => navigate("/audit")}>
              Audit Log
            </button>
            <button className="btn secondary" onClick={() => navigate("/changes")}>
              Change Control
            </button>
            <button className="btn" onClick={() => navigate("/cases")}>
              Case Desk
            </button>
          </div>
        </div>
        <div className="grid-3">
          <div className="list-item readable">
            <div className="muted">Wazuh Manager</div>
            <div className={`status-pill ${integration.wazuh_manager.ok ? "success" : "failed"}`}>
              {integration.wazuh_manager.ok ? "Connected" : "Offline"}
            </div>
            {integration.wazuh_manager.source ? <div className="meta-line">Check: {integration.wazuh_manager.source}</div> : null}
            {managerError ? <div className="meta-line">Error: {managerError}</div> : null}
          </div>
          <div className="list-item readable">
            <div className="muted">Indexer</div>
            <div className={`status-pill ${integration.indexer.ok ? "success" : "failed"}`}>
              {integration.indexer.ok ? integration.indexer.status || "Connected" : "Offline"}
            </div>
            {integration.indexer.cluster ? <div className="meta-line">Cluster: {integration.indexer.cluster}</div> : null}
            {indexerError ? <div className="meta-line">Error: {indexerError}</div> : null}
          </div>
          <div className="list-item readable">
            <div className="muted">Workflow Totals</div>
            <div className="meta-line">Scheduled playbooks: {summary.scheduled_enabled}/{summary.scheduled_total}</div>
            <div className="meta-line">Recent case entries: {parsedCases.length}</div>
            <div className="meta-line">Approvals pending: {summary.approvals_pending}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

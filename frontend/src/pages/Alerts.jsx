import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { getAgents, getAlerts } from "../api/wazuh";
import IOCPanel from "../components/IOCPanel";
import MitrePanel from "../components/MitrePanel";
import Pager from "../components/Pager";
import RelativeTimestamp from "../components/RelativeTimestamp";
import { parseWazuhTimestamp } from "../utils/time";

const pickAlertId = (alert) => {
  const raw = alert?.id ?? alert?.alert_id;
  if (raw === null || raw === undefined) return "";
  if (typeof raw === "object") return "";
  return String(raw).trim();
};

const normalizeAgents = (data) => {
  const items = Array.isArray(data) ? data : data?.data?.affected_items || data?.affected_items || data?.items || [];
  return (Array.isArray(items) ? items : []).map((agent) => ({
    id: String(agent?.id || agent?.agent_id || "").padStart(3, "0"),
    name: agent?.name || agent?.hostname || agent?.id || agent?.agent_id || "unknown",
  }));
};

const normalizeAlerts = (data) => {
  let items = [];
  if (Array.isArray(data)) items = data;
  else if (data?.data?.affected_items) items = data.data.affected_items;
  else if (data?.affected_items) items = data.affected_items;
  else if (data?.data?.items) items = data.data.items;
  else if (data?.items) items = data.items;

  const out = [];
  (Array.isArray(items) ? items : []).forEach((alert) => {
    const id = pickAlertId(alert);
    if (!id) return;
    const rule = alert?.rule || {};
    const agent = alert?.agent || {};
    const decoder = alert?.decoder || {};
    const manager = alert?.manager || {};
    const groups = rule?.groups;
    out.push({
      id,
      ruleId: rule?.id || "",
      rule: rule?.description || rule?.id || alert?.message || "Alert",
      groups: Array.isArray(groups) ? groups.filter(Boolean).join(", ") : "",
      level: rule?.level ?? rule?.severity ?? alert?.level ?? "n/a",
      agentName: agent?.name || agent?.hostname || agent?.id || alert?.agent || "unknown",
      agentId: agent?.id || alert?.agent_id || "",
      agentIp: agent?.ip || agent?.ip_address || "",
      decoder: decoder?.name || "",
      location: alert?.location || "",
      manager: manager?.name || manager?.node || "",
      fullLog: alert?.full_log || alert?.log || "",
      timestampRaw: alert?.timestamp || alert?.time || alert?.["@timestamp"] || alert?.date || "",
      raw: alert,
    });
  });
  return out;
};

const byNewestAlert = (left, right) => {
  const l = parseWazuhTimestamp(left?.timestampRaw)?.getTime() || 0;
  const r = parseWazuhTimestamp(right?.timestampRaw)?.getTime() || 0;
  return r - l;
};

const severityClass = (level) => {
  const num = Number(level);
  if (Number.isNaN(num)) return "neutral";
  if (num >= 12) return "failed";
  if (num >= 7) return "pending";
  return "success";
};

const severityBucket = (level) => {
  const num = Number(level);
  if (Number.isNaN(num)) return "unknown";
  if (num >= 12) return "critical";
  if (num >= 10) return "high";
  if (num >= 7) return "medium";
  return "low";
};

export default function Alerts() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const queryParam = searchParams.get("query") || "";

  const [query, setQuery] = useState(queryParam);
  const [agentFilter, setAgentFilter] = useState("");
  const [agentOnly, setAgentOnly] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("all");

  const [agents, setAgents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [queuePage, setQueuePage] = useState(1);
  const [queuePageSize, setQueuePageSize] = useState(50);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadAlerts = (q, options = {}, { silent = false } = {}) => {
    if (!silent) setLoading(true);
    getAlerts(q, 250, options)
      .then((alertsRes) => {
        const items = normalizeAlerts(alertsRes.data).sort(byNewestAlert);
        setAlerts(items);
        setSelectedId((current) => {
          if (!items.length) return "";
          if (current && items.some((item) => item.id === current)) return current;
          return items[0].id;
        });
        setError(null);
      })
      .catch((err) => {
        setAlerts([]);
        setSelectedId("");
        setError(err.response?.data?.detail || err.message || "Failed to load alerts");
      })
      .finally(() => {
        if (!silent) setLoading(false);
      });
  };

  useEffect(() => {
    getAgents(undefined, { limit: 5000 })
      .then((res) => {
        const mapped = normalizeAgents(res.data);
        const deduped = [];
        const seen = new Set();
        mapped.forEach((agent) => {
          if (!agent.id || seen.has(agent.id)) return;
          seen.add(agent.id);
          deduped.push(agent);
        });
        setAgents(deduped);
      })
      .catch(() => setAgents([]));
  }, []);

  useEffect(() => {
    setQuery(queryParam);
    loadAlerts(queryParam, {
      agentId: agentFilter || undefined,
      agentOnly,
    });
  }, [queryParam, agentFilter, agentOnly]);

  const triageSummary = useMemo(() => {
    const bucket = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    alerts.forEach((alert) => {
      bucket[severityBucket(alert.level)] += 1;
    });
    return bucket;
  }, [alerts]);

  const filteredAlerts = useMemo(() => {
    if (severityFilter === "all") return alerts;
    return alerts.filter((alert) => severityBucket(alert.level) === severityFilter);
  }, [alerts, severityFilter]);

  const selected = useMemo(() => {
    if (!filteredAlerts.length) return null;
    return filteredAlerts.find((a) => a.id === selectedId) || filteredAlerts[0];
  }, [filteredAlerts, selectedId]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / queuePageSize));
    if (queuePage > totalPages) {
      setQueuePage(totalPages);
    }
  }, [filteredAlerts.length, queuePage, queuePageSize]);

  useEffect(() => {
    setQueuePage(1);
  }, [severityFilter]);

  const pagedAlerts = useMemo(() => {
    const start = (queuePage - 1) * queuePageSize;
    return filteredAlerts.slice(start, start + queuePageSize);
  }, [filteredAlerts, queuePage, queuePageSize]);

  return (
    <div className="page page-route-alerts">
      <div className="page-header">
        <div>
          <h2>Alert Triage Cockpit</h2>
          <p className="muted">Investigate detections, pivot context, and hand off response actions.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={() => loadAlerts(query, { agentId: agentFilter || undefined, agentOnly, force: true })}>
            Refresh Feed
          </button>
          <button className="btn secondary" onClick={() => navigate("/approvals")}>
            Approval Queue
          </button>
          <button className="btn" onClick={() => navigate("/cases")}>
            Case Desk
          </button>
        </div>
      </div>
      <div className="ticketing-kpi-grid">
        <div className="ticketing-kpi">
          <div className="ticketing-kpi-label">Total Alerts</div>
          <div className="ticketing-kpi-value">{alerts.length}</div>
          <div className="ticketing-kpi-meta">Current filtered queue</div>
        </div>
        <div className="ticketing-kpi">
          <div className="ticketing-kpi-label">Critical</div>
          <div className="ticketing-kpi-value">{triageSummary.critical}</div>
          <div className="ticketing-kpi-meta">Immediate analyst attention</div>
        </div>
        <div className="ticketing-kpi">
          <div className="ticketing-kpi-label">High</div>
          <div className="ticketing-kpi-value">{triageSummary.high}</div>
          <div className="ticketing-kpi-meta">Potential incident escalation</div>
        </div>
        <div className="ticketing-kpi">
          <div className="ticketing-kpi-label">Medium / Low</div>
          <div className="ticketing-kpi-value">{triageSummary.medium + triageSummary.low}</div>
          <div className="ticketing-kpi-meta">Backlog and noise review</div>
        </div>
      </div>

      {loading ? <div className="empty-state">Loading alerts...</div> : null}
      {!loading && error ? <div className="empty-state">Error: {error}</div> : null}

      <div className="ticketing-layout">
        <div className="ticketing-main">
          <div className="card ticketing-table-card">
            <div className="card-header">
              <div>
                <h3>Detection Queue</h3>
                <p className="muted">Sorted by newest event timestamp.</p>
              </div>
              <div className="ticketing-tabs">
                {[
                  { id: "all", label: "All" },
                  { id: "critical", label: "Critical" },
                  { id: "high", label: "High" },
                  { id: "medium", label: "Medium" },
                  { id: "low", label: "Low" },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    className={`ticketing-tab${severityFilter === tab.id ? " active" : ""}`}
                    onClick={() => setSeverityFilter(tab.id)}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="ticketing-filters">
              <input
                className="input"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search by alert ID, rule, agent, IOC, or IP..."
              />
              <select className="input" value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)}>
                <option value="">All agents</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name} ({agent.id})
                  </option>
                ))}
              </select>
              <label className="chip clickable">
                <input
                  type="checkbox"
                  checked={agentOnly}
                  onChange={(e) => setAgentOnly(e.target.checked)}
                  className="mr-6"
                />
                Agent Alerts Only
              </label>
              <button className="btn secondary" onClick={() => setSearchParams(query ? { query } : {})}>
                Apply Search
              </button>
              <button
                className="btn secondary"
                onClick={() => {
                  setQuery("");
                  setSearchParams({});
                }}
              >
                Clear
              </button>
            </div>

            <div className="table-scroll ticketing-table-scroll">
              <table className="table readable">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>
                      <span className="column-guide">
                        Severity
                        <span className="column-guide-popover">
                          Wazuh severity maps to rule level. Higher values signal faster escalation and response urgency.
                        </span>
                      </span>
                    </th>
                    <th className="alerts-col-rule">Rule</th>
                    <th className="alerts-col-agent">Agent</th>
                    <th>
                      <span className="column-guide">
                        Groups
                        <span className="column-guide-popover">
                          Groups show the rule families attached to the alert so we can separate real signal from noisy control categories.
                        </span>
                      </span>
                    </th>
                    <th className="alerts-col-time">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAlerts.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="text-center">
                        No alerts found.
                      </td>
                    </tr>
                  ) : (
                    pagedAlerts.map((alert) => (
                      <tr
                        key={alert.id}
                        onClick={() => {
                          setSelectedId(alert.id);
                        }}
                        className={`clickable ${selected?.id === alert.id ? "selected" : ""}`}
                      >
                        <td>{alert.id}</td>
                        <td>
                          <span className={`status-pill ${severityClass(alert.level)}`}>{alert.level}</span>
                        </td>
                        <td className="alerts-col-rule">
                          <span className="table-wrap-cell">{alert.rule}</span>
                        </td>
                        <td className="alerts-col-agent">
                          <span className="table-wrap-cell">{alert.agentName}</span>
                        </td>
                        <td className="alerts-col-groups">
                          <span className="table-wrap-cell">{alert.groups || "-"}</span>
                        </td>
                        <td className="alerts-col-time"><RelativeTimestamp value={alert.timestampRaw} /></td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            <Pager
              total={filteredAlerts.length}
              page={queuePage}
              pageSize={queuePageSize}
              onPageChange={setQueuePage}
              onPageSizeChange={(size) => {
                setQueuePageSize(size);
                setQueuePage(1);
              }}
              pageSizeOptions={[25, 50, 100]}
              label="alerts"
            />
          </div>
        </div>

        <aside className="card ticketing-details">
          {selected ? (
            <>
              <div className="ticketing-detail-header">
                <div>
                  <h3>Alert {selected.id}</h3>
                  <p className="muted">{selected.rule} | {selected.agentName}</p>
                </div>
                <div className="ticketing-detail-actions">
                  <button className="btn secondary" onClick={() => navigate(`/alerts?query=${encodeURIComponent(selected.id)}`)}>
                    Pin Alert
                  </button>
                  <button className="btn secondary" onClick={() => navigate("/approvals")}>
                    Request Approval
                  </button>
                  <button className="btn" onClick={() => navigate("/cases")}>
                    Open Case Desk
                  </button>
                </div>
              </div>

              <div className="kv-grid">
                <div className="kv-row">
                  <span className="kv-key">Alert ID</span>
                  <span className="kv-value">{selected.id}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Severity</span>
                  <span className="kv-value">
                    <span className={`status-pill ${severityClass(selected.level)}`}>Level {selected.level}</span>
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Timestamp</span>
                  <span className="kv-value"><RelativeTimestamp value={selected.timestampRaw} /></span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Agent</span>
                  <span className="kv-value">
                    {selected.agentName} ({selected.agentId || "-"}) {selected.agentIp ? `| ${selected.agentIp}` : ""}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Rule</span>
                  <span className="kv-value">
                    {selected.rule} {selected.ruleId ? `(${selected.ruleId})` : ""}
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Decoder</span>
                  <span className="kv-value">{selected.decoder || "-"}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Location</span>
                  <span className="kv-value">{selected.location || "-"}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Manager</span>
                  <span className="kv-value">{selected.manager || "-"}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key">Groups</span>
                  <span className="kv-value">{selected.groups || "-"}</span>
                </div>
              </div>

              <details className="ticketing-detail-section" open>
                <summary>Event Log</summary>
                <pre className="code-block">{selected.fullLog ? String(selected.fullLog) : "No full_log field on this alert."}</pre>
              </details>
              <details className="ticketing-detail-section">
                <summary>Indicators of Compromise</summary>
                <IOCPanel alertId={selected.id} />
              </details>
              <details className="ticketing-detail-section">
                <summary>MITRE Mapping</summary>
                <MitrePanel alertId={selected.id} />
              </details>
              <details className="ticketing-detail-section">
                <summary>Raw Alert JSON</summary>
                <pre className="code-block">{JSON.stringify(selected.raw, null, 2)}</pre>
              </details>
            </>
          ) : (
            <div className="empty-state">Select an alert to inspect its full context.</div>
          )}
        </aside>
      </div>
    </div>
  );
}


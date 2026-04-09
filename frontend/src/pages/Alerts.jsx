import { useEffect, useMemo, useRef, useState } from "react";
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

const toIsoUtcString = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return "";
  return parsed.toISOString();
};

const emptySeveritySummary = () => ({
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  unknown: 0,
});

const toNonNegativeInt = (value, fallback = 0) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.trunc(parsed) : fallback;
};

const summarizeAlerts = (items, totalHint = 0) => {
  const summary = emptySeveritySummary();
  (Array.isArray(items) ? items : []).forEach((alert) => {
    summary[severityBucket(alert?.level)] += 1;
  });
  summary.total = Math.max(toNonNegativeInt(totalHint, 0), summary.critical + summary.high + summary.medium + summary.low + summary.unknown);
  if (summary.total > summary.critical + summary.high + summary.medium + summary.low + summary.unknown) {
    summary.unknown += summary.total - (summary.critical + summary.high + summary.medium + summary.low + summary.unknown);
  }
  return summary;
};

const normalizeServerSummary = (rawSummary, fallbackSummary) => {
  if (!rawSummary || typeof rawSummary !== "object") return fallbackSummary;
  const normalized = {
    total: toNonNegativeInt(rawSummary.total, fallbackSummary.total),
    critical: toNonNegativeInt(rawSummary.critical, fallbackSummary.critical),
    high: toNonNegativeInt(rawSummary.high, fallbackSummary.high),
    medium: toNonNegativeInt(rawSummary.medium, fallbackSummary.medium),
    low: toNonNegativeInt(rawSummary.low, fallbackSummary.low),
    unknown: toNonNegativeInt(rawSummary.unknown, fallbackSummary.unknown),
  };
  const known = normalized.critical + normalized.high + normalized.medium + normalized.low + normalized.unknown;
  if (normalized.total < known) normalized.total = known;
  if (normalized.total > known) normalized.unknown += (normalized.total - known);
  return normalized;
};

export default function Alerts() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const queryParam = searchParams.get("query") || "";
  const startParam = searchParams.get("start") || "";
  const endParam = searchParams.get("end") || "";

  const [query, setQuery] = useState(queryParam);
  const [startTime, setStartTime] = useState(startParam);
  const [endTime, setEndTime] = useState(endParam);
  const [agentFilter, setAgentFilter] = useState("");
  const [agentOnly, setAgentOnly] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("all");

  const [agents, setAgents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [severitySummary, setSeveritySummary] = useState(() => emptySeveritySummary());
  const [selectedId, setSelectedId] = useState("");
  const [detailMode, setDetailMode] = useState(false);
  const [queuePage, setQueuePage] = useState(1);
  const [queuePageSize, setQueuePageSize] = useState(50);
  const tableScrollRef = useRef(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadAlerts = (q, options = {}, { silent = false } = {}) => {
    if (!silent) setLoading(true);
    const opts = options && typeof options === "object" ? options : {};
    const start = String(opts.start || "").trim();
    const end = String(opts.end || "").trim();
    const deepSearch = Boolean(String(q || "").trim() || start || end);
    const resolvedLimit = Number.isFinite(Number(opts.limit)) && Number(opts.limit) > 0
      ? Number(opts.limit)
      : deepSearch
        ? 20000
        : 1000;
    getAlerts(q, resolvedLimit, { ...opts, includeTotal: true, includeSummary: true })
      .then((alertsRes) => {
        const payload = alertsRes?.data;
        const itemsRaw = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.items)
            ? payload.items
            : [];
        const totalValue = Number(payload?.total);
        const items = normalizeAlerts(itemsRaw).sort(byNewestAlert);
        const hintedTotal = Number.isFinite(totalValue) && totalValue >= 0 ? totalValue : items.length;
        const fallbackSummary = summarizeAlerts(items, hintedTotal);
        const nextSummary = normalizeServerSummary(payload?.summary, fallbackSummary);
        setTotalAlerts(nextSummary.total);
        setSeveritySummary(nextSummary);
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
        setTotalAlerts(0);
        setSeveritySummary(emptySeveritySummary());
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
    setStartTime(startParam);
    setEndTime(endParam);
    loadAlerts(queryParam, {
      agentId: agentFilter || undefined,
      agentOnly,
      start: toIsoUtcString(startParam) || undefined,
      end: toIsoUtcString(endParam) || undefined,
    });
  }, [queryParam, startParam, endParam, agentFilter, agentOnly]);

  const filteredAlerts = useMemo(() => {
    if (severityFilter === "all") return alerts;
    return alerts.filter((alert) => severityBucket(alert.level) === severityFilter);
  }, [alerts, severityFilter]);

  const selected = useMemo(() => {
    if (!filteredAlerts.length) return null;
    return filteredAlerts.find((a) => a.id === selectedId) || filteredAlerts[0];
  }, [filteredAlerts, selectedId]);

  useEffect(() => {
    if (!selected) setDetailMode(false);
  }, [selected]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / queuePageSize));
    if (queuePage > totalPages) {
      setQueuePage(totalPages);
    }
  }, [filteredAlerts.length, queuePage, queuePageSize]);

  useEffect(() => {
    setQueuePage(1);
  }, [severityFilter]);

  useEffect(() => {
    const node = tableScrollRef.current;
    if (!node) return;
    node.scrollLeft = 0;
  }, [agentFilter, agentOnly, detailMode, filteredAlerts.length, queuePage, queuePageSize, severityFilter]);

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
          <button
            className="btn secondary"
            onClick={() =>
              loadAlerts(query, {
                agentId: agentFilter || undefined,
                agentOnly,
                start: toIsoUtcString(startTime) || undefined,
                end: toIsoUtcString(endTime) || undefined,
                force: true,
              })}
          >
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
          <div className="ticketing-kpi-value">{totalAlerts}</div>
          <div className="ticketing-kpi-meta">Total matches for current search scope</div>
        </div>
        <div className="ticketing-kpi">
          <div className="ticketing-kpi-label">Critical</div>
          <div className="ticketing-kpi-value">{severitySummary.critical}</div>
          <div className="ticketing-kpi-meta">Immediate analyst attention</div>
        </div>
        <div className="ticketing-kpi">
          <div className="ticketing-kpi-label">High</div>
          <div className="ticketing-kpi-value">{severitySummary.high}</div>
          <div className="ticketing-kpi-meta">Potential incident escalation</div>
        </div>
        <div className="ticketing-kpi">
          <div className="ticketing-kpi-label">Medium / Low</div>
          <div className="ticketing-kpi-value">{severitySummary.medium + severitySummary.low}</div>
          <div className="ticketing-kpi-meta">Backlog and noise review</div>
        </div>
      </div>

      {loading ? <div className="empty-state">Loading alerts...</div> : null}
      {!loading && error ? <div className="empty-state">Error: {error}</div> : null}

      {detailMode && selected ? (
        <div className="card ticketing-detail-full">
          <div className="ticketing-detail-header">
            <div>
              <h3>Alert {selected.id}</h3>
              <p className="muted">{selected.rule} | {selected.agentName}</p>
            </div>
            <div className="ticketing-detail-actions">
              <button className="btn secondary" onClick={() => setDetailMode(false)}>
                Back to Queue
              </button>
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
        </div>
      ) : (
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
            <input
              className="input"
              type="datetime-local"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              title="Start time"
            />
            <input
              className="input"
              type="datetime-local"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              title="End time"
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
            <button
              className="btn secondary"
              onClick={() => {
                const next = {};
                if (query.trim()) next.query = query.trim();
                if (startTime) next.start = startTime;
                if (endTime) next.end = endTime;
                setSearchParams(next);
              }}
            >
              Apply Search
            </button>
            <button
              className="btn secondary"
              onClick={() => {
                setQuery("");
                setStartTime("");
                setEndTime("");
                setSearchParams({});
              }}
            >
              Clear
            </button>
          </div>

          <div className="table-scroll ticketing-table-scroll" ref={tableScrollRef}>
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
                        setDetailMode(true);
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
      )}
    </div>
  );
}


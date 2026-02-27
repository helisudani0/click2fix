import { useEffect, useMemo, useState } from "react";
import { getAnalyticsOverview, getKillChain, getAlertSummary, getHourlyVolume } from "../api/wazuh";
import { formatWazuhTimestamp, parseWazuhTimestamp } from "../utils/time";

const statusClass = status => {
  if (status === "spike" || status === "drop") return "failed";
  if (status === "normal") return "success";
  return "neutral";
};

export default function Analytics() {
  const [overview, setOverview] = useState(null);
  const [killChain, setKillChain] = useState({ stages: {}, raw: [] });
  const [caseFilter, setCaseFilter] = useState("");
  const [alertId, setAlertId] = useState("");
  const [alertSummary, setAlertSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [hourlySeries, setHourlySeries] = useState([]);

  const refreshOverview = () => {
    setLoading(true);
    getAnalyticsOverview()
      .then(r => setOverview(r.data))
      .catch(() => setOverview(null))
      .finally(() => setLoading(false));
    getHourlyVolume(72)
      .then(r => setHourlySeries(r.data?.series || []))
      .catch(() => setHourlySeries([]));
  };

  const refreshKillChain = (caseId) => {
    getKillChain(caseId)
      .then(r => setKillChain(r.data))
      .catch(() => setKillChain({ stages: {}, raw: [] }));
  };

  useEffect(() => {
    refreshOverview();
    refreshKillChain();
    getHourlyVolume(72)
      .then(r => setHourlySeries(r.data?.series || []))
      .catch(() => setHourlySeries([]));
  }, []);

  const stageRows = useMemo(() => {
    const entries = Object.entries(killChain?.stages || {});
    return entries.sort((a, b) => b[1] - a[1]);
  }, [killChain]);

  const handleKillChainFilter = () => {
    const caseId = caseFilter.trim();
    refreshKillChain(caseId ? Number(caseId) : undefined);
  };

  const handleAlertSummary = () => {
    if (!alertId.trim()) return;
    setLoadingSummary(true);
    getAlertSummary(alertId.trim())
      .then(r => setAlertSummary(r.data))
      .catch(() => setAlertSummary({ summary: "Unable to load alert summary." }))
      .finally(() => setLoadingSummary(false));
  };

  const anomaly = overview?.anomaly;
  const normalizedHourly = useMemo(() => {
    const rows = Array.isArray(hourlySeries) ? [...hourlySeries] : [];
    const mapped = rows.map((row, idx) => ({
      hour: row?.hour || row?.ts || row?.bucket || String(idx),
      count: Number(row?.count || 0),
    }));
    mapped.sort((a, b) => {
      const left = parseWazuhTimestamp(a.hour)?.getTime() ?? 0;
      const right = parseWazuhTimestamp(b.hour)?.getTime() ?? 0;
      return left - right;
    });
    return mapped;
  }, [hourlySeries]);

  const hourlyChart = useMemo(() => {
    if (!normalizedHourly.length) return null;
    const series = normalizedHourly.slice(-72);
    const width = 920;
    const height = 160;
    const values = series.map((row) => Number(row.count || 0));
    const max = Math.max(...values, 1);
    const step = series.length > 1 ? width / (series.length - 1) : width;
    const points = values
      .map((value, idx) => {
        const x = Math.round(idx * step);
        const y = Math.round(height - (value / max) * height);
        return `${x},${y}`;
      })
      .join(" ");
    const latest = series[series.length - 1];
    const average = values.reduce((sum, value) => sum + value, 0) / values.length;
    return {
      series,
      max,
      latest,
      average: Math.round(average),
      points,
      from: series[0]?.hour,
      to: latest?.hour,
    };
  }, [normalizedHourly]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Analytics & Correlation</h2>
          <p className="muted">
            Behavioral insights, kill-chain mapping, and summarization for SOC triage.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={refreshOverview} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh Overview"}
          </button>
        </div>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Total Alerts</div>
          <div className="stat-value">{overview?.total ?? 0}</div>
          <div className="stat-sub">All stored alerts</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last 24 Hours</div>
          <div className="stat-value">{overview?.last_24h ?? 0}</div>
          <div className="stat-sub">Recent detection volume</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last 7 Days</div>
          <div className="stat-value">{overview?.last_7d ?? 0}</div>
          <div className="stat-sub">Weekly trend baseline</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Anomaly Status</div>
          <div className={`status-pill ${statusClass(anomaly?.status)}`}>
            {anomaly?.status || "no_data"}
          </div>
          <div className="stat-sub">
            {anomaly
              ? `Last hour ${anomaly.last_hour} vs mean ${anomaly.mean.toFixed(1)}`
              : "Awaiting telemetry"}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Top Rules (7d)</h3>
              <p className="muted">Most triggered detections</p>
            </div>
          </div>
          {overview?.top_rules?.length ? (
            <ul className="list">
              {overview.top_rules.map((row, idx) => (
                <li className="list-item" key={idx}>
                  <div>{row[0]}</div>
                  <div className="muted">{row[1]} hits</div>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">No rule activity yet.</div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Top Agents (7d)</h3>
              <p className="muted">Highest alert volume</p>
            </div>
          </div>
          {overview?.top_agents?.length ? (
            <ul className="list">
              {overview.top_agents.map((row, idx) => (
                <li className="list-item" key={idx}>
                  <div>{row[0]}</div>
                  <div className="muted">{row[1]} alerts</div>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">No agent activity yet.</div>
          )}
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Severity Distribution</h3>
              <p className="muted">Alert severity levels in the last 7 days</p>
            </div>
          </div>
          {overview?.severity?.length ? (
            <ul className="list">
              {overview.severity.map((row, idx) => (
                <li className="list-item" key={idx}>
                  <div>Level {row[0]}</div>
                  <div className="muted">{row[1]} alerts</div>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">No severity data yet.</div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Hourly Alert Volume</h3>
              <p className="muted">Last 72 hours of alerts</p>
            </div>
          </div>
          {hourlyChart ? (
            <>
              <div className="list-item split">
                <span>Latest hour: {hourlyChart.latest?.count || 0} alerts</span>
                <span className="chip">Peak: {hourlyChart.max}</span>
              </div>
              <div className="trend-wrap">
                <svg viewBox="0 0 920 180" width="100%" height="200" role="img" aria-label="Hourly alert volume chart">
                  <rect x="0" y="0" width="920" height="180" fill="var(--panel-soft)" stroke="var(--border)" rx="12" />
                  <polyline
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth="3"
                    points={hourlyChart.points}
                    transform="translate(0,10)"
                  />
                </svg>
                <div className="trend-legend">
                  <span>{formatWazuhTimestamp(hourlyChart.from)}</span>
                  <span>Avg {hourlyChart.average}/h</span>
                  <span>{formatWazuhTimestamp(hourlyChart.to)}</span>
                </div>
              </div>
              <div className="table-scroll">
                <table className="table compact">
                  <thead>
                    <tr>
                      <th>Hour</th>
                      <th>Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hourlyChart.series.slice().reverse().map((row, idx) => (
                      <tr key={`${row.hour}-${idx}`}>
                        <td>{formatWazuhTimestamp(row.hour)}</td>
                        <td>{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="empty-state">No hourly data yet.</div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Kill-Chain Correlation</h3>
            <p className="muted">Mapped MITRE tactics to kill-chain stages</p>
          </div>
        </div>
        <div className="page-actions mb-12">
          <input
            className="input w-240"
            placeholder="Filter by case ID (optional)"
            value={caseFilter}
            onChange={e => setCaseFilter(e.target.value)}
          />
          <button className="btn secondary" onClick={handleKillChainFilter}>
            Apply
          </button>
        </div>
        {stageRows.length ? (
          <ul className="list">
            {stageRows.map(([stage, count]) => (
              <li className="list-item" key={stage}>
                <div>{stage}</div>
                <div className="muted">{count} matches</div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="empty-state">No kill-chain data yet.</div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Alert Summary & Recommendations</h3>
            <p className="muted">Paste an alert ID to generate a SOC summary.</p>
          </div>
        </div>
        <div className="page-actions mb-12">
          <input
            className="input w-320"
            placeholder="Alert ID"
            value={alertId}
            onChange={e => setAlertId(e.target.value)}
          />
          <button className="btn" onClick={handleAlertSummary} disabled={loadingSummary}>
            {loadingSummary ? "Loading..." : "Summarize"}
          </button>
        </div>
        {!alertSummary ? (
          <div className="empty-state">No alert summary yet.</div>
        ) : (
          <div className="grid-2">
            <div>
              <div className="list">
                <div className="list-item">
                  <div>Summary</div>
                  <div className="muted">{alertSummary.summary}</div>
                </div>
                <div className="list-item">
                  <div>Root Cause</div>
                  <div className="muted">{alertSummary.root_cause || "n/a"}</div>
                </div>
                <div className="list-item">
                  <div>Agent</div>
                  <div className="muted">{alertSummary.agent || "n/a"}</div>
                </div>
                <div className="list-item">
                  <div>Rule</div>
                  <div className="muted">{alertSummary.rule || "n/a"}</div>
                </div>
                <div className="list-item">
                  <div>Primary MITRE</div>
                  <div className="muted">
                    {alertSummary.mitre?.primary
                      ? `${alertSummary.mitre.primary.tactic || "Unknown"} / ${alertSummary.mitre.primary.technique_id || alertSummary.mitre.primary.technique || "Unknown"} (confidence ${alertSummary.mitre.primary.confidence ?? 0}%)${alertSummary.mitre.primary.source ? ` via ${alertSummary.mitre.primary.source}` : ""}`
                      : "n/a"}
                  </div>
                </div>
                <div className="list-item">
                  <div>Impact</div>
                  <div className="muted">{alertSummary.impact || "n/a"}</div>
                </div>
                <div className="list-item">
                  <div>False-Positive Score</div>
                  <div className="muted">{alertSummary.false_positive_score ?? "n/a"}</div>
                </div>
              </div>
            </div>
            <div>
              <div className="list">
                <div className="list-item">
                  <div>Suggestions</div>
                  <div className="muted">
                    {(alertSummary.suggestions || []).join(", ") || "n/a"}
                  </div>
                </div>
                <div className="list-item">
                  <div>IOC Matches</div>
                  <div className="muted">
                    {alertSummary.ioc_summary?.unique_indicators ?? (alertSummary.iocs || []).length} unique
                    {alertSummary.ioc_summary?.high_confidence_indicators ? ` | ${alertSummary.ioc_summary.high_confidence_indicators} high confidence` : ""}
                  </div>
                </div>
                <div className="list-item">
                  <div>Event Time</div>
                  <div className="muted">{formatWazuhTimestamp(alertSummary.event_time) || "n/a"}</div>
                </div>
                <div className="list-item">
                  <div>Top IOC(s)</div>
                  <div className="muted">
                    {Array.isArray(alertSummary.ioc_summary?.top_indicators) && alertSummary.ioc_summary.top_indicators.length
                      ? alertSummary.ioc_summary.top_indicators
                          .slice(0, 3)
                          .map((ioc) => `${ioc.ioc || "unknown"} (${ioc.ioc_type || "unknown"}, ${ioc.score ?? 0})`)
                          .join(" | ")
                      : "n/a"}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

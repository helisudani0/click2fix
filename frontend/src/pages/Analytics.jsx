import { useEffect, useMemo, useState } from "react";
import {
  getAnalyticsOverview,
  getAnalyticsAiInsights,
  getKillChain,
  getAlertSummary,
  getHourlyVolume,
  getEventTimeSeriesV2,
  getEventCorrelationV2,
  getSystemAiConfig,
} from "../api/wazuh";
import { formatWazuhTimestamp, parseWazuhTimestamp } from "../utils/time";
import { formatApiError } from "../utils/httpErrors";

const statusClass = status => {
  if (status === "spike" || status === "drop") return "failed";
  if (status === "normal") return "success";
  return "neutral";
};

const DATA_LAYER_BUCKETS = ["5m", "15m", "1h", "6h", "1d"];

const buildIsoRange = (lookbackHours) => {
  const safeHours = Math.max(1, Number(lookbackHours || 1));
  const end = new Date();
  const start = new Date(end.getTime() - safeHours * 60 * 60 * 1000);
  return {
    start: start.toISOString(),
    end: end.toISOString(),
  };
};

const errorText = (err, fallback) => formatApiError(err, fallback);

const isNotFoundResult = (result) =>
  result?.status === "rejected" && Number(result?.reason?.response?.status || 0) === 404;

export default function Analytics() {
  const [overview, setOverview] = useState(null);
  const [killChain, setKillChain] = useState({ stages: {}, raw: [] });
  const [caseFilter, setCaseFilter] = useState("");
  const [alertId, setAlertId] = useState("");
  const [alertSummary, setAlertSummary] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [hourlySeries, setHourlySeries] = useState([]);
  const [tenantIdOverride, setTenantIdOverride] = useState("");
  const [timeSeriesBucket, setTimeSeriesBucket] = useState("1h");
  const [correlationWindow, setCorrelationWindow] = useState("15m");
  const [loadingDataLayer, setLoadingDataLayer] = useState(false);
  const [dataLayerSupported, setDataLayerSupported] = useState(true);
  const [dataLayerError, setDataLayerError] = useState("");
  const [eventTimeSeries, setEventTimeSeries] = useState([]);
  const [eventTimeSeriesTotals, setEventTimeSeriesTotals] = useState([]);
  const [eventTimeSeriesMeta, setEventTimeSeriesMeta] = useState({
    bucket: "1h",
    total_count: 0,
    total_points: 0,
  });
  const [eventCorrelationGroups, setEventCorrelationGroups] = useState([]);
  const [eventCorrelationMeta, setEventCorrelationMeta] = useState({
    window: "15m",
    total_groups: 0,
    correlated_events: 0,
  });
  const [aiInsightPrompt, setAiInsightPrompt] = useState("");
  const [loadingAiInsight, setLoadingAiInsight] = useState(false);
  const [aiInsight, setAiInsight] = useState(null);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiDisabledReason, setAiDisabledReason] = useState(
    "AI is disabled. Enable it in Org Admin / Platform AI Configuration."
  );

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

  const refreshDataLayer = () => {
    const tenantText = String(tenantIdOverride || "").trim();
    const tenantParsed = tenantText ? Number(tenantText) : undefined;
    if (tenantText && (!Number.isFinite(tenantParsed) || tenantParsed <= 0)) {
      setDataLayerError("Tenant ID must be a positive number.");
      return;
    }
    const tenantParam = tenantText ? Number(tenantParsed) : undefined;
    const seriesRange = buildIsoRange(72);
    const correlationRange = buildIsoRange(24);
    setLoadingDataLayer(true);
    setDataLayerError("");

    Promise.allSettled([
      getEventTimeSeriesV2({
        ...(tenantParam ? { tenant_id: tenantParam } : {}),
        stream: "events",
        bucket: timeSeriesBucket,
        group_by: "severity",
        start: seriesRange.start,
        end: seriesRange.end,
        limit: 3000,
      }),
      getEventCorrelationV2({
        ...(tenantParam ? { tenant_id: tenantParam } : {}),
        stream: "events",
        window: correlationWindow,
        min_group_size: 2,
        cross_domain: true,
        min_domains: 2,
        include_detections: true,
        max_groups: 20,
        start: correlationRange.start,
        end: correlationRange.end,
      }),
    ])
      .then(([seriesResult, correlationResult]) => {
        const errors = [];
        const unsupported = isNotFoundResult(seriesResult) && isNotFoundResult(correlationResult);
        if (unsupported) {
          setDataLayerSupported(false);
          setEventTimeSeries([]);
          setEventTimeSeriesTotals([]);
          setEventTimeSeriesMeta({
            bucket: timeSeriesBucket,
            total_count: 0,
            total_points: 0,
          });
          setEventCorrelationGroups([]);
          setEventCorrelationMeta({
            window: correlationWindow,
            total_groups: 0,
            correlated_events: 0,
          });
          setDataLayerError("");
          return;
        }
        setDataLayerSupported(true);

        if (seriesResult.status === "fulfilled") {
          const data = seriesResult.value?.data || {};
          setEventTimeSeries(Array.isArray(data.series) ? data.series : []);
          setEventTimeSeriesTotals(Array.isArray(data.totals) ? data.totals : []);
          setEventTimeSeriesMeta({
            bucket: data.bucket || timeSeriesBucket,
            total_count: Number(data.total_count || 0),
            total_points: Number(data.total_points || 0),
          });
        } else {
          setEventTimeSeries([]);
          setEventTimeSeriesTotals([]);
          setEventTimeSeriesMeta({
            bucket: timeSeriesBucket,
            total_count: 0,
            total_points: 0,
          });
          errors.push(errorText(seriesResult.reason, "Failed to load event time-series."));
        }

        if (correlationResult.status === "fulfilled") {
          const data = correlationResult.value?.data || {};
          setEventCorrelationGroups(Array.isArray(data.groups) ? data.groups : []);
          setEventCorrelationMeta({
            window: data.window || correlationWindow,
            total_groups: Number(data.total_groups || 0),
            correlated_events: Number(data.correlated_events || 0),
          });
        } else {
          setEventCorrelationGroups([]);
          setEventCorrelationMeta({
            window: correlationWindow,
            total_groups: 0,
            correlated_events: 0,
          });
          errors.push(errorText(correlationResult.reason, "Failed to load event correlation."));
        }

        setDataLayerError(errors.join(" "));
      })
      .finally(() => setLoadingDataLayer(false));
  };

  const refreshAiAvailability = () => {
    getSystemAiConfig()
      .then((response) => {
        const node = response?.data?.ai_config || {};
        const enabled = Boolean(node?.enabled);
        setAiEnabled(enabled);
        setAiDisabledReason(
          enabled
            ? ""
            : "AI is disabled. Enable it in Org Admin / Platform AI Configuration."
        );
      })
      .catch(() => {
        setAiEnabled(false);
        setAiDisabledReason("AI status unavailable. Configure AI in Org Admin / Platform AI Configuration.");
      });
  };

  useEffect(() => {
    refreshOverview();
    refreshKillChain();
    refreshDataLayer();
    refreshAiAvailability();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  const handleAiInsight = () => {
    if (!aiEnabled) {
      setAiInsight({
        mode: "disabled",
        summary: aiDisabledReason || "AI is disabled. Enable it in Org Admin / Platform AI Configuration.",
        priority_findings: [],
        recommended_actions: [],
      });
      return;
    }
    setLoadingAiInsight(true);
    getAnalyticsAiInsights({
      hours: 72,
      alert_id: alertId.trim() || undefined,
      prompt: aiInsightPrompt || undefined,
    })
      .then((response) => {
        setAiInsight(response?.data || null);
      })
      .catch((err) => {
        setAiInsight({
          mode: "error",
          summary: errorText(err, "Unable to generate AI insight right now."),
          priority_findings: [],
          recommended_actions: [],
        });
      })
      .finally(() => setLoadingAiInsight(false));
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
    const chartTop = 12;
    const chartHeight = 152;
    const plotBottom = chartTop + chartHeight;
    const values = series.map((row) => Number(row.count || 0));
    const max = Math.max(...values, 1);
    const step = series.length > 1 ? width / (series.length - 1) : width;
    const points = values
      .map((value, idx) => {
        const x = Math.round(idx * step);
        const y = Math.round(plotBottom - (value / max) * chartHeight);
        return `${x},${y}`;
      })
      .join(" ");
    const latest = series[series.length - 1];
    const latestValue = Number(latest?.count || 0);
    const latestX = Math.round((series.length - 1) * step);
    const latestY = Math.round(plotBottom - (latestValue / max) * chartHeight);
    const areaPoints = `${points} ${width},${plotBottom} 0,${plotBottom}`;
    const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio) => Math.round(chartTop + chartHeight * ratio));
    const average = values.reduce((sum, value) => sum + value, 0) / values.length;
    return {
      series,
      max,
      latest,
      latestX,
      latestY,
      average: Math.round(average),
      points,
      areaPoints,
      gridLines,
      from: series[0]?.hour,
      to: latest?.hour,
    };
  }, [normalizedHourly]);

  const normalizedEventSeries = useMemo(() => {
    const aggregate = new Map();
    (Array.isArray(eventTimeSeries) ? eventTimeSeries : []).forEach((row) => {
      const key = row?.bucket_start || row?.hour || row?.bucket || "";
      if (!key) return;
      const count = Number(row?.count || 0);
      aggregate.set(key, Number(aggregate.get(key) || 0) + count);
    });
    const items = Array.from(aggregate.entries()).map(([bucket, count]) => ({ bucket, count }));
    items.sort((left, right) => {
      const leftTs = parseWazuhTimestamp(left.bucket)?.getTime() ?? 0;
      const rightTs = parseWazuhTimestamp(right.bucket)?.getTime() ?? 0;
      return leftTs - rightTs;
    });
    return items;
  }, [eventTimeSeries]);

  const dataLayerChart = useMemo(() => {
    if (!normalizedEventSeries.length) return null;
    const series = normalizedEventSeries.slice(-120);
    const width = 920;
    const chartTop = 12;
    const chartHeight = 152;
    const plotBottom = chartTop + chartHeight;
    const values = series.map((row) => Number(row.count || 0));
    const max = Math.max(...values, 1);
    const step = series.length > 1 ? width / (series.length - 1) : width;
    const points = values
      .map((value, idx) => {
        const x = Math.round(idx * step);
        const y = Math.round(plotBottom - (value / max) * chartHeight);
        return `${x},${y}`;
      })
      .join(" ");
    const latest = series[series.length - 1];
    const latestValue = Number(latest?.count || 0);
    const latestX = Math.round((series.length - 1) * step);
    const latestY = Math.round(plotBottom - (latestValue / max) * chartHeight);
    const areaPoints = `${points} ${width},${plotBottom} 0,${plotBottom}`;
    const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio) => Math.round(chartTop + chartHeight * ratio));
    const average = values.reduce((sum, value) => sum + value, 0) / values.length;
    return {
      series,
      max,
      latest,
      latestX,
      latestY,
      average: Math.round(average),
      points,
      areaPoints,
      gridLines,
      from: series[0]?.bucket,
      to: latest?.bucket,
    };
  }, [normalizedEventSeries]);

  const topCorrelationGroups = useMemo(
    () => (Array.isArray(eventCorrelationGroups) ? eventCorrelationGroups.slice(0, 12) : []),
    [eventCorrelationGroups],
  );

  return (
    <div className="page page-route-analytics">
      <div className="page-header">
        <div>
          <h2>Analytics & Correlation</h2>
          <p className="muted">
            Behavioral insights, kill-chain mapping, and summarization for SOC triage.
          </p>
        </div>
        <div className="page-actions">
          <button
            className="btn secondary"
            onClick={() => {
              refreshOverview();
              refreshDataLayer();
            }}
            disabled={loading || loadingDataLayer}
          >
            {loading || loadingDataLayer ? "Refreshing..." : "Refresh Overview"}
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

      <div className="card">
        <div className="card-header">
          <div>
            <h3>AI Operational Insight</h3>
            <p className="muted">Generate a concise triage brief from analytics telemetry and optional alert context.</p>
          </div>
        </div>
        <div className="page-actions mb-12">
          <input
            className="input w-320"
            placeholder="Optional instruction (example: focus on containment)"
            value={aiInsightPrompt}
            disabled={!aiEnabled}
            onChange={(event) => setAiInsightPrompt(event.target.value)}
          />
          <button className="btn secondary" onClick={handleAiInsight} disabled={loadingAiInsight || !aiEnabled}>
            {loadingAiInsight ? "Generating..." : "Generate Insight"}
          </button>
        </div>
        <div className="meta-line mb-12">
          {aiEnabled
            ? "AI is enabled from Org Admin / Platform AI Configuration."
            : (aiDisabledReason || "AI is disabled. Enable it in Org Admin / Platform AI Configuration.")}
        </div>
        {!aiInsight ? (
          <div className="empty-state">No AI insight generated yet.</div>
        ) : (
          <div className="grid-2">
            <div className="list">
              <div className="list-item">
                <div>Mode</div>
                <div className="muted">{aiInsight.mode || "unknown"}</div>
              </div>
              <div className="list-item">
                <div>Summary</div>
                <div className="muted">{aiInsight.summary || "n/a"}</div>
              </div>
              {aiInsight.reason ? (
                <div className="list-item">
                  <div>Note</div>
                  <div className="muted">{aiInsight.reason}</div>
                </div>
              ) : null}
            </div>
            <div className="list">
              <div className="list-item">
                <div>Priority Findings</div>
                <div className="muted">
                  {Array.isArray(aiInsight.priority_findings) && aiInsight.priority_findings.length
                    ? aiInsight.priority_findings.join(" | ")
                    : "n/a"}
                </div>
              </div>
              <div className="list-item">
                <div>Recommended Actions</div>
                <div className="muted">
                  {Array.isArray(aiInsight.recommended_actions) && aiInsight.recommended_actions.length
                    ? aiInsight.recommended_actions
                        .map((item) => {
                          const action = item?.action || item?.name || "";
                          const reason = item?.reason || "";
                          return reason ? `${action} (${reason})` : action;
                        })
                        .filter(Boolean)
                        .join(" | ")
                    : "n/a"}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {dataLayerSupported ? (
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Data Layer Time-Series</h3>
              <p className="muted">Indexed event buckets for short-window detection analytics.</p>
            </div>
          </div>

          <div className="page-actions mb-12">
            <input
              className="input w-240"
              placeholder="Tenant ID (optional)"
              value={tenantIdOverride}
              onChange={(event) => setTenantIdOverride(event.target.value)}
            />
            <select
              className="input w-240"
              value={timeSeriesBucket}
              onChange={(event) => setTimeSeriesBucket(event.target.value)}
            >
              {DATA_LAYER_BUCKETS.map((bucket) => (
                <option key={bucket} value={bucket}>{bucket}</option>
              ))}
            </select>
            <button className="btn secondary" onClick={refreshDataLayer} disabled={loadingDataLayer}>
              {loadingDataLayer ? "Loading..." : "Refresh Data Layer"}
            </button>
          </div>

          {dataLayerError ? <div className="empty-state mb-12">{dataLayerError}</div> : null}

          <div className="list">
            <div className="list-item split">
              <span>Total Events (72h)</span>
              <span className="chip">{eventTimeSeriesMeta.total_count || 0}</span>
            </div>
            <div className="list-item split">
              <span>Series Points</span>
              <span className="muted">{eventTimeSeriesMeta.total_points || 0}</span>
            </div>
            <div className="list-item split">
              <span>Bucket Size</span>
              <span className="muted">{eventTimeSeriesMeta.bucket || timeSeriesBucket}</span>
            </div>
          </div>

          {dataLayerChart ? (
            <>
              <div className="list-item split mt-12">
                <span>Latest bucket: {dataLayerChart.latest?.count || 0} events</span>
                <span className="chip">Peak: {dataLayerChart.max}</span>
              </div>
              <div className="trend-wrap">
                <svg className="trend-chart-svg" viewBox="0 0 920 180" width="100%" height="200" role="img" aria-label="Event data-layer time-series chart">
                  <defs>
                    <linearGradient id="dataLayerSurface" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" stopColor="rgba(34, 54, 77, 0.82)" />
                      <stop offset="100%" stopColor="rgba(9, 16, 29, 0.96)" />
                    </linearGradient>
                    <linearGradient id="dataLayerArea" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" stopColor="rgba(107, 215, 255, 0.56)" />
                      <stop offset="100%" stopColor="rgba(107, 215, 255, 0.03)" />
                    </linearGradient>
                    <linearGradient id="dataLayerLine" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#74d9ff" />
                      <stop offset="50%" stopColor="#46b8ff" />
                      <stop offset="100%" stopColor="#58f0c7" />
                    </linearGradient>
                    <linearGradient id="dataLayerLineGlow" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="rgba(116, 217, 255, 0.1)" />
                      <stop offset="50%" stopColor="rgba(70, 184, 255, 0.78)" />
                      <stop offset="100%" stopColor="rgba(88, 240, 199, 0.2)" />
                    </linearGradient>
                    <filter id="dataLayerGlow" x="-30%" y="-30%" width="160%" height="160%">
                      <feGaussianBlur stdDeviation="3.2" result="blurred" />
                      <feMerge>
                        <feMergeNode in="blurred" />
                        <feMergeNode in="SourceGraphic" />
                      </feMerge>
                    </filter>
                    <filter id="dataLayerShadow" x="-20%" y="-20%" width="140%" height="140%">
                      <feDropShadow dx="0" dy="3" stdDeviation="2.6" floodColor="rgba(4, 10, 18, 0.85)" />
                    </filter>
                  </defs>
                  <rect x="0" y="0" width="920" height="180" rx="12" fill="url(#dataLayerSurface)" stroke="rgba(118, 148, 176, 0.38)" />
                  {dataLayerChart.gridLines.map((y, idx) => (
                    <line key={`data-layer-grid-${idx}`} x1="0" y1={y} x2="920" y2={y} className="trend-grid-line" />
                  ))}
                  <polygon points={dataLayerChart.areaPoints} className="trend-area" fill="url(#dataLayerArea)" />
                  <polyline
                    className="trend-line-shadow"
                    fill="none"
                    stroke="url(#dataLayerLineGlow)"
                    strokeWidth="6"
                    points={dataLayerChart.points}
                    filter="url(#dataLayerShadow)"
                  />
                  <polyline
                    className="trend-line-main trend-line-animated"
                    fill="none"
                    stroke="url(#dataLayerLine)"
                    strokeWidth="3.2"
                    points={dataLayerChart.points}
                    filter="url(#dataLayerGlow)"
                  />
                  <circle className="trend-point-pulse" cx={dataLayerChart.latestX} cy={dataLayerChart.latestY} r="7.2" />
                  <circle className="trend-point-core" cx={dataLayerChart.latestX} cy={dataLayerChart.latestY} r="4.2" />
                </svg>
                <div className="trend-legend">
                  <span>{formatWazuhTimestamp(dataLayerChart.from)}</span>
                  <span>Avg {dataLayerChart.average}/bucket</span>
                  <span>{formatWazuhTimestamp(dataLayerChart.to)}</span>
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state mt-12">No indexed time-series data yet.</div>
          )}

          <div className="table-scroll mt-12">
            <table className="table compact">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Total</th>
                </tr>
              </thead>
              <tbody>
                {eventTimeSeriesTotals.length === 0 ? (
                  <tr>
                    <td colSpan={2} className="muted">No grouped totals.</td>
                  </tr>
                ) : (
                  eventTimeSeriesTotals.map((row, idx) => (
                    <tr key={`${row.group || "group"}-${idx}`}>
                      <td>{row.group || "unknown"}</td>
                      <td>{Number(row.count || 0)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>High-Speed Correlation</h3>
              <p className="muted">Cross-domain correlated clusters across indexed events.</p>
            </div>
          </div>

          <div className="page-actions mb-12">
            <select
              className="input w-240"
              value={correlationWindow}
              onChange={(event) => setCorrelationWindow(event.target.value)}
            >
              {DATA_LAYER_BUCKETS.map((window) => (
                <option key={window} value={window}>{window}</option>
              ))}
            </select>
            <button className="btn secondary" onClick={refreshDataLayer} disabled={loadingDataLayer}>
              {loadingDataLayer ? "Loading..." : "Refresh Correlation"}
            </button>
          </div>

          <div className="grid-3">
            <div className="list-item readable">
              <div className="muted">Window</div>
              <div className="meta-line">{eventCorrelationMeta.window || correlationWindow}</div>
            </div>
            <div className="list-item readable">
              <div className="muted">Groups</div>
              <div className="meta-line">{eventCorrelationMeta.total_groups || 0}</div>
            </div>
            <div className="list-item readable">
              <div className="muted">Correlated Events</div>
              <div className="meta-line">{eventCorrelationMeta.correlated_events || 0}</div>
            </div>
          </div>

          {topCorrelationGroups.length === 0 ? (
            <div className="empty-state mt-12">No correlated groups found for the current window.</div>
          ) : (
            <div className="table-scroll mt-12">
              <table className="table compact">
                <thead>
                  <tr>
                    <th>Window</th>
                    <th>Correlation Key</th>
                    <th>Events</th>
                    <th>Agents</th>
                    <th>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {topCorrelationGroups.map((group, idx) => (
                    <tr key={`${group.correlation_key || "key"}-${group.window_start || idx}`}>
                      <td>{formatWazuhTimestamp(group.window_start)}</td>
                      <td>{group.correlation_key || "-"}</td>
                      <td>{Number(group.event_count || 0)}</td>
                      <td>{Number(group.unique_agents || 0)}</td>
                      <td>{Number(group.score || 0)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
      ) : (
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Advanced Correlation</h3>
              <p className="muted">Data-layer correlation is disabled in this deployment.</p>
            </div>
          </div>
          <div className="empty-state">
            Core analytics is active. Advanced indexed correlation endpoints are not enabled for this v1 deployment.
          </div>
        </div>
      )}

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
                <svg className="trend-chart-svg" viewBox="0 0 920 180" width="100%" height="200" role="img" aria-label="Hourly alert volume chart">
                  <defs>
                    <linearGradient id="hourlySurface" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" stopColor="rgba(32, 52, 76, 0.84)" />
                      <stop offset="100%" stopColor="rgba(9, 15, 27, 0.97)" />
                    </linearGradient>
                    <linearGradient id="hourlyArea" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" stopColor="rgba(138, 232, 201, 0.5)" />
                      <stop offset="100%" stopColor="rgba(138, 232, 201, 0.03)" />
                    </linearGradient>
                    <linearGradient id="hourlyLine" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#8be8c9" />
                      <stop offset="55%" stopColor="#59d0f7" />
                      <stop offset="100%" stopColor="#64a7ff" />
                    </linearGradient>
                    <linearGradient id="hourlyLineGlow" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="rgba(139, 232, 201, 0.16)" />
                      <stop offset="50%" stopColor="rgba(89, 208, 247, 0.72)" />
                      <stop offset="100%" stopColor="rgba(100, 167, 255, 0.24)" />
                    </linearGradient>
                    <filter id="hourlyGlow" x="-30%" y="-30%" width="160%" height="160%">
                      <feGaussianBlur stdDeviation="3.1" result="blurred" />
                      <feMerge>
                        <feMergeNode in="blurred" />
                        <feMergeNode in="SourceGraphic" />
                      </feMerge>
                    </filter>
                    <filter id="hourlyShadow" x="-20%" y="-20%" width="140%" height="140%">
                      <feDropShadow dx="0" dy="3" stdDeviation="2.4" floodColor="rgba(3, 9, 18, 0.86)" />
                    </filter>
                  </defs>
                  <rect x="0" y="0" width="920" height="180" rx="12" fill="url(#hourlySurface)" stroke="rgba(118, 148, 176, 0.38)" />
                  {hourlyChart.gridLines.map((y, idx) => (
                    <line key={`hourly-grid-${idx}`} x1="0" y1={y} x2="920" y2={y} className="trend-grid-line" />
                  ))}
                  <polygon points={hourlyChart.areaPoints} className="trend-area" fill="url(#hourlyArea)" />
                  <polyline
                    className="trend-line-shadow"
                    fill="none"
                    stroke="url(#hourlyLineGlow)"
                    strokeWidth="6"
                    points={hourlyChart.points}
                    filter="url(#hourlyShadow)"
                  />
                  <polyline
                    className="trend-line-main trend-line-animated"
                    fill="none"
                    stroke="url(#hourlyLine)"
                    strokeWidth="3.2"
                    points={hourlyChart.points}
                    filter="url(#hourlyGlow)"
                  />
                  <circle className="trend-point-pulse" cx={hourlyChart.latestX} cy={hourlyChart.latestY} r="7.2" />
                  <circle className="trend-point-core" cx={hourlyChart.latestX} cy={hourlyChart.latestY} r="4.2" />
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


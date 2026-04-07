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
import EChartLinePanel from "../components/EChartLinePanel";
import EChart3DPanel from "../components/EChart3DPanel";

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

const formatTickTime = (raw) => {
  const parsed = parseWazuhTimestamp(raw);
  if (!parsed) return String(raw || "-");
  const day = parsed.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const time = parsed.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
  return `${day} ${time}`;
};

const buildBar3DOption = ({
  labels,
  values,
  metricLabel,
  palette = ["#73daff", "#5db9ff", "#64ffd8"],
}) => {
  if (!Array.isArray(labels) || !Array.isArray(values) || !labels.length || !values.length) return null;
  const maxValue = Math.max(...values.map((value) => Number(value || 0)), 1);
  const labelStep = Math.max(1, Math.ceil(labels.length / 8));
  return {
    animationDurationUpdate: 420,
    animationDuration: 520,
    tooltip: {
      formatter: (params) => {
        const tuple = Array.isArray(params?.value) ? params.value : [];
        const idx = Number(tuple[0] || 0);
        const val = Number(tuple[2] || 0);
        return `${labels[idx] || "bucket"}<br/>${metricLabel}: ${val}`;
      },
      backgroundColor: "rgba(6, 12, 21, 0.94)",
      borderColor: "rgba(122, 166, 201, 0.62)",
      borderWidth: 1,
      textStyle: { color: "#d7ebff" },
    },
    xAxis3D: {
      type: "category",
      data: labels,
      axisLabel: {
        color: "#8ea7c2",
        interval: 0,
        formatter: (value, idx) => (idx % labelStep === 0 ? value : ""),
      },
      axisLine: { lineStyle: { color: "rgba(124, 159, 188, 0.44)" } },
    },
    yAxis3D: {
      type: "category",
      data: [metricLabel],
      axisLabel: { show: false },
      axisLine: { lineStyle: { color: "rgba(124, 159, 188, 0.26)" } },
    },
    zAxis3D: {
      type: "value",
      min: 0,
      max: Math.max(4, Math.round(maxValue * 1.15)),
      axisLabel: { color: "#8ea7c2" },
      axisLine: { lineStyle: { color: "rgba(124, 159, 188, 0.44)" } },
      splitLine: { lineStyle: { color: "rgba(120, 159, 188, 0.16)" } },
    },
    grid3D: {
      boxWidth: Math.max(86, Math.min(152, labels.length * 2.1)),
      boxDepth: 28,
      boxHeight: 56,
      viewControl: {
        projection: "perspective",
        alpha: 23,
        beta: 28,
        panSensitivity: 0.9,
        rotateSensitivity: 1,
        zoomSensitivity: 0.65,
        autoRotate: false,
      },
      light: {
        main: { intensity: 1.05, shadow: false },
        ambient: { intensity: 0.48 },
      },
      axisPointer: {
        show: true,
        lineStyle: { color: "rgba(132, 216, 255, 0.66)" },
      },
    },
    series: [
      {
        type: "bar3D",
        shading: "lambert",
        data: values.map((value, idx) => ({
          value: [idx, 0, Number(value || 0)],
          itemStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: palette[0] },
                { offset: 0.5, color: palette[1] },
                { offset: 1, color: palette[2] },
              ],
            },
            opacity: 0.96,
          },
        })),
        label: { show: false },
        emphasis: {
          label: {
            show: true,
            distance: 2,
            formatter: (params) => `${Number(params?.value?.[2] || 0)}`,
            textStyle: { color: "#d5ebff", fontSize: 11, fontWeight: 700 },
          },
          itemStyle: {
            color: "#a0e6ff",
          },
        },
      },
    ],
  };
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
  const [threeDMode, setThreeDMode] = useState(() => {
    if (typeof window === "undefined") return false;
    const saved = window.localStorage.getItem("soar.analytics.3d");
    if (saved === null) return true;
    return saved === "1";
  });

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem("soar.analytics.3d", threeDMode ? "1" : "0");
  }, [threeDMode]);

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
    const values = series.map((row) => Number(row.count || 0));
    const max = Math.max(...values, 1);
    const latest = series[series.length - 1];
    const average = values.reduce((sum, value) => sum + value, 0) / values.length;
    return {
      series,
      max,
      latest,
      average: Math.round(average),
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
    const values = series.map((row) => Number(row.count || 0));
    const max = Math.max(...values, 1);
    const latest = series[series.length - 1];
    const average = values.reduce((sum, value) => sum + value, 0) / values.length;
    return {
      series,
      max,
      latest,
      average: Math.round(average),
      from: series[0]?.bucket,
      to: latest?.bucket,
    };
  }, [normalizedEventSeries]);

  const topCorrelationGroups = useMemo(
    () => (Array.isArray(eventCorrelationGroups) ? eventCorrelationGroups.slice(0, 12) : []),
    [eventCorrelationGroups],
  );

  const dataLayerChartOption = useMemo(() => {
    if (!dataLayerChart?.series?.length) return null;
    const labels = dataLayerChart.series.map((row) => formatTickTime(row.bucket));
    const values = dataLayerChart.series.map((row) => Number(row.count || 0));
    return {
      animationDuration: 650,
      grid: { top: 18, right: 18, bottom: 46, left: 56 },
      tooltip: {
        trigger: "axis",
        backgroundColor: "rgba(6, 12, 21, 0.94)",
        borderColor: "rgba(122, 166, 201, 0.62)",
        borderWidth: 1,
        textStyle: { color: "#d7ebff" },
        axisPointer: {
          type: "cross",
          lineStyle: { color: "rgba(121, 166, 203, 0.62)", width: 1 },
          crossStyle: { color: "rgba(121, 166, 203, 0.62)" },
          label: { backgroundColor: "rgba(7, 14, 24, 0.9)" },
        },
      },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: labels,
        axisLine: { lineStyle: { color: "rgba(109, 143, 173, 0.4)" } },
        axisLabel: { color: "#8ea7c2", fontSize: 10, hideOverlap: true },
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        splitLine: { lineStyle: { color: "rgba(108, 138, 167, 0.22)", type: "dashed" } },
        axisLabel: { color: "#8ea7c2", fontSize: 10 },
      },
      dataZoom: [
        { type: "inside", zoomOnMouseWheel: true, moveOnMouseMove: true, moveOnMouseWheel: true },
        { type: "slider", height: 14, bottom: 10, borderColor: "rgba(109, 143, 173, 0.3)", fillerColor: "rgba(66, 160, 232, 0.22)" },
      ],
      series: [
        {
          type: "line",
          smooth: 0.24,
          symbol: "circle",
          symbolSize: 6,
          showSymbol: false,
          data: values,
          lineStyle: {
            width: 3,
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 1,
              y2: 0,
              colorStops: [
                { offset: 0, color: "#74d9ff" },
                { offset: 0.5, color: "#46b8ff" },
                { offset: 1, color: "#58f0c7" },
              ],
            },
            shadowBlur: 10,
            shadowColor: "rgba(83, 203, 255, 0.52)",
          },
          itemStyle: { color: "#8ee8ff", borderColor: "#143047", borderWidth: 1 },
          emphasis: { focus: "series", scale: true },
          areaStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: "rgba(108, 215, 255, 0.45)" },
                { offset: 1, color: "rgba(108, 215, 255, 0.04)" },
              ],
            },
          },
        },
      ],
    };
  }, [dataLayerChart]);

  const hourlyChartOption = useMemo(() => {
    if (!hourlyChart?.series?.length) return null;
    const labels = hourlyChart.series.map((row) => formatTickTime(row.hour));
    const values = hourlyChart.series.map((row) => Number(row.count || 0));
    return {
      animationDuration: 650,
      grid: { top: 18, right: 18, bottom: 46, left: 56 },
      tooltip: {
        trigger: "axis",
        backgroundColor: "rgba(6, 12, 21, 0.94)",
        borderColor: "rgba(122, 166, 201, 0.62)",
        borderWidth: 1,
        textStyle: { color: "#d7ebff" },
        axisPointer: {
          type: "cross",
          lineStyle: { color: "rgba(121, 166, 203, 0.62)", width: 1 },
          crossStyle: { color: "rgba(121, 166, 203, 0.62)" },
          label: { backgroundColor: "rgba(7, 14, 24, 0.9)" },
        },
      },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: labels,
        axisLine: { lineStyle: { color: "rgba(109, 143, 173, 0.4)" } },
        axisLabel: { color: "#8ea7c2", fontSize: 10, hideOverlap: true },
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        splitLine: { lineStyle: { color: "rgba(108, 138, 167, 0.22)", type: "dashed" } },
        axisLabel: { color: "#8ea7c2", fontSize: 10 },
      },
      dataZoom: [
        { type: "inside", zoomOnMouseWheel: true, moveOnMouseMove: true, moveOnMouseWheel: true },
        { type: "slider", height: 14, bottom: 10, borderColor: "rgba(109, 143, 173, 0.3)", fillerColor: "rgba(92, 214, 182, 0.22)" },
      ],
      series: [
        {
          type: "line",
          smooth: 0.24,
          symbol: "circle",
          symbolSize: 6,
          showSymbol: false,
          data: values,
          lineStyle: {
            width: 3,
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 1,
              y2: 0,
              colorStops: [
                { offset: 0, color: "#8be8c9" },
                { offset: 0.55, color: "#59d0f7" },
                { offset: 1, color: "#64a7ff" },
              ],
            },
            shadowBlur: 10,
            shadowColor: "rgba(95, 200, 241, 0.48)",
          },
          itemStyle: { color: "#aaf6d9", borderColor: "#143047", borderWidth: 1 },
          emphasis: { focus: "series", scale: true },
          areaStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: "rgba(138, 232, 201, 0.36)" },
                { offset: 1, color: "rgba(138, 232, 201, 0.04)" },
              ],
            },
          },
        },
      ],
    };
  }, [hourlyChart]);

  const severityChart = useMemo(() => {
    const rows = Array.isArray(overview?.severity) ? overview.severity : [];
    const series = rows
      .map((row, idx) => ({
        level: Number(
          Array.isArray(row)
            ? (row[0] ?? idx)
            : (row?.level ?? idx)
        ),
        count: Number(
          Array.isArray(row)
            ? (row[1] ?? 0)
            : (row?.count ?? 0)
        ),
      }))
      .filter((row) => Number.isFinite(row.level));
    if (!series.length) return null;
    series.sort((left, right) => left.level - right.level);
    const values = series.map((row) => Number(row.count || 0));
    return {
      series,
      total: values.reduce((sum, value) => sum + value, 0),
      max: Math.max(...values, 1),
    };
  }, [overview]);

  const severityChartOption = useMemo(() => {
    if (!severityChart?.series?.length) return null;
    const labels = severityChart.series.map((row) => `L${row.level}`);
    const values = severityChart.series.map((row) => Number(row.count || 0));
    return {
      animationDuration: 600,
      grid: { top: 20, right: 18, bottom: 34, left: 56 },
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: "rgba(6, 12, 21, 0.94)",
        borderColor: "rgba(122, 166, 201, 0.62)",
        borderWidth: 1,
        textStyle: { color: "#d7ebff" },
      },
      xAxis: {
        type: "category",
        data: labels,
        axisLine: { lineStyle: { color: "rgba(109, 143, 173, 0.4)" } },
        axisLabel: { color: "#8ea7c2", fontSize: 11 },
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        axisLabel: { color: "#8ea7c2", fontSize: 10 },
        splitLine: { lineStyle: { color: "rgba(108, 138, 167, 0.22)", type: "dashed" } },
      },
      series: [
        {
          type: "bar",
          barWidth: "64%",
          data: values,
          label: {
            show: true,
            position: "top",
            color: "#cfe8ff",
            fontSize: 10,
          },
          itemStyle: {
            borderRadius: [8, 8, 4, 4],
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: "#8cedd5" },
                { offset: 0.45, color: "#5ac8ff" },
                { offset: 1, color: "#4d7dff" },
              ],
            },
            shadowBlur: 12,
            shadowColor: "rgba(88, 188, 252, 0.35)",
          },
          emphasis: {
            focus: "series",
            itemStyle: {
              shadowBlur: 16,
              shadowColor: "rgba(122, 213, 255, 0.58)",
            },
          },
        },
      ],
    };
  }, [severityChart]);

  const dataLayerChart3DOption = useMemo(() => {
    if (!dataLayerChart?.series?.length) return null;
    const labels = dataLayerChart.series.map((row) => formatTickTime(row.bucket));
    const values = dataLayerChart.series.map((row) => Number(row.count || 0));
    return buildBar3DOption({
      labels,
      values,
      metricLabel: "events",
      palette: ["#79ddff", "#59bfff", "#57f3cf"],
    });
  }, [dataLayerChart]);

  const hourlyChart3DOption = useMemo(() => {
    if (!hourlyChart?.series?.length) return null;
    const labels = hourlyChart.series.map((row) => formatTickTime(row.hour));
    const values = hourlyChart.series.map((row) => Number(row.count || 0));
    return buildBar3DOption({
      labels,
      values,
      metricLabel: "alerts",
      palette: ["#9aeccf", "#69cff6", "#6aafff"],
    });
  }, [hourlyChart]);

  const severityChart3DOption = useMemo(() => {
    if (!severityChart?.series?.length) return null;
    const labels = severityChart.series.map((row) => `L${row.level}`);
    const values = severityChart.series.map((row) => Number(row.count || 0));
    return buildBar3DOption({
      labels,
      values,
      metricLabel: "alerts",
      palette: ["#8af1da", "#65c9ff", "#4f82ff"],
    });
  }, [severityChart]);

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
            type="button"
            onClick={() => setThreeDMode((value) => !value)}
          >
            {threeDMode ? "3D Charts: ON" : "3D Charts: OFF"}
          </button>
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

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Data Layer Time-Series</h3>
              <p className="muted">Indexed event buckets for short-window detection analytics.</p>
            </div>
          </div>
          {!dataLayerSupported ? (
            <div className="empty-state">
              Data Layer Time-Series is unavailable in this environment.
              The backend indexed-event endpoints are disabled (404), so only core analytics charts are shown.
            </div>
          ) : (
            <>
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
                    {threeDMode ? (
                      <EChart3DPanel option={dataLayerChart3DOption} style={{ width: "100%", height: 260 }} loading={loadingDataLayer} />
                    ) : (
                      <EChartLinePanel option={dataLayerChartOption} style={{ width: "100%", height: 260 }} loading={loadingDataLayer} />
                    )}
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
            </>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>{dataLayerSupported ? "High-Speed Correlation" : "Advanced Correlation"}</h3>
              <p className="muted">
                {dataLayerSupported
                  ? "Cross-domain correlated clusters across indexed events."
                  : "Data-layer correlation is disabled in this deployment."}
              </p>
            </div>
          </div>
          {!dataLayerSupported ? (
            <div className="empty-state">
              Core analytics is active. Advanced indexed correlation endpoints are not enabled for this v1 deployment.
            </div>
          ) : (
            <>
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
            </>
          )}
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
          {severityChart ? (
            <>
              <div className="list-item split">
                <span>Total alerts: {severityChart.total}</span>
                <span className="chip">Peak bucket: {severityChart.max}</span>
              </div>
              <div className="trend-wrap">
                {threeDMode ? (
                  <EChart3DPanel option={severityChart3DOption} style={{ width: "100%", height: 260 }} />
                ) : (
                  <EChartLinePanel option={severityChartOption} style={{ width: "100%", height: 260 }} />
                )}
              </div>
              <div className="table-scroll">
                <table className="table compact">
                  <thead>
                    <tr>
                      <th>Level</th>
                      <th>Alerts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {severityChart.series.slice().reverse().map((row) => (
                      <tr key={`severity-${row.level}`}>
                        <td>{row.level}</td>
                        <td>{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
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
                {threeDMode ? (
                  <EChart3DPanel option={hourlyChart3DOption} style={{ width: "100%", height: 260 }} loading={loading} />
                ) : (
                  <EChartLinePanel option={hourlyChartOption} style={{ width: "100%", height: 260 }} loading={loading} />
                )}
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


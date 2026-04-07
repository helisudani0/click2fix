import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import Pager from "../components/Pager";
import {
  getAgents,
  getAgentGroups,
  getAgentDetail,
  getAgentInventory,
  getAgentVulnerabilities,
  getAgentEvents,
  getAgentMitre,
  getAgentFim,
  getAgentSca,
  getAlerts
} from "../api/wazuh";
import { formatWazuhShort, formatWazuhTimestamp, nowUtcIso, parseWazuhTimestamp } from "../utils/time";

const normalizeAgents = (data) => {
  if (Array.isArray(data)) return data;
  if (data?.data?.affected_items) return data.data.affected_items;
  if (data?.affected_items) return data.affected_items;
  if (data?.items) return data.items;
  return [];
};

const normalizeAgentDetail = (data) => {
  if (Array.isArray(data)) return data[0] || {};
  if (data?.data?.affected_items?.length) return data.data.affected_items[0];
  if (data?.affected_items?.length) return data.affected_items[0];
  return data || {};
};

const normalizeInventoryBlock = (block) => {
  if (Array.isArray(block)) return block;
  if (!block || typeof block !== "object") return [];
  if (Array.isArray(block?.data?.affected_items)) return block.data.affected_items;
  if (Array.isArray(block?.affected_items)) return block.affected_items;
  if (Array.isArray(block?.items)) return block.items;
  return [block];
};

const normalizeInventory = (payload) => {
  if (!payload || typeof payload !== "object") {
    return { hardware: [], os: [], packages: [], source: {} };
  }
  return {
    hardware: normalizeInventoryBlock(payload.hardware),
    os: normalizeInventoryBlock(payload.os),
    packages: normalizeInventoryBlock(payload.packages),
    source: payload.source && typeof payload.source === "object" ? payload.source : {},
  };
};

const normalizeAlerts = (data) => {
  let items = [];
  if (Array.isArray(data)) items = data;
  else if (data?.data?.affected_items) items = data.data.affected_items;
  else if (data?.affected_items) items = data.affected_items;
  else if (data?.data?.items) items = data.data.items;
  else if (data?.items) items = data.items;
  return items.map((alert) => {
    const rule = alert.rule || {};
    const agent = alert.agent || {};
    const alertId = [alert.id, alert.alert_id].find(
      (value) => value !== null && value !== undefined && typeof value !== "object"
    );
    const id = String(alertId || "").trim();
    if (!id) return null;
    return {
      id,
      rule: rule.description || rule.id || alert.message || "Alert",
      level: rule.level || rule.severity || alert.level || "n/a",
      timestampRaw: alert.timestamp || alert.time || alert["@timestamp"] || alert.date || "-",
      timestamp: formatWazuhTimestamp(alert.timestamp || alert.time || alert["@timestamp"] || alert.date || "-"),
      agent: agent.name || agent.id || alert.agent || "-"
    };
  }).filter(Boolean);
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

const normalizeScaResult = (value) => {
  const token = String(value || "").trim().toLowerCase().replace(/_/g, " ");
  if (["pass", "passed", "ok", "success"].includes(token)) return "passed";
  if (["fail", "failed", "error"].includes(token)) return "failed";
  if (["not applicable", "n/a", "na", "invalid"].includes(token)) return "not applicable";
  return token || "unknown";
};

const scaResultClass = (value) => {
  const result = normalizeScaResult(value);
  if (result === "passed") return "success";
  if (result === "failed") return "failed";
  if (result === "not applicable") return "pending";
  return "neutral";
};

const formatAgentId = (raw) => {
  if (raw === null || raw === undefined) return "";
  if (typeof raw === "number") return String(raw).padStart(3, "0");
  const str = String(raw);
  return /^[0-9]+$/.test(str) && str.length < 3 ? str.padStart(3, "0") : str;
};

const toDisplay = (value, fallback = "-") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) {
    const labels = value
      .map((item) => toDisplay(item, ""))
      .filter(Boolean);
    return labels.length ? labels.join(", ") : fallback;
  }
  if (typeof value === "object") {
    for (const key of ["name", "id", "value", "label", "title", "text"]) {
      if (value[key] !== null && value[key] !== undefined && typeof value[key] !== "object") {
        return String(value[key]);
      }
    }
    return fallback;
  }
  return String(value);
};

const normalizeGroupLabel = (value) => {
  if (!value) return "-";
  if (Array.isArray(value)) {
    const labels = value
      .map((group) => {
        if (typeof group === "string") return group;
        if (group && typeof group === "object") {
          return group.name || group.id || "";
        }
        return "";
      })
      .filter(Boolean);
    return labels.length ? labels.join(", ") : "-";
  }
  if (typeof value === "object") return value.name || value.id || "-";
  return String(value);
};

const toNumber = (value, fallback = 0) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
};

const formatMemoryValue = (value) => {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return toDisplay(value);
  const gib = num / (1024 ** 3);
  if (gib >= 1) return `${gib.toFixed(1)} GB`;
  const mib = num / (1024 ** 2);
  if (mib >= 1) return `${mib.toFixed(0)} MB`;
  return `${num} B`;
};

const latestTimestamp = (...values) => {
  const candidates = values
    .flat()
    .map((value) => ({ value, parsed: parseWazuhTimestamp(value) }))
    .filter((item) => item.parsed);
  if (!candidates.length) return null;
  candidates.sort((a, b) => b.parsed.getTime() - a.parsed.getTime());
  return candidates[0].value;
};

const latestKeepaliveTimestamp = (...records) => {
  const keepaliveKeys = [
    "lastKeepAlive",
    "last_keepalive",
    "last_keep_alive",
    "lastKeepAliveTime",
    "last_keepalive_time",
    "lastAlive",
    "last_alive",
  ];
  const candidates = [];
  records
    .flat()
    .forEach((record) => {
      if (!record || typeof record !== "object") return;
      keepaliveKeys.forEach((key) => {
        if (record[key]) {
          candidates.push(record[key]);
        }
      });
      if (record.status && typeof record.status === "object") {
        keepaliveKeys.forEach((key) => {
          if (record.status[key]) {
            candidates.push(record.status[key]);
          }
        });
      }
      if (record.agent && typeof record.agent === "object") {
        keepaliveKeys.forEach((key) => {
          if (record.agent[key]) {
            candidates.push(record.agent[key]);
          }
        });
        if (record.agent.status && typeof record.agent.status === "object") {
          keepaliveKeys.forEach((key) => {
            if (record.agent.status[key]) {
              candidates.push(record.agent.status[key]);
            }
          });
        }
      }
    });
  return latestTimestamp(candidates);
};

const riskClass = (risk) => {
  const value = String(risk || "").toLowerCase();
  if (value === "critical" || value === "high") return "failed";
  if (value === "medium") return "pending";
  if (value === "low") return "success";
  return "neutral";
};

export default function Agents() {
  const navigate = useNavigate();
  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState("");
  const [agentSearch, setAgentSearch] = useState("");
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [agentDetail, setAgentDetail] = useState(null);
  const [inventory, setInventory] = useState({});
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [vulnSource, setVulnSource] = useState("");
  const [vulnError, setVulnError] = useState("");
  const [eventSeries, setEventSeries] = useState([]);
  const [mitreTactics, setMitreTactics] = useState([]);
  const [fimEvents, setFimEvents] = useState([]);
  const [scaItems, setScaItems] = useState([]);
  const [scaSource, setScaSource] = useState("");
  const [scaError, setScaError] = useState("");
  const [scaPolicies, setScaPolicies] = useState([]);
  const [scaRecommendations, setScaRecommendations] = useState([]);
  const [scaTelemetry, setScaTelemetry] = useState({});
  const [scaCheckFilter, setScaCheckFilter] = useState("failed");
  const [scaCheckSearch, setScaCheckSearch] = useState("");
  const [agentAlerts, setAgentAlerts] = useState([]);
  const [detailError, setDetailError] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [agentPage, setAgentPage] = useState(1);
  const [agentPageSize, setAgentPageSize] = useState(25);
  const [compliancePage, setCompliancePage] = useState(1);
  const [compliancePageSize, setCompliancePageSize] = useState(10);
  const [scaRecommendationsPage, setScaRecommendationsPage] = useState(1);
  const [scaRecommendationsPageSize, setScaRecommendationsPageSize] = useState(10);
  const [scaChecksPage, setScaChecksPage] = useState(1);
  const [scaChecksPageSize, setScaChecksPageSize] = useState(50);
  const [vulnerabilitiesPage, setVulnerabilitiesPage] = useState(1);
  const [vulnerabilitiesPageSize, setVulnerabilitiesPageSize] = useState(25);
  const [alertsPage, setAlertsPage] = useState(1);
  const [alertsPageSize, setAlertsPageSize] = useState(25);
  const [fimPage, setFimPage] = useState(1);
  const [fimPageSize, setFimPageSize] = useState(25);

  const [error, setError] = useState(null);
  const [lastRefreshAt, setLastRefreshAt] = useState(null);
  const selectedAgentRef = useRef("");

  useEffect(() => {
    selectedAgentRef.current = selectedAgentId;
  }, [selectedAgentId]);

  useEffect(() => {
    getAgentGroups()
      .then(r => {
        const list = Array.isArray(r.data) ? r.data : [];
        const names = list
          .map((g) => g?.name || g?.group || g)
          .map((g) => (typeof g === "string" ? g : toDisplay(g, "")))
          .filter(Boolean);
        setGroups(names);
      })
      .catch(() => setGroups([]));
  }, []);

  const loadAgentList = useCallback((force = false) => {
    getAgents(selectedGroup, { force, limit: 5000 })
      .then((r) => {
        const items = normalizeAgents(r.data).filter((agent) => {
          const id = formatAgentId(agent.id || agent.agent_id || "");
          return id && id !== "000";
        });
        setAgents(items);
        const firstId = items.length ? formatAgentId(items[0].id || items[0].agent_id || "") : "";
        setSelectedAgentId((current) => {
          if (!current) return firstId;
          const hasSelected = items.some(
            (agent) => formatAgentId(agent.id || agent.agent_id || "") === current
          );
          return hasSelected ? current : firstId;
        });
        setError(null);
      })
      .catch((err) => setError(err.response?.data?.detail || err.message));
  }, [selectedGroup]);

  useEffect(() => {
    loadAgentList();
  }, [loadAgentList]);

  const loadAgentModules = useCallback((agentId, withLoading = false) => {
    if (!agentId) return;
    if (withLoading) {
      setDetailLoading(true);
    }
    Promise.allSettled([
      getAgentDetail(agentId),
      getAgentInventory(agentId, 100),
      getAgentVulnerabilities(agentId),
      getAgentEvents(agentId, 24),
      getAgentMitre(agentId),
      getAgentFim(agentId, 50),
      getAgentSca(agentId, {
        limit: 200,
        includeChecks: true,
        checksLimit: 20000,
        recommendationLimit: 40,
      }),
      getAlerts("", undefined, { agentId, agentOnly: true }),
    ])
      .then((results) => {
        if (selectedAgentRef.current !== agentId) {
          return;
        }
        const readValue = (idx, fallback = null) =>
          results[idx]?.status === "fulfilled" ? results[idx].value : fallback;
        const readError = (idx) =>
          results[idx]?.status === "rejected"
            ? (results[idx].reason?.response?.data?.detail || results[idx].reason?.message || "Request failed")
            : null;

        const detailRes = readValue(0, { data: {} });
        const inventoryRes = readValue(1, { data: {} });
        const vulnRes = readValue(2, { data: {} });
        const eventsRes = readValue(3, { data: { items: [] } });
        const mitreRes = readValue(4, { data: { tactics: [] } });
        const fimRes = readValue(5, { data: { items: [] } });
        const scaRes = readValue(6, { data: { items: [] } });
        const alertRes = readValue(7, { data: [] });

        const detail = normalizeAgentDetail(detailRes.data);
        if (detail?.id || detail?.agent_id) {
          detail.id = formatAgentId(detail.id || detail.agent_id);
        }
        setAgentDetail(detail);
        setInventory(normalizeInventory(inventoryRes.data || {}));

        const vulnItems =
          vulnRes.data?.items ||
          vulnRes.data?.data?.affected_items ||
          vulnRes.data?.affected_items ||
          vulnRes.data?.data?.items ||
          [];
        setVulnerabilities(Array.isArray(vulnItems) ? vulnItems : []);
        setVulnSource(vulnRes.data?.source || "");
        setVulnError(vulnRes.data?.error || readError(2) || "");

        setEventSeries(Array.isArray(eventsRes.data?.items) ? eventsRes.data.items : []);
        setMitreTactics(Array.isArray(mitreRes.data?.tactics) ? mitreRes.data.tactics : []);
        const fimItems = Array.isArray(fimRes.data?.items) ? fimRes.data.items : [];
        fimItems.sort((a, b) => {
          const left = parseWazuhTimestamp(a?.timestamp || a?.["@timestamp"] || a?.time)?.getTime() || 0;
          const right = parseWazuhTimestamp(b?.timestamp || b?.["@timestamp"] || b?.time)?.getTime() || 0;
          return right - left;
        });
        setFimEvents(fimItems);
        const scaPayload = scaRes.data || {};
        setScaItems(Array.isArray(scaPayload?.items) ? scaPayload.items : []);
        setScaPolicies(Array.isArray(scaPayload?.policies) ? scaPayload.policies : []);
        setScaRecommendations(Array.isArray(scaPayload?.recommendations) ? scaPayload.recommendations : []);
        setScaTelemetry(scaPayload?.telemetry_context && typeof scaPayload.telemetry_context === "object"
          ? scaPayload.telemetry_context
          : {});
        setScaSource(scaPayload?.source || "");
        setScaError(scaPayload?.error || readError(6) || "");
        setAgentAlerts(normalizeAlerts(alertRes.data).sort(byNewestAlert));

        const criticalError = readError(0) || readError(1);
        setDetailError(criticalError);
        setLastRefreshAt(nowUtcIso());
      })
      .catch((err) => {
        if (selectedAgentRef.current !== agentId) {
          return;
        }
        setDetailError(err.response?.data?.detail || err.message);
        setInventory(normalizeInventory({}));
        setEventSeries([]);
        setMitreTactics([]);
        setFimEvents([]);
        setScaItems([]);
        setScaPolicies([]);
        setScaRecommendations([]);
        setScaTelemetry({});
      })
      .finally(() => {
        if (withLoading && selectedAgentRef.current === agentId) {
          setDetailLoading(false);
        }
      });
  }, []);

  useEffect(() => {
    if (!selectedAgentId) {
      setDetailLoading(false);
      setAgentDetail(null);
      setScaItems([]);
      setScaPolicies([]);
      setScaRecommendations([]);
      setScaTelemetry({});
      return;
    }
    setDetailError(null);
    loadAgentModules(selectedAgentId, true);
  }, [selectedAgentId, loadAgentModules]);

  const filteredAgents = useMemo(() => {
    const query = agentSearch.trim().toLowerCase();
    if (!query) return agents;
    return agents.filter((a) => {
      const id = formatAgentId(a.id || a.agent_id || "");
      const name = String(a.name || a.hostname || "");
      const group = String(a.group || a.group_name || "");
      return (
        id.toLowerCase().includes(query) ||
        name.toLowerCase().includes(query) ||
        group.toLowerCase().includes(query)
      );
    });
  }, [agents, agentSearch]);

  const pagedFilteredAgents = useMemo(() => {
    const start = (Math.max(1, agentPage) - 1) * Math.max(1, agentPageSize);
    return filteredAgents.slice(start, start + Math.max(1, agentPageSize));
  }, [filteredAgents, agentPage, agentPageSize]);

  const summary = useMemo(() => {
    const fallback =
      agents.find((agent) => formatAgentId(agent.id || agent.agent_id || "") === selectedAgentId) || {};
    const detail = agentDetail && Object.keys(agentDetail).length ? agentDetail : {};
    const agent = { ...fallback, ...detail };
    const osFallback = (() => {
      const items = inventory.os || [];
      const osItem = Array.isArray(items) && items.length ? items[0] : {};
      const win = osItem.win || osItem.windows || {};
      const name =
        osItem.os?.name ||
        osItem.os_name ||
        win.os?.name ||
        win.os_name ||
        osItem.platform ||
        "";
      const version =
        osItem.os?.version ||
        osItem.os_version ||
        win.os?.version ||
        win.os_version ||
        osItem.version ||
        "";
      if (!name && !version) return "";
      return `${name} ${version}`.trim();
    })();
    const osRaw =
      agent.os?.name ||
      agent.os?.platform ||
      agent.os?.uname ||
      agent.os?.version ||
      agent.os ||
      osFallback ||
      "unknown";
    const ip =
      (typeof agent.ip === "string" ? agent.ip : agent.ip?.ip) ||
      agent.last_ip ||
      agent.register_ip ||
      "-";
    const keepalive = latestKeepaliveTimestamp(detail, fallback, agent) || "-";
    const registeredAt =
      agent.register_date ||
      agent.registration_date ||
      agent.dateAdd ||
      "-";
    const version = agent.version || agent.agent_version || "-";
    const groups =
      normalizeGroupLabel(agent.group) !== "-"
        ? normalizeGroupLabel(agent.group)
        : normalizeGroupLabel(agent.group_name) !== "-"
          ? normalizeGroupLabel(agent.group_name)
          : normalizeGroupLabel(agent.groups);
    return {
      name: toDisplay(agent.name || agent.hostname || agent.id || "Agent", "Agent"),
      status: toDisplay(agent.status, "unknown"),
      os: toDisplay(osRaw, "unknown"),
      ip: toDisplay(ip),
      lastSeen: formatWazuhTimestamp(keepalive),
      version: toDisplay(version),
      groups: toDisplay(groups),
      cluster: toDisplay(agent.node_name || agent.node || agent.cluster_node || "-"),
      registered: formatWazuhTimestamp(registeredAt),
    };
  }, [agentDetail, agents, selectedAgentId, inventory]);

  const hardware = useMemo(() => {
    const items = normalizeInventoryBlock(inventory.hardware);
    const hw = items.length ? items[0] : {};
    const win = hw.win || hw.windows || {};
    const host = typeof hw.host === "object" && hw.host ? hw.host : {};
    const hostCpu = typeof host.cpu === "object" && host.cpu ? host.cpu : {};
    const hostMem = typeof host.memory === "object" && host.memory ? host.memory : {};
    const raw = {
      cores:
        hw.cpu?.cores ||
        hw.cpu?.cores_count ||
        win.cpu?.cores ||
        win.cpu?.cores_count ||
        hostCpu.cores ||
        hw.cpu_cores ||
        hw.cores ||
        "-",
      memory:
        hw.ram?.total ||
        hw.memory?.total ||
        win.ram?.total ||
        win.memory?.total ||
        hostMem.total ||
        hw.ram_total ||
        hw.memory_total ||
        "-",
      cpu:
        hw.cpu?.name ||
        hw.cpu?.model ||
        win.cpu?.name ||
        win.cpu?.model ||
        hostCpu.name ||
        hostCpu.model ||
        (typeof host.cpu === "string" ? host.cpu : undefined) ||
        hw.cpu_name ||
        "-",
      hostname:
        hw.board?.name ||
        win.board?.name ||
        hw.hostname ||
        win.hostname ||
        host.hostname ||
        hw.node_name ||
        agentDetail?.name ||
        "-",
      serial:
        hw.board?.serial ||
        win.board?.serial ||
        host.serial_number ||
        hw.serial_number ||
        win.serial_number ||
        hw.serial ||
        "-",
    };
    return {
      cores: toDisplay(raw.cores),
      memory: formatMemoryValue(raw.memory),
      cpu: toDisplay(raw.cpu),
      hostname: toDisplay(raw.hostname),
      serial: toDisplay(raw.serial),
    };
  }, [inventory, agentDetail?.name]);

  const vulnSummary = useMemo(() => {
    const buckets = { critical: 0, high: 0, medium: 0, low: 0 };
    const pkgCounts = {};
    vulnerabilities.forEach((v) => {
      const severityRaw = String(
        v.severity ||
        v.vulnerability?.severity ||
        v.vulnerability?.cvss?.severity ||
        v.vulnerability?.score?.severity ||
        v.vulnerability?.score?.base ||
        v.vulnerability?.score?.base_score ||
        v.cvss?.severity ||
        v.cvss?.score ||
        v.score ||
        ""
      ).toLowerCase();
      if (severityRaw.includes("critical") || Number(severityRaw) >= 9) buckets.critical += 1;
      else if (severityRaw.includes("high") || Number(severityRaw) >= 7) buckets.high += 1;
      else if (severityRaw.includes("medium") || Number(severityRaw) >= 4) buckets.medium += 1;
      else if (severityRaw) buckets.low += 1;

      const pkg =
        v.package?.name ||
        v.vulnerability?.package?.name ||
        v.vulnerability?.package_name ||
        v.package_name ||
        v.name;
      if (pkg) {
        pkgCounts[pkg] = (pkgCounts[pkg] || 0) + 1;
      }
    });
    const topPackages = Object.entries(pkgCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    return { buckets, topPackages };
  }, [vulnerabilities]);

  const eventChart = useMemo(() => {
    if (!Array.isArray(eventSeries) || eventSeries.length === 0) {
      return { points: "", areaPoints: "", gridLines: [], max: 0, last: 0, latestX: 0, latestY: 0 };
    }

    const width = 560;
    const chartTop = 14;
    const chartHeight = 136;
    const plotBottom = chartTop + chartHeight;
    const values = eventSeries.map((row) => toNumber(row?.count, 0));
    const max = Math.max(...values, 1);
    const step = values.length > 1 ? width / (values.length - 1) : width;

    const points = values
      .map((count, idx) => {
        const x = Math.round(idx * step);
        const y = Math.round(plotBottom - (count / max) * chartHeight);
        return `${x},${y}`;
      })
      .join(" ");
    const last = values[values.length - 1] || 0;
    const latestX = Math.round((values.length - 1) * step);
    const latestY = Math.round(plotBottom - (last / max) * chartHeight);
    const areaPoints = `${points} ${width},${plotBottom} 0,${plotBottom}`;
    const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio) => Math.round(chartTop + chartHeight * ratio));

    return {
      points,
      areaPoints,
      gridLines,
      max,
      last,
      latestX,
      latestY,
    };
  }, [eventSeries]);

  const mitreTop = useMemo(() => {
    const rows = Array.isArray(mitreTactics) ? mitreTactics : [];
    return rows
      .map((row) => ({
        tactic: toDisplay(row?.key || row?.tactic, "Unknown"),
        count: toNumber(row?.doc_count, toNumber(row?.count, 0)),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [mitreTactics]);

  const complianceRows = useMemo(() => {
    const rows = Array.isArray(scaPolicies) && scaPolicies.length
      ? scaPolicies
      : (Array.isArray(scaItems) ? scaItems : []);
    return rows.map((row, idx) => {
      const policy =
        toDisplay(
          row?.policy_name ||
          row?.policy?.name ||
          row?.policy_name ||
          row?.name ||
          row?.policy_id,
          `Policy ${idx + 1}`
        );
      const passed =
        row?.summary?.passed ||
        row?.pass ||
        row?.passed ||
        row?.checks_passed ||
        row?.result?.pass ||
        0;
      const failed =
        row?.summary?.failed ||
        row?.fail ||
        row?.failed ||
        row?.checks_failed ||
        row?.checks_summary?.failed ||
        row?.result?.fail ||
        0;
      const notApplicable =
        row?.summary?.invalid ||
        row?.invalid ||
        row?.not_applicable ||
        row?.checks_not_applicable ||
        row?.checks_summary?.not_applicable ||
        0;
      const score =
        row?.summary?.score ||
        row?.score ||
        row?.compliance_score ||
        row?.result?.score ||
        0;
      const endScan =
        row?.scan?.end_scan ||
        row?.end_scan ||
        row?.scan_time ||
        row?.timestamp ||
        row?.["@timestamp"] ||
        null;
      return {
        id: row?.id || row?.policy_id || `${policy}-${idx}`,
        policy,
        passed: toNumber(passed, 0),
        failed: toNumber(failed, 0),
        notApplicable: toNumber(notApplicable, 0),
        score: toNumber(score, 0),
        endScan,
      };
    })
      .sort((a, b) => {
        const da = parseWazuhTimestamp(a.endScan);
        const db = parseWazuhTimestamp(b.endScan);
        return (db?.getTime() || 0) - (da?.getTime() || 0);
      });
  }, [scaItems, scaPolicies]);

  const pagedComplianceRows = useMemo(() => {
    const start = (Math.max(1, compliancePage) - 1) * Math.max(1, compliancePageSize);
    return complianceRows.slice(start, start + Math.max(1, compliancePageSize));
  }, [complianceRows, compliancePage, compliancePageSize]);

  const complianceSummary = useMemo(() => {
    if (!complianceRows.length) {
      return { passed: 0, failed: 0, notApplicable: 0, score: 0, policy: "-", endScan: null };
    }
    const latest = complianceRows[0];
    return {
      passed: toNumber(latest.passed, 0),
      failed: toNumber(latest.failed, 0),
      notApplicable: toNumber(latest.notApplicable, 0),
      score: toNumber(latest.score, 0),
      policy: latest.policy,
      endScan: latest.endScan,
    };
  }, [complianceRows]);

  const scaChecks = useMemo(() => {
    if (!Array.isArray(scaPolicies) || scaPolicies.length === 0) return [];
    const rows = [];
    scaPolicies.forEach((policy) => {
      const checks = Array.isArray(policy?.checks) ? policy.checks : [];
      checks.forEach((check, idx) => {
        rows.push({
          key: `${policy?.policy_id || policy?.policy_name || "policy"}-${check?.id || idx + 1}-${idx}`,
          policyId: policy?.policy_id || "",
          policyName: toDisplay(policy?.policy_name || policy?.name || policy?.policy_id, "Policy"),
          id: toDisplay(check?.id || check?.check_id, String(idx + 1)),
          title: toDisplay(check?.title || check?.name, `Check ${idx + 1}`),
          result: normalizeScaResult(check?.result || check?.status),
          reason: toDisplay(check?.reason, ""),
          description: toDisplay(check?.description, ""),
          remediation: toDisplay(check?.remediation, ""),
        });
      });
    });
    return rows;
  }, [scaPolicies]);

  const scaChecksSummary = useMemo(() => {
    const summary = { passed: 0, failed: 0, notApplicable: 0, unknown: 0, total: 0 };
    scaChecks.forEach((check) => {
      const result = normalizeScaResult(check?.result);
      if (result === "passed") summary.passed += 1;
      else if (result === "failed") summary.failed += 1;
      else if (result === "not applicable") summary.notApplicable += 1;
      else summary.unknown += 1;
    });
    summary.total = summary.passed + summary.failed + summary.notApplicable + summary.unknown;
    return summary;
  }, [scaChecks]);

  const filteredScaChecks = useMemo(() => {
    const filterValue = normalizeScaResult(scaCheckFilter);
    const query = String(scaCheckSearch || "").trim().toLowerCase();
    return scaChecks.filter((check) => {
      const result = normalizeScaResult(check?.result);
      if (filterValue !== "all" && result !== filterValue) return false;
      if (!query) return true;
      const haystack = [
        check?.policyName,
        check?.policyId,
        check?.id,
        check?.title,
        check?.reason,
        check?.description,
        check?.remediation,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [scaCheckFilter, scaCheckSearch, scaChecks]);

  const pagedFilteredScaChecks = useMemo(() => {
    const start = (Math.max(1, scaChecksPage) - 1) * Math.max(1, scaChecksPageSize);
    return filteredScaChecks.slice(start, start + Math.max(1, scaChecksPageSize));
  }, [filteredScaChecks, scaChecksPage, scaChecksPageSize]);

  const pagedScaRecommendations = useMemo(() => {
    const start = (Math.max(1, scaRecommendationsPage) - 1) * Math.max(1, scaRecommendationsPageSize);
    return scaRecommendations.slice(start, start + Math.max(1, scaRecommendationsPageSize));
  }, [scaRecommendations, scaRecommendationsPage, scaRecommendationsPageSize]);

  const pagedVulnerabilities = useMemo(() => {
    const start = (Math.max(1, vulnerabilitiesPage) - 1) * Math.max(1, vulnerabilitiesPageSize);
    return vulnerabilities.slice(start, start + Math.max(1, vulnerabilitiesPageSize));
  }, [vulnerabilities, vulnerabilitiesPage, vulnerabilitiesPageSize]);

  const pagedAgentAlerts = useMemo(() => {
    const start = (Math.max(1, alertsPage) - 1) * Math.max(1, alertsPageSize);
    return agentAlerts.slice(start, start + Math.max(1, alertsPageSize));
  }, [agentAlerts, alertsPage, alertsPageSize]);

  const pagedFimEvents = useMemo(() => {
    const start = (Math.max(1, fimPage) - 1) * Math.max(1, fimPageSize);
    return fimEvents.slice(start, start + Math.max(1, fimPageSize));
  }, [fimEvents, fimPage, fimPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredAgents.length / Math.max(1, agentPageSize)));
    if (agentPage > totalPages) {
      setAgentPage(totalPages);
    }
  }, [filteredAgents.length, agentPage, agentPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(complianceRows.length / Math.max(1, compliancePageSize)));
    if (compliancePage > totalPages) {
      setCompliancePage(totalPages);
    }
  }, [complianceRows.length, compliancePage, compliancePageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(scaRecommendations.length / Math.max(1, scaRecommendationsPageSize)));
    if (scaRecommendationsPage > totalPages) {
      setScaRecommendationsPage(totalPages);
    }
  }, [scaRecommendations.length, scaRecommendationsPage, scaRecommendationsPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredScaChecks.length / Math.max(1, scaChecksPageSize)));
    if (scaChecksPage > totalPages) {
      setScaChecksPage(totalPages);
    }
  }, [filteredScaChecks.length, scaChecksPage, scaChecksPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(vulnerabilities.length / Math.max(1, vulnerabilitiesPageSize)));
    if (vulnerabilitiesPage > totalPages) {
      setVulnerabilitiesPage(totalPages);
    }
  }, [vulnerabilities.length, vulnerabilitiesPage, vulnerabilitiesPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(agentAlerts.length / Math.max(1, alertsPageSize)));
    if (alertsPage > totalPages) {
      setAlertsPage(totalPages);
    }
  }, [agentAlerts.length, alertsPage, alertsPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(fimEvents.length / Math.max(1, fimPageSize)));
    if (fimPage > totalPages) {
      setFimPage(totalPages);
    }
  }, [fimEvents.length, fimPage, fimPageSize]);

  useEffect(() => {
    setAgentPage(1);
  }, [agentSearch, selectedGroup]);

  useEffect(() => {
    setCompliancePage(1);
    setScaRecommendationsPage(1);
    setScaChecksPage(1);
    setVulnerabilitiesPage(1);
    setAlertsPage(1);
    setFimPage(1);
  }, [selectedAgentId]);

  useEffect(() => {
    setScaChecksPage(1);
  }, [scaCheckFilter, scaCheckSearch]);

  return (
    <div className="page page-route-agents">
      <div className="page-header">
        <div>
          <h2>Agents</h2>
          <p className="muted">Fleet status, vulnerabilities, and telemetry.</p>
        </div>
        <div className="page-actions">
          <button
            className="btn secondary"
            onClick={() => {
              loadAgentList(true);
              if (selectedAgentId) {
                loadAgentModules(selectedAgentId, true);
              }
            }}
          >
            Refresh
          </button>
          <input
            className="input"
            value={agentSearch}
            onChange={(e) => setAgentSearch(e.target.value)}
            placeholder="Search agents"
          />
          <select
            className="input"
            value={selectedGroup}
            onChange={(e) => setSelectedGroup(e.target.value)}
          >
            <option value="">All groups</option>
            {groups.map((g) => (
              <option key={g} value={g}>{g}</option>
            ))}
          </select>
        </div>
      </div>

      {error && <div className="empty-state">{error}</div>}

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Agent Inventory</h3>
            <p className="muted">Click an agent to view details.</p>
          </div>
        </div>
        <div className="table-scroll agents-inventory-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Group</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredAgents.length === 0 ? (
                <tr>
                  <td colSpan="4" className="text-center">
                    No agents found
                  </td>
                </tr>
              ) : (
                pagedFilteredAgents.map(a => {
                  const id = formatAgentId(a.id || a.agent_id || "");
                  const name = toDisplay(a.name || a.hostname || a.id || a.agent_id || "-");
                  const groupsRaw = Array.isArray(a.groups)
                    ? a.groups
                      .map((group) =>
                        typeof group === "string"
                          ? group
                          : (group?.name || group?.id || "")
                      )
                      .filter(Boolean)
                      .join(", ")
                    : (a.group || a.group_name || "-");
                  const group = toDisplay(groupsRaw, "-");
                  const status = toDisplay(a.status, "unknown");
                  const isActive = String(status).toLowerCase() === "active";
                  return (
                    <tr
                      key={id}
                      onClick={() => setSelectedAgentId(id)}
                      className={`clickable ${selectedAgentId === id ? "selected" : ""}`}
                    >
                      <td>{id || "-"}</td>
                      <td>{name}</td>
                      <td>{group}</td>
                      <td>
                        <span className={`status-pill ${isActive ? "active" : "inactive"}`}>
                          {status}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        <Pager
          total={filteredAgents.length}
          page={agentPage}
          pageSize={agentPageSize}
          onPageChange={setAgentPage}
          onPageSizeChange={(size) => {
            setAgentPageSize(size);
            setAgentPage(1);
          }}
          pageSizeOptions={[10, 25, 50, 100]}
          label="agents"
        />
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Agent Snapshot</h3>
              <p className="muted">Live status and metadata from the Wazuh manager.</p>
            </div>
          </div>
          <div className="grid-4">
            <div className="stat-card">
              <div className="stat-label">Status</div>
              <div className="stat-value">{summary.status}</div>
              <div className="stat-sub">Agent {selectedAgentId || "-"}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">IP Address</div>
              <div className="stat-value">{summary.ip}</div>
              <div className="stat-sub">Cluster {summary.cluster}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Version</div>
              <div className="stat-value">{summary.version}</div>
              <div className="stat-sub">Groups: {summary.groups}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Last Keepalive</div>
              <div className="stat-value">{summary.lastSeen}</div>
              <div className="stat-sub">Registered {summary.registered}</div>
              <div className="meta-line">
                Last sync {formatWazuhShort(lastRefreshAt)}
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>System Inventory</h3>
              <p className="muted">Hardware and OS details from syscollector.</p>
            </div>
          </div>
          {detailLoading ? (
            <div className="empty-state">Loading agent details...</div>
          ) : detailError ? (
            <div className="empty-state">{detailError}</div>
          ) : selectedAgentId ? (
            <div className="list">
              <div className="list-item split">
                <div>
                  <strong>{summary.name}</strong>
                  <div className="meta-line">Agent ID: {selectedAgentId}</div>
                </div>
                <span className={`status-pill ${summary.status === "active" ? "active" : "inactive"}`}>
                  {summary.status}
                </span>
              </div>
              <div className="list-item">
                <div className="meta-line">OS</div>
                <div>{summary.os}</div>
              </div>
              <div className="list-item">
                <div className="meta-line">CPU</div>
                <div>{hardware.cpu}</div>
              </div>
              <div className="list-item">
                <div className="meta-line">Cores</div>
                <div>{hardware.cores}</div>
              </div>
              <div className="list-item">
                <div className="meta-line">Memory</div>
                <div>{hardware.memory}</div>
              </div>
              <div className="list-item">
                <div className="meta-line">Host Name</div>
                <div>{hardware.hostname}</div>
              </div>
              <div className="list-item">
                <div className="meta-line">Serial</div>
                <div>{hardware.serial}</div>
              </div>
            </div>
          ) : (
            <div className="empty-state">Select an agent to view details.</div>
          )}
        </div>
      </div>

      <div className="grid-3">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Events Count Evolution</h3>
              <p className="muted">Alert volume in the last 24 hours (30 min buckets).</p>
            </div>
            <button
              className="btn secondary"
              onClick={() =>
                navigate(`/alerts?query=${encodeURIComponent(`agent.id:${selectedAgentId || "*"}`)}`)
              }
            >
              Hunt
            </button>
          </div>
          {eventSeries.length === 0 ? (
            <div className="empty-state">No event histogram data available.</div>
          ) : (
            <>
	              <div className="list-item split mb-12">
	                <span>{eventChart.last} last bucket</span>
	                <span className="chip">Max bucket: {eventChart.max}</span>
	              </div>
	              <div className="trend-wrap">
	                <svg className="trend-chart-svg" viewBox="0 0 560 170" width="100%" height="180" role="img" aria-label="Events count evolution">
	                  <defs>
	                    <linearGradient id="agentEventsSurface" x1="0%" y1="0%" x2="0%" y2="100%">
	                      <stop offset="0%" stopColor="rgba(31, 52, 74, 0.84)" />
	                      <stop offset="100%" stopColor="rgba(8, 14, 26, 0.96)" />
	                    </linearGradient>
	                    <linearGradient id="agentEventsArea" x1="0%" y1="0%" x2="0%" y2="100%">
	                      <stop offset="0%" stopColor="rgba(122, 221, 255, 0.52)" />
	                      <stop offset="100%" stopColor="rgba(122, 221, 255, 0.04)" />
	                    </linearGradient>
	                    <linearGradient id="agentEventsLine" x1="0%" y1="0%" x2="100%" y2="0%">
	                      <stop offset="0%" stopColor="#7addff" />
	                      <stop offset="48%" stopColor="#49beff" />
	                      <stop offset="100%" stopColor="#72f2cf" />
	                    </linearGradient>
	                    <linearGradient id="agentEventsLineGlow" x1="0%" y1="0%" x2="100%" y2="0%">
	                      <stop offset="0%" stopColor="rgba(122, 221, 255, 0.12)" />
	                      <stop offset="55%" stopColor="rgba(73, 190, 255, 0.76)" />
	                      <stop offset="100%" stopColor="rgba(114, 242, 207, 0.2)" />
	                    </linearGradient>
	                    <filter id="agentEventsGlow" x="-30%" y="-30%" width="160%" height="160%">
	                      <feGaussianBlur stdDeviation="3" result="blurred" />
	                      <feMerge>
	                        <feMergeNode in="blurred" />
	                        <feMergeNode in="SourceGraphic" />
	                      </feMerge>
	                    </filter>
	                    <filter id="agentEventsShadow" x="-20%" y="-20%" width="140%" height="140%">
	                      <feDropShadow dx="0" dy="2.6" stdDeviation="2.2" floodColor="rgba(3, 9, 18, 0.86)" />
	                    </filter>
	                  </defs>
	                  <rect x="0" y="0" width="560" height="170" rx="10" fill="url(#agentEventsSurface)" stroke="rgba(118, 148, 176, 0.36)" />
	                  {eventChart.gridLines.map((y, idx) => (
	                    <line key={`agent-events-grid-${idx}`} x1="0" y1={y} x2="560" y2={y} className="trend-grid-line" />
	                  ))}
	                  <polygon points={eventChart.areaPoints} className="trend-area" fill="url(#agentEventsArea)" />
	                  <polyline
	                    className="trend-line-shadow"
	                    fill="none"
	                    stroke="url(#agentEventsLineGlow)"
	                    strokeWidth="6"
	                    points={eventChart.points}
	                    filter="url(#agentEventsShadow)"
	                  />
	                  <polyline
	                    className="trend-line-main trend-line-animated"
	                    fill="none"
	                    stroke="url(#agentEventsLine)"
	                    strokeWidth="3.2"
	                    points={eventChart.points}
	                    filter="url(#agentEventsGlow)"
	                  />
	                  <circle className="trend-point-pulse" cx={eventChart.latestX} cy={eventChart.latestY} r="6.6" />
	                  <circle className="trend-point-core" cx={eventChart.latestX} cy={eventChart.latestY} r="4" />
	                </svg>
	              </div>
	            </>
	          )}
	        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>MITRE ATT&CK</h3>
              <p className="muted">Top tactics for this agent.</p>
            </div>
            <button
              className="btn secondary"
              onClick={() =>
                navigate(`/alerts?query=${encodeURIComponent(`agent.id:${selectedAgentId || "*"} AND rule.mitre.id:*`)}`)
              }
            >
              Open MITRE
            </button>
          </div>
          {mitreTop.length === 0 ? (
            <div className="empty-state">No MITRE tactic data for selected time window.</div>
          ) : (
            <ul className="list">
              {mitreTop.map((item) => (
                <li
                  key={item.tactic}
                  className="list-item split clickable"
                  onClick={() =>
                    navigate(
                      `/alerts?query=${encodeURIComponent(`agent.id:${selectedAgentId || "*"} AND rule.mitre.tactic:"${item.tactic}"`)}`
                    )
                  }
                >
                  <span>{item.tactic}</span>
                  <span className="chip">{item.count}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Compliance</h3>
              <p className="muted">Latest SCA policy snapshot.</p>
            </div>
            <span className="chip">Source: {toDisplay(scaSource || "n/a")}</span>
          </div>
          {complianceRows.length === 0 ? (
            <div className="empty-state">
	              No compliance data yet.
	              {scaSource && <div className="meta-line mt-6">Source: {toDisplay(scaSource)}</div>}
	              {scaError && <div className="meta-line mt-6">Error: {toDisplay(scaError)}</div>}
	            </div>
          ) : (
            <div className="list">
              <div className="list-item split">
                <div>
                  <div>{toDisplay(complianceSummary.policy)}</div>
                  <div className="meta-line">Latest scan: {formatWazuhTimestamp(complianceSummary.endScan)}</div>
                </div>
                <span className="chip">Score {complianceSummary.score}%</span>
              </div>
              <div className="grid-4">
                <div className="stat-card">
                  <div className="stat-label">Passed</div>
                  <div className="stat-value">{complianceSummary.passed}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-label">Failed</div>
                  <div className="stat-value">{complianceSummary.failed}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-label">Not Applicable</div>
                  <div className="stat-value">{complianceSummary.notApplicable}</div>
                </div>
                <div className="stat-card">
                  <div className="stat-label">Policies</div>
                  <div className="stat-value">{complianceRows.length}</div>
                </div>
              </div>
              <div className="table-scroll">
                <table className="table compact">
                  <thead>
                    <tr>
                      <th>Policy</th>
                      <th>End scan</th>
                      <th>Passed</th>
                      <th>Failed</th>
                      <th>Not applicable</th>
                      <th>Score</th>
                    </tr>
	                  </thead>
	                  <tbody>
	                    {pagedComplianceRows.map((row) => (
	                      <tr key={row.id}>
	                        <td>{row.policy}</td>
	                        <td>{formatWazuhTimestamp(row.endScan)}</td>
	                        <td>{row.passed}</td>
	                        <td>{row.failed}</td>
                        <td>{row.notApplicable}</td>
                        <td>{row.score}%</td>
                      </tr>
                    ))}
	                  </tbody>
	                </table>
	              </div>
              <Pager
                total={complianceRows.length}
                page={compliancePage}
                pageSize={compliancePageSize}
                onPageChange={setCompliancePage}
                onPageSizeChange={(size) => {
                  setCompliancePageSize(size);
                  setCompliancePage(1);
                }}
                pageSizeOptions={[10, 25, 50]}
                label="policies"
              />
	            </div>
	          )}
	        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>SCA Hardening Priorities</h3>
              <p className="muted">Failed checks ranked from this agent's alerts, vulnerabilities, FIM, and MITRE context.</p>
            </div>
            <span className="chip">Top {scaRecommendations.length}</span>
          </div>
          <div className="grid-4 mb-12">
            <div className="stat-card">
              <div className="stat-label">High Alerts</div>
              <div className="stat-value">{toNumber(scaTelemetry?.alerts_high, 0)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Critical Vulns</div>
              <div className="stat-value">{toNumber(scaTelemetry?.vulnerabilities_critical, 0)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">FIM Events</div>
              <div className="stat-value">{toNumber(scaTelemetry?.fim_events, 0)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Failed Checks</div>
              <div className="stat-value">{scaChecksSummary.failed}</div>
            </div>
          </div>
	          {scaRecommendations.length === 0 ? (
	            <div className="empty-state">No ranked failed checks available for this agent yet.</div>
	          ) : (
	            <div className="list">
	              {pagedScaRecommendations.map((rec) => (
	                <div key={`${rec.policy_id || rec.policy_name}-${rec.check_id}-${rec.rank}`} className="list-item">
	                  <div className="list-item split">
                    <div>
                      <strong>
                        #{toDisplay(rec.rank)} | {toDisplay(rec.policy_name)} | Check {toDisplay(rec.check_id)}
                      </strong>
                      <div className="meta-line">{toDisplay(rec.title)}</div>
                    </div>
                    <span className={`status-pill ${riskClass(rec.priority)}`}>
                      {toDisplay(rec.priority)}
                    </span>
                  </div>
                  <div className="meta-line mt-6">{toDisplay(rec.reason)}</div>
                  {rec.remediation && (
                    <div className="meta-line mt-6">
                      Remediation: {toDisplay(rec.remediation)}
                    </div>
	                  )}
	                </div>
	              ))}
              <Pager
                total={scaRecommendations.length}
                page={scaRecommendationsPage}
                pageSize={scaRecommendationsPageSize}
                onPageChange={setScaRecommendationsPage}
                onPageSizeChange={(size) => {
                  setScaRecommendationsPageSize(size);
                  setScaRecommendationsPage(1);
                }}
                pageSizeOptions={[5, 10, 25, 50]}
                label="recommendations"
              />
	            </div>
	          )}
	        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Full SCA Checks</h3>
              <p className="muted">All checks from all policy snapshots for this agent.</p>
            </div>
            <span className="chip">Total {scaChecksSummary.total}</span>
          </div>
          <div className="page-actions mb-12">
            <select
              className="input"
              value={scaCheckFilter}
              onChange={(e) => setScaCheckFilter(e.target.value)}
            >
              <option value="failed">Failed only</option>
              <option value="passed">Passed only</option>
              <option value="not applicable">Not applicable</option>
              <option value="unknown">Unknown</option>
              <option value="all">All</option>
            </select>
            <input
              className="input"
              value={scaCheckSearch}
              onChange={(e) => setScaCheckSearch(e.target.value)}
              placeholder="Search check ID, title, remediation, policy"
            />
          </div>
          <div className="grid-4 mb-12">
            <div className="stat-card">
              <div className="stat-label">Passed</div>
              <div className="stat-value">{scaChecksSummary.passed}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Failed</div>
              <div className="stat-value">{scaChecksSummary.failed}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Not Applicable</div>
              <div className="stat-value">{scaChecksSummary.notApplicable}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Unknown</div>
              <div className="stat-value">{scaChecksSummary.unknown}</div>
            </div>
          </div>
          <div className="table-scroll">
            <table className="table compact">
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Check</th>
                  <th>Result</th>
                  <th>Title</th>
                  <th>Reason</th>
                  <th>Remediation</th>
                </tr>
              </thead>
              <tbody>
	                {filteredScaChecks.length === 0 ? (
	                  <tr>
	                    <td colSpan="6" className="text-center">
	                      No checks match this filter.
	                    </td>
	                  </tr>
	                ) : (
	                  pagedFilteredScaChecks.map((check) => (
	                    <tr key={check.key}>
	                      <td>{toDisplay(check.policyName)}</td>
	                      <td>{toDisplay(check.id)}</td>
                      <td>
                        <span className={`status-pill ${scaResultClass(check.result)}`}>
                          {toDisplay(check.result)}
                        </span>
                      </td>
                      <td>{toDisplay(check.title)}</td>
                      <td>{toDisplay(check.reason, "-")}</td>
                      <td>{toDisplay(check.remediation, "-")}</td>
                    </tr>
	                  ))
	                )}
	              </tbody>
	            </table>
	          </div>
            <Pager
              total={filteredScaChecks.length}
              page={scaChecksPage}
              pageSize={scaChecksPageSize}
              onPageChange={setScaChecksPage}
              onPageSizeChange={(size) => {
                setScaChecksPageSize(size);
                setScaChecksPage(1);
              }}
              pageSizeOptions={[25, 50, 100, 200]}
              label="checks"
            />
	        </div>
	      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Vulnerability Detection</h3>
              <p className="muted">Severity summary and top affected packages.</p>
            </div>
            <span className="chip">Source: {toDisplay(vulnSource || "n/a")}</span>
          </div>
	          <div className="grid-4 mb-12">
            <div className="stat-card">
              <div className="stat-label">Critical</div>
              <div className="stat-value">{vulnSummary.buckets.critical}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">High</div>
              <div className="stat-value">{vulnSummary.buckets.high}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Medium</div>
              <div className="stat-value">{vulnSummary.buckets.medium}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Low</div>
              <div className="stat-value">{vulnSummary.buckets.low}</div>
            </div>
          </div>
	          <div className="list mb-12">
	            {vulnSummary.topPackages.length === 0 ? (
	              <div className="empty-state">
	                Vulnerability data not available. Confirm indexer access and vulnerability index name.
	                {vulnSource && <div className="meta-line mt-6">Source: {toDisplay(vulnSource)}</div>}
	                {vulnError && <div className="meta-line mt-6">Error: {toDisplay(vulnError)}</div>}
	              </div>
	            ) : (
              vulnSummary.topPackages.map(([pkg, count]) => (
                <div key={pkg} className="list-item split">
                  <div>{pkg}</div>
                  <span className="chip">{count}</span>
                </div>
              ))
            )}
          </div>
          <div className="table-scroll">
            <table className="table compact">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>Package</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
	                {vulnerabilities.length === 0 ? (
	                  <tr>
		                    <td colSpan="4" className="text-center">
		                      No vulnerabilities reported (or module disabled).
		                    </td>
	                  </tr>
	                ) : (
	                  pagedVulnerabilities.map((vuln, idx) => {
	                    const vulnInfo = vuln.vulnerability || {};
                    const cve =
                      vulnInfo.id ||
                      vulnInfo.cve ||
                      vuln.cve ||
                      vuln.id ||
                      vuln.name ||
                      "-";
                    const severity =
                      vulnInfo.severity ||
                      vuln.severity ||
                      vulnInfo.cvss?.severity ||
                      vulnInfo.score?.severity ||
                      vulnInfo.score?.base ||
                      vulnInfo.score?.base_score ||
                      vuln.cvss?.score ||
                      vuln.score ||
                      "-";
                    const pkg =
                      vuln.package?.name ||
                      vulnInfo.package?.name ||
                      vulnInfo.package_name ||
                      vuln.package_name ||
                      vuln.name ||
                      "-";
                    const status =
                      vulnInfo.status ||
                      vuln.status ||
                      vulnInfo.state ||
                      vuln.state ||
                      "-";
                    return (
                      <tr key={`${cve}-${idx}`}>
                        <td>{toDisplay(cve)}</td>
                        <td>
                          <span className={`status-pill ${severityClass(severity)}`}>
                            {toDisplay(severity)}
                          </span>
                        </td>
                        <td>{toDisplay(pkg)}</td>
                        <td>{toDisplay(status)}</td>
                      </tr>
                    );
	                  })
	                )}
	              </tbody>
	            </table>
	          </div>
          <Pager
            total={vulnerabilities.length}
            page={vulnerabilitiesPage}
            pageSize={vulnerabilitiesPageSize}
            onPageChange={setVulnerabilitiesPage}
            onPageSizeChange={(size) => {
              setVulnerabilitiesPageSize(size);
              setVulnerabilitiesPage(1);
            }}
            pageSizeOptions={[10, 25, 50, 100]}
            label="vulnerabilities"
          />
	        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Recent Alerts</h3>
              <p className="muted">Latest alert activity for the selected agent.</p>
            </div>
            <button
              className="btn secondary"
              onClick={() =>
                navigate(`/alerts?query=${encodeURIComponent(`agent.id:${selectedAgentId || "*"}`)}`)
              }
            >
              View All
            </button>
          </div>
          <div className="table-scroll">
            <table className="table compact">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
	                {agentAlerts.length === 0 ? (
	                  <tr>
		                    <td colSpan="4" className="text-center">
		                      No recent alerts for this agent.
		                    </td>
	                  </tr>
	                ) : (
	                  pagedAgentAlerts.map((alert) => (
	                    <tr
	                      key={alert.id}
                      className="clickable"
                      onClick={() => navigate(`/alerts?query=${encodeURIComponent(alert.id)}`)}
                    >
                      <td>{alert.id}</td>
                      <td>{alert.rule}</td>
                      <td>
                        <span className={`status-pill ${severityClass(alert.level)}`}>
                          {alert.level}
                        </span>
                      </td>
                      <td>{alert.timestamp}</td>
                    </tr>
	                  ))
	                )}
	              </tbody>
	            </table>
	          </div>
          <Pager
            total={agentAlerts.length}
            page={alertsPage}
            pageSize={alertsPageSize}
            onPageChange={setAlertsPage}
            onPageSizeChange={(size) => {
              setAlertsPageSize(size);
              setAlertsPage(1);
            }}
            pageSizeOptions={[10, 25, 50, 100]}
            label="alerts"
          />
	        </div>
	      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>FIM: Recent Events</h3>
            <p className="muted">File integrity monitoring events.</p>
          </div>
          <button
            className="btn secondary"
            onClick={() =>
              navigate(`/alerts?query=${encodeURIComponent(`agent.id:${selectedAgentId || "*"} AND rule.groups:syscheck`)}`)
            }
          >
            Hunt FIM
          </button>
        </div>
        <div className="table-scroll">
          <table className="table compact">
            <thead>
              <tr>
                <th>Time</th>
                <th>Path</th>
                <th>Action</th>
                <th>Rule</th>
                <th>Level</th>
              </tr>
            </thead>
            <tbody>
	              {fimEvents.length === 0 ? (
	                <tr>
		                  <td colSpan="5" className="text-center">
		                    No FIM events found for this agent.
		                  </td>
	                </tr>
	              ) : (
	                pagedFimEvents.map((evt, idx) => {
	                  const path = toDisplay(evt?.syscheck?.path || evt?.syscheck?.event || evt?.data?.path || "-");
	                  const action = toDisplay(evt?.syscheck?.event || evt?.syscheck?.action || "-");
	                  const rule = toDisplay(evt?.rule?.description || evt?.rule?.id || "-");
                  const level = toDisplay(evt?.rule?.level || "-");
                  const ts = evt?.timestamp || evt?.["@timestamp"] || evt?.time || "-";
                  return (
                    <tr key={`${ts}-${idx}`}>
                      <td>{formatWazuhTimestamp(ts)}</td>
                      <td>{path}</td>
                      <td>{action}</td>
                      <td>{rule}</td>
                      <td>{level}</td>
                    </tr>
                  );
	                })
	              )}
	            </tbody>
	          </table>
	        </div>
        <Pager
          total={fimEvents.length}
          page={fimPage}
          pageSize={fimPageSize}
          onPageChange={setFimPage}
          onPageSizeChange={(size) => {
            setFimPageSize(size);
            setFimPage(1);
          }}
          pageSizeOptions={[10, 25, 50, 100]}
          label="FIM events"
        />
	      </div>
    </div>
  );
}


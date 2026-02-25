import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import ExecutionStream from "../components/ExecutionStream";
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
  getAlerts,
  getActions,
  getActionConnectorStatus,
  requestApproval,
  runAction,
  validateAction,
  testActionCapability
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

const compactArgs = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const out = {};
  Object.entries(value).forEach(([key, v]) => {
    if (v === null || v === undefined) return;
    if (typeof v === "string" && v.trim() === "") return;
    out[key] = v;
  });
  return out;
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

const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);

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
  const [agentAlerts, setAgentAlerts] = useState([]);
  const [detailError, setDetailError] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [actions, setActions] = useState([]);
  const [actionId, setActionId] = useState("");
  const [actionInputs, setActionInputs] = useState({});
  const [targetMode, setTargetMode] = useState("agent");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [targetSearch, setTargetSearch] = useState("");
  const [excludeAgents, setExcludeAgents] = useState("");
  const [justification, setJustification] = useState("");
  const [actionStatus, setActionStatus] = useState(null);
  const [connectorStatus, setConnectorStatus] = useState(null);
  const [connectorError, setConnectorError] = useState("");
  const [error, setError] = useState(null);
  const [lastRefreshAt, setLastRefreshAt] = useState(null);
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [, setCooldownTimer] = useState(0);
  const [actionValidation, setActionValidation] = useState(null);
  const [activeExecutionId, setActiveExecutionId] = useState(null);
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

  useEffect(() => {
    getActions()
      .then(r => {
        const list = r.data || [];
        setActions(list);
        const hasHealthcheck = list.some((item) => item?.id === "endpoint-healthcheck");
        if (hasHealthcheck) {
          setActionId((current) => current || "endpoint-healthcheck");
        }
      })
      .catch(() => setActions([]));
  }, []);

  const loadConnectorStatus = useCallback(() => {
    getActionConnectorStatus()
      .then((res) => {
        setConnectorStatus(res.data || null);
        setConnectorError("");
      })
      .catch((err) => {
        setConnectorStatus(null);
        setConnectorError(err.response?.data?.detail || err.message || "Unable to load connector status");
      });
  }, []);

  useEffect(() => {
    loadConnectorStatus();
  }, [loadConnectorStatus]);

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
      getAgentSca(agentId, 5),
      getAlerts("", 50, { agentId, agentOnly: true }),
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
        setScaItems(Array.isArray(scaRes.data?.items) ? scaRes.data.items : []);
        setScaSource(scaRes.data?.source || "");
        setScaError(scaRes.data?.error || readError(6) || "");
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
      return;
    }
    setDetailError(null);
    loadAgentModules(selectedAgentId, true);
  }, [selectedAgentId, loadAgentModules]);

  useEffect(() => {
    const action = actions.find(a => a.id === actionId);
    if (!action) {
      setActionInputs({});
      return;
    }
    const inputs = {};
    (action.inputs || []).forEach(field => {
      inputs[field.name] = "";
    });
    setActionInputs(inputs);
  }, [actionId, actions]);

  useEffect(() => {
    if (targetMode === "group") {
      setTargetValue(selectedGroup || "");
      return;
    }
    if (targetMode === "multi") {
      setTargetValue("");
      setTargetAgentIds((prev) => (prev.length ? prev : selectedAgentId ? [selectedAgentId] : []));
      return;
    }
    if (targetMode === "fleet") {
      setTargetValue("all");
      return;
    }
    setTargetValue(selectedAgentId || "");
  }, [targetMode, selectedAgentId, selectedGroup]);

  const selectedAction = actions.find(a => a.id === actionId);

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

  const targetPickList = useMemo(() => {
    const query = targetSearch.trim().toLowerCase();
    const list = agents
      .map((a) => {
        const id = formatAgentId(a.id || a.agent_id || "");
        if (!id || id === "000") return null;
        const name = String(a.name || a.hostname || id);
        const groupsRaw = a.groups || a.group || a.group_name || "-";
        const group = toDisplay(groupsRaw, "-");
        return { id, name, group };
      })
      .filter(Boolean);

    if (!query) return list;
    return list.filter((item) => {
      return (
        item.id.toLowerCase().includes(query) ||
        item.name.toLowerCase().includes(query) ||
        item.group.toLowerCase().includes(query)
      );
    });
  }, [agents, targetSearch]);

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

	  const requestAgentApproval = async () => {
	    if (!actionId) {
	      setActionStatus("Select an action.");
	      return;
	    }
	    const target = targetMode === "multi" ? targetAgentIds : (targetValue || "").trim();
	    if (targetMode !== "fleet" && ((Array.isArray(target) && target.length === 0) || (!Array.isArray(target) && !target))) {
	      setActionStatus(
	        targetMode === "group"
	          ? "Select a group target."
	          : targetMode === "multi"
	            ? "Select one or more agents."
            : "Select an agent target."
      );
      return;
    }
	    try {
	      await requestApproval({
	        ...(targetMode === "group"
	          ? { group: target }
	          : targetMode === "fleet"
	            ? { agent_id: "all" }
	            : targetMode === "multi"
	              ? { agent_ids: target }
	              : { agent_id: target }),
	        ...(((targetMode === "fleet" || targetMode === "group") && excludeAgents.trim())
	          ? {
	              exclude_agent_ids: excludeAgents
	                .split(",")
	                .map((id) => id.trim())
	                .filter(Boolean),
	            }
	          : {}),
	        action_id: actionId,
	        args: compactArgs(actionInputs),
	        justification: justification || undefined
	      });
      setActionStatus(
        targetMode === "fleet"
          ? "Approval request submitted for fleet:all."
          : targetMode === "multi"
            ? `Approval request submitted for ${target.length} agent(s).`
          : `Approval request submitted for ${targetMode}:${target}.`
      );
    } catch (err) {
      setActionStatus(err.response?.data?.detail || err.message);
    }
  };

	  const runAgentAction = async () => {
	    if (!actionId) {
	      setActionStatus("Select an action.");
	      return;
	    }
	    const target = targetMode === "multi" ? targetAgentIds : (targetValue || "").trim();
	    if (targetMode !== "fleet" && ((Array.isArray(target) && target.length === 0) || (!Array.isArray(target) && !target))) {
	      setActionStatus(
	        targetMode === "group"
	          ? "Select a group target."
	          : targetMode === "multi"
	            ? "Select one or more agents."
            : "Select an agent target."
      );
      return;
    }
    
    // Check if action is already running
    if (isActionRunning) {
      setActionStatus("Action is already running. Please wait for completion.");
      return;
    }
    
    // Validate action prerequisites
    try {
      const validationPayload = {
        action_id: actionId,
        ...(targetMode === "group"
          ? { group: target }
          : targetMode === "fleet"
            ? { agent_id: "all" }
            : targetMode === "multi"
              ? { agent_ids: target }
            : { agent_id: target }),
        args: compactArgs(actionInputs)
      };
      
      const validationResponse = await validateAction(validationPayload);
      setActionValidation(validationResponse.data);
      
      if (!validationResponse.data.is_valid) {
        setActionStatus(`Validation failed: ${validationResponse.data.errors.join(", ")}`);
        return;
      }
    } catch (validationErr) {
      setActionStatus(`Validation error: ${validationErr.response?.data?.detail || validationErr.message}`);
      return;
    }
    
    setIsActionRunning(true);
    setActionStatus("Action execution in progress...");
    
	    try {
	      const res = await runAction({
	        ...(targetMode === "group"
	          ? { group: target }
	          : targetMode === "fleet"
	            ? { agent_id: "all" }
	            : targetMode === "multi"
	              ? { agent_ids: target }
	            : { agent_id: target }),
	        action_id: actionId,
	        ...(((targetMode === "fleet" || targetMode === "group") && excludeAgents.trim())
	          ? {
	              exclude_agent_ids: excludeAgents
	                .split(",")
	                .map((id) => id.trim())
	                .filter(Boolean),
	            }
	          : {}),
	        args: compactArgs(actionInputs),
	        justification: justification || undefined
	      });
      const executionId = res?.data?.execution_id;
      if (executionId) {
        setActiveExecutionId(executionId);
      }
      setActionStatus(
        executionId
          ? targetMode === "multi"
            ? `Action execution completed for ${target.length} agent(s) (run #${executionId}).`
            : `Action execution completed for ${targetMode}:${target} (run #${executionId}).`
          : targetMode === "multi"
            ? `Action execution completed for ${target.length} agent(s).`
            : `Action execution completed for ${targetMode}:${target}.`
      );
    } catch (err) {
      setActionStatus(err.response?.data?.detail || err.message);
    } finally {
      setIsActionRunning(false);
      // Start cooldown timer
      setCooldownTimer(5);
      const timer = setInterval(() => {
        setCooldownTimer(prev => {
          if (prev <= 1) {
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
  };

  const validateConnector = async () => {
    try {
      const target = targetMode === "multi" ? targetAgentIds : (targetValue || "").trim();
      if ((Array.isArray(target) && target.length === 0) || (!Array.isArray(target) && !target && targetMode !== "fleet")) {
        setActionStatus(
          targetMode === "group"
            ? "Select a group target."
            : targetMode === "multi"
              ? "Select one or more agents."
              : "Select an agent target."
        );
        return;
      }
      const payload =
        targetMode === "group"
          ? { group: target, action_id: "endpoint-healthcheck" }
          : targetMode === "fleet"
            ? { agent_id: "all", action_id: "endpoint-healthcheck" }
            : targetMode === "multi"
              ? { agent_ids: target, action_id: "endpoint-healthcheck" }
              : { agent_id: target, action_id: "endpoint-healthcheck" };

      const res = await testActionCapability(payload);
      const mode = res?.data?.execution_mode || res?.data?.preferred_channel || "endpoint";
      const total = res?.data?.execution_result?.total || (Array.isArray(target) ? target.length : 1);
      setActionStatus(`Connector test passed in ${mode} mode for ${total || 1} target(s).`);
    } catch (err) {
      setActionStatus(err.response?.data?.detail || err.message);
    }
  };

  const testActionWorkflow = async () => {
    if (!actionId) {
      setActionStatus("Select an action.");
      return;
    }
    const target = targetMode === "multi" ? targetAgentIds : (targetValue || "").trim();
    if ((Array.isArray(target) && target.length === 0) || (!Array.isArray(target) && !target && targetMode !== "fleet")) {
      setActionStatus(
        targetMode === "group"
          ? "Select a group target."
          : targetMode === "multi"
            ? "Select one or more agents."
            : "Select an agent target."
      );
      return;
    }
    
    setActionStatus("Testing action workflow...");
    
    try {
      const payload = {
        action_id: actionId,
        ...(targetMode === "group"
          ? { group: target }
          : targetMode === "fleet"
            ? { agent_id: "all" }
            : targetMode === "multi"
              ? { agent_ids: target }
            : { agent_id: target }),
        args: compactArgs(actionInputs)
      };
      
      const res = await testActionCapability(payload);
      const data = res?.data || {};
      
      if (data.execution_status === "success") {
        setActionStatus(
          `Test completed successfully. Channel: ${data.execution_channel}, Mode: ${data.execution_mode}`
        );
      } else if (data.execution_status === "failed") {
        setActionStatus(`Test failed: ${data.execution_error || "Unknown error"}`);
      } else {
        setActionStatus(
          `Test validation ${data.validation_passed ? "passed" : "failed"}. ` +
          `Channel: ${data.preferred_channel}, Timeout: ${data.timeout_seconds}s`
        );
      }
    } catch (err) {
      setActionStatus(`Test error: ${err.response?.data?.detail || err.message}`);
    }
  };

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
      return { points: "", max: 0, last: 0 };
    }

    const width = 560;
    const height = 140;
    const values = eventSeries.map((row) => toNumber(row?.count, 0));
    const max = Math.max(...values, 1);
    const step = values.length > 1 ? width / (values.length - 1) : width;

    const points = values
      .map((count, idx) => {
        const x = idx * step;
        const y = height - (count / max) * height;
        return `${x},${y}`;
      })
      .join(" ");

    return {
      points,
      max,
      last: values[values.length - 1] || 0,
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
    const rows = Array.isArray(scaItems) ? scaItems : [];
    return rows.map((row, idx) => {
      const policy =
        toDisplay(
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
        row?.result?.fail ||
        0;
      const notApplicable =
        row?.summary?.invalid ||
        row?.invalid ||
        row?.not_applicable ||
        row?.checks_not_applicable ||
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
      })
      .slice(0, 5);
  }, [scaItems]);

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

  const recommendations = useMemo(() => {
    const names = new Set((actions || []).map((a) => a.id));
    const recs = [];
    const osValue = String(summary.os || "").toLowerCase();

    const addRec = (action, title, reason) => {
      if (!names.has(action)) return;
      if (recs.some((r) => r.action === action)) return;
      recs.push({ action, title, reason });
    };

    if (vulnSummary.buckets.critical > 0 || vulnSummary.buckets.high > 50) {
      if (osValue.includes("windows")) {
        addRec("patch-windows", "Prioritize endpoint patching", "Critical/high vulnerabilities detected.");
      } else {
        addRec("patch-linux", "Prioritize endpoint patching", "Critical/high vulnerabilities detected.");
      }
    }
    if (mitreTop.some((row) => String(row.tactic).toLowerCase().includes("defense evasion"))) {
      addRec("collect-forensics", "Collect forensic triage", "Defense Evasion activity is elevated.");
      addRec("malware-scan", "Run malware scan", "Likely stealth activity pattern in MITRE data.");
    }
    if (fimEvents.length >= 20) {
      addRec("malware-scan", "Investigate mass FIM changes", "High volume of recent file/registry changes.");
    }
    if (agentAlerts.some((alert) => Number(alert.level) >= 10)) {
      addRec("firewall-drop", "Contain high-severity source", "High-severity alerts detected for this endpoint.");
    }

    return recs.slice(0, 4);
  }, [actions, agentAlerts, fimEvents.length, mitreTop, summary.os, vulnSummary]);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Agents</h2>
          <p className="muted">Fleet status, vulnerabilities, and automated response.</p>
        </div>
        <div className="page-actions">
          <button
            className="btn secondary"
            onClick={() => {
              loadAgentList(true);
              loadConnectorStatus();
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
            <p className="muted">Click an agent to view details and run actions.</p>
          </div>
        </div>
        <div className="table-scroll">
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
                filteredAgents.map(a => {
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
                        <span className={`pill ${isActive ? "active" : "inactive"}`}>
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
                <span className={`pill ${summary.status === "active" ? "active" : "inactive"}`}>
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
              <div className="list-item">
                <div className="muted">Action</div>
                <div className="page-actions mt-8">
                  <select
                    className="input"
                    value={targetMode}
                    onChange={(e) => setTargetMode(e.target.value)}
                  >
                    <option value="agent">Selected Agent</option>
                    <option value="multi">Multiple Agents</option>
                    <option value="group">Agent Group</option>
                    <option value="fleet">All Agents (Fleet)</option>
                  </select>
                </div>
	                {targetMode === "multi" ? (
	                  <div className="mt-8">
	                    <div className="page-actions">
	                      <input
	                        className="input"
	                        value={targetSearch}
	                        onChange={(e) => setTargetSearch(e.target.value)}
	                        placeholder="Search agents to select..."
	                      />
	                      <button
	                        className="btn secondary"
	                        type="button"
	                        onClick={() => setTargetAgentIds(targetPickList.map((a) => a.id))}
	                      >
	                        Select All
	                      </button>
	                      <button
	                        className="btn secondary"
	                        type="button"
	                        onClick={() => setTargetAgentIds([])}
	                      >
	                        Clear
	                      </button>
	                    </div>
		                    <div className="meta-line mt-6">
		                      Selected: {targetAgentIds.length}
		                    </div>
		                    <div className="list-scroll mt-10 h-220">
	                      <div className="list">
	                        {targetPickList.length === 0 ? (
	                          <div className="empty-state">No agents match your search.</div>
	                        ) : (
                          targetPickList.map((agent) => {
                            const checked = targetAgentIds.includes(agent.id);
                            return (
                              <label key={`target-${agent.id}`} className="list-item clickable readable">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={(e) => {
                                    const next = e.target.checked;
                                    setTargetAgentIds((prev) => {
                                      if (next) {
                                        return prev.includes(agent.id) ? prev : [...prev, agent.id];
                                      }
                                      return prev.filter((id) => id !== agent.id);
                                    });
                                  }}
	                                  className="mr-10"
	                                />
                                {agent.name} ({agent.id}) - {agent.group}
                              </label>
                            );
                          })
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="page-actions mt-8">
                    {targetMode === "group" ? (
                      <select
                        className="input"
                        value={targetValue}
                        onChange={(e) => setTargetValue(e.target.value)}
                      >
                        <option value="">Select group</option>
                        {groups.map((g) => (
                          <option key={`group-${g}`} value={g}>{g}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        className="input"
                        value={targetValue}
                        onChange={(e) => setTargetValue(e.target.value)}
                        placeholder={targetMode === "fleet" ? "all" : "Agent ID (example: 001)"}
                        disabled={targetMode === "fleet"}
                      />
                    )}

                    {targetMode === "fleet" || targetMode === "group" ? (
                      <input
                        className="input"
                        value={excludeAgents}
                        onChange={(e) => setExcludeAgents(e.target.value)}
                        placeholder="Exclude agent IDs (comma separated)"
                      />
                    ) : null}
                  </div>
                )}
	                <select
	                  className="input mt-8"
	                  value={actionId}
	                  onChange={(e) => setActionId(e.target.value)}
	                >
                  <option value="">Select action</option>
                  {actions.map((action) => (
                    <option key={action.id} value={action.id}>
                      {toDisplay(action.label || action.id)} ({toDisplay(action.category || "response")})
                    </option>
                  ))}
                </select>
	                {selectedAction?.description && (
	                  <div className="muted mt-8">
	                    {toDisplay(selectedAction.description)}
	                  </div>
	                )}
	                {String(selectedAction?.id || "").trim().toLowerCase() === "custom-os-command" ? (
	                  <div className="empty-state mt-8">
	                    Emergency fallback. This runs exactly what you type on endpoints.
	                  </div>
	                ) : null}
	                {selectedAction?.docs && typeof selectedAction.docs === "object" && Object.keys(selectedAction.docs).length > 0 ? (
	                  <div className="list-item readable mt-10">
	                    <div className="muted">Action Guide</div>
                    {selectedAction.docs.what_it_does ? (
                      <div><strong>What it does:</strong> {String(selectedAction.docs.what_it_does)}</div>
                    ) : null}
	                    {selectedAction.docs.when_to_use ? (
	                      <div className="mt-6"><strong>When to use:</strong> {String(selectedAction.docs.when_to_use)}</div>
	                    ) : null}
	                    {selectedAction.docs.impact ? (
	                      <div className="mt-6"><strong>Impact:</strong> {String(selectedAction.docs.impact)}</div>
	                    ) : null}
	                    {selectedAction.docs.rollback ? (
	                      <div className="mt-6"><strong>Rollback:</strong> {String(selectedAction.docs.rollback)}</div>
	                    ) : null}
	                    {selectedAction.docs.evidence ? (
	                      <div className="mt-6"><strong>Evidence:</strong> {String(selectedAction.docs.evidence)}</div>
	                    ) : null}
	                  </div>
	                ) : null}
	                {selectedAction && (
	                  <div className="page-actions mt-8">
	                    <span className="chip">{toDisplay(selectedAction.category || "response")}</span>
                    <span className={`status-pill ${riskClass(selectedAction.risk)}`}>
                      {toDisplay(selectedAction.risk || "n/a")}
                    </span>
                    <span className="chip">{selectedAction.custom ? "custom command" : "built-in command"}</span>
                  </div>
                )}
	                {actionValidation && (
	                  <div className="list-item inset-panel mt-8">
	                    <div className="muted">Validation Results</div>
	                    <div className="grid-2 mt-4">
                      <div>
                        <span className={`status-pill ${actionValidation.is_valid ? "success" : "failed"}`}>
                          {actionValidation.is_valid ? "Valid" : "Invalid"}
                        </span>
                      </div>
                      <div>
                        <span className="chip">OS: {actionValidation.agent_os}</span>
                        <span className="chip">Channel: {actionValidation.preferred_channel}</span>
                        <span className="chip">Timeout: {actionValidation.timeout_seconds}s</span>
                      </div>
                    </div>
	                    {!actionValidation.is_valid && (
	                      <div className="muted mt-4">
	                        Errors: {actionValidation.errors.join(", ")}
	                      </div>
	                    )}
	                  </div>
	                )}
	                <div className="page-actions mt-8">
                  <span className="chip">
                    Mode: {toDisplay(connectorStatus?.orchestration_mode || "n/a")}
                  </span>
                  <span className="chip">
                    WinRM creds: {connectorStatus?.connectors?.windows?.credentials_configured ? "configured" : "missing"}
                  </span>
                  <span className="chip">
                    Linux creds: {connectorStatus?.connectors?.linux?.credentials_configured ? "configured" : "missing"}
                  </span>
                </div>
	                {connectorError && (
	                  <div className="meta-line mt-8">
	                    Connector status error: {connectorError}
	                  </div>
	                )}
	                {(selectedAction?.inputs || []).map(field => (
	                  <div key={field.name} className="mt-10">
	                    <div className="muted">{toDisplay(field.label || field.name)}</div>
                    {MULTILINE_INPUT_FIELDS.has(String(field.name || "").trim().toLowerCase()) ? (
	                      <textarea
	                        className="input mono"
	                        value={actionInputs[field.name] || ""}
                        onChange={(e) =>
                          setActionInputs(prev => ({
                            ...prev,
                            [field.name]: e.target.value
                          }))
                        }
                        placeholder={field.placeholder || ""}
	                        rows={4}
	                      />
                    ) : (
                      <input
                        className="input"
                        value={actionInputs[field.name] || ""}
                        onChange={(e) =>
                          setActionInputs(prev => ({
                            ...prev,
                            [field.name]: e.target.value
                          }))
                        }
                        placeholder={field.placeholder || ""}
                      />
                    )}
                  </div>
                ))}
	                <div className="mt-10">
	                  <div className="muted">Justification (if required)</div>
	                  <input
	                    className="input"
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    placeholder="Why is this response needed?"
                  />
                </div>
	                <div className="page-actions mt-12">
                  <button className="btn secondary" onClick={validateConnector}>
                    Validate Connector
                  </button>
                  <button className="btn secondary" onClick={testActionWorkflow}>
                    Test Action
                  </button>
                  <button className="btn secondary" onClick={requestAgentApproval}>
                    Request Approval
                  </button>
                  <button className="btn" onClick={runAgentAction}>
                    Run Action
                  </button>
                </div>
	                {actionStatus && (
	                  <div className="empty-state mt-12">{toDisplay(actionStatus)}</div>
	                )}
	                {activeExecutionId && (
	                  <div className="mt-12">
	                    <ExecutionStream executionId={activeExecutionId} />
	                  </div>
	                )}
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
	              <svg viewBox="0 0 560 170" width="100%" height="180" role="img" aria-label="Events count evolution">
	                <rect x="0" y="0" width="560" height="170" fill="var(--panel-soft)" stroke="var(--border)" rx="10" />
	                <polyline
	                  fill="none"
	                  stroke="var(--accent)"
	                  strokeWidth="3"
	                  points={eventChart.points}
	                  transform="translate(0,15)"
                />
              </svg>
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
                    {complianceRows.map((row) => (
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
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Response Recommendations</h3>
            <p className="muted">Suggested actions from current threat and compliance context.</p>
          </div>
        </div>
        {recommendations.length === 0 ? (
          <div className="empty-state">No immediate recommendation from current telemetry.</div>
        ) : (
          <div className="list">
            {recommendations.map((rec) => (
              <button
                key={rec.action}
                className="list-item split clickable"
                onClick={() => {
                  setActionId(rec.action);
                  setActionStatus(`Prepared action: ${rec.action}`);
                }}
              >
                <div>
                  <div>{rec.title}</div>
                  <div className="meta-line">{rec.reason}</div>
                </div>
                <span className="chip">{rec.action}</span>
              </button>
            ))}
          </div>
        )}
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
                  vulnerabilities.slice(0, 50).map((vuln, idx) => {
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
                  agentAlerts.map((alert) => (
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
                fimEvents.map((evt, idx) => {
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
      </div>
    </div>
  );
}

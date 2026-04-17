import { useCallback, useEffect, useMemo, useState } from "react";
import ExecutionStream from "../components/ExecutionStream";
import Pager from "../components/Pager";
import RelativeTimestamp from "../components/RelativeTimestamp";
import {
  getAgentGroups,
  getAgents,
  getExecutions,
  getVulnerabilities,
  runGlobalShell,
} from "../api/wazuh";
import { formatApiError } from "../utils/httpErrors";
import { redactSensitiveCommandText } from "../utils/output";

const CONNECTED_STATUSES = new Set(["active", "connected", "online"]);
const SHELL_PLATFORM_MAP = {
  powershell: "windows",
  cmd: "windows",
  bash: "linux",
  sh: "linux",
};
const LIVE_EXECUTION_STATUSES = new Set([
  "QUEUED",
  "RUNNING",
  "PENDING",
  "PENDING_VERIFICATION",
  "PAUSED",
  "IN_PROGRESS",
  "DISPATCHED",
]);
const VULN_FETCH_LIMIT = 800;
const VULN_SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const normalizeAgents = (data) => {
  if (Array.isArray(data)) return data;
  if (data?.data?.affected_items) return data.data.affected_items;
  if (data?.affected_items) return data.affected_items;
  if (data?.items) return data.items;
  return [];
};

const formatAgentId = (raw) => {
  if (raw === null || raw === undefined) return "";
  const text = String(raw).trim();
  if (!text) return "";
  return /^[0-9]+$/.test(text) && text.length < 3 ? text.padStart(3, "0") : text;
};

const toAgentGroups = (agent) => {
  const values = [];
  const append = (value) => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) {
      value.forEach(append);
      return;
    }
    const text = String(value).trim();
    if (!text) return;
    if (text.includes(",")) {
      text.split(",").forEach(append);
      return;
    }
    values.push(text);
  };
  append(agent?.group);
  append(agent?.groups);
  append(agent?.group_name);
  return Array.from(new Set(values));
};

const agentStatus = (agent) =>
  String(agent?.status || agent?.agent?.status || "").trim().toLowerCase();

const agentPlatform = (agent) => {
  const osNode = agent?.os;
  const osName = typeof osNode === "object" && osNode
    ? String(osNode.name || osNode.platform || osNode.full || "")
    : String(agent?.os_name || agent?.os || agent?.platform || "");
  const lowered = osName.toLowerCase();
  if (lowered.includes("windows")) return "windows";
  if (
    lowered.includes("linux")
    || lowered.includes("ubuntu")
    || lowered.includes("debian")
    || lowered.includes("centos")
    || lowered.includes("fedora")
    || lowered.includes("suse")
  ) {
    return "linux";
  }
  return "unknown";
};

const statusTone = (status) => {
  const value = String(status || "").toUpperCase();
  if (value === "SUCCESS") return "success";
  if (["FAILED", "ERROR", "KILLED"].includes(value)) return "failed";
  if (["RUNNING", "PAUSED", "PENDING", "PENDING_VERIFICATION", "QUEUED", "CANCELLED", "PARTIAL"].includes(value)) return "pending";
  return "neutral";
};

const titleCase = (value) => {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "-";
  return `${text[0].toUpperCase()}${text.slice(1)}`;
};

const severityTone = (severity) => {
  const key = String(severity || "").toLowerCase();
  if (key === "critical" || key === "high") return "failed";
  if (key === "medium") return "pending";
  if (key === "low") return "success";
  return "neutral";
};

const isExecutionLive = (status) => LIVE_EXECUTION_STATUSES.has(String(status || "").trim().toUpperCase());

const hasInlineLinuxPassword = (value) => {
  const text = String(value || "");
  if (!text) return false;
  if (/\bsudo\s+-S\b/i.test(text)) return true;
  return /\b(?:echo|printf)\b[\s\S]{0,200}\|\s*sudo\b/i.test(text);
};

const parseJsonMaybe = (value) => {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") return value;
  const text = value.trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const extractCommandFromArgs = (value) => {
  const parsed = parseJsonMaybe(value);
  if (Array.isArray(parsed)) {
    const first = parsed.find((item) => typeof item === "string" && item.trim());
    return first ? first.trim() : "";
  }
  if (parsed && typeof parsed === "object") {
    for (const key of ["command", "custom_command", "script", "cmd", "shell_command"]) {
      const candidate = parsed[key];
      if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
    }
    const firstString = Object.values(parsed).find((item) => typeof item === "string" && item.trim());
    return typeof firstString === "string" ? firstString.trim() : "";
  }
  if (typeof parsed === "string") return parsed.trim();
  return "";
};

const unquoteShellPayload = (value) => {
  const text = String(value || "").trim();
  if (!text) return "";
  if (text.length >= 2 && text.startsWith("'") && text.endsWith("'")) {
    return text
      .slice(1, -1)
      .replace(/'\\''/g, "'")
      .replace(/'"'"'/g, "'");
  }
  if (text.length >= 2 && text.startsWith("\"") && text.endsWith("\"")) {
    return text.slice(1, -1).replace(/\\"/g, "\"");
  }
  return text;
};

const resolveShellAndCommand = (argsValue) => {
  const commandUsed = redactSensitiveCommandText(extractCommandFromArgs(argsValue));
  if (!commandUsed) return { shell: "-", command: "" };
  const cmdMatch = commandUsed.match(/^cmd(?:\.exe)?\s+\/c\s+([\s\S]+)$/i);
  if (cmdMatch) return { shell: "CMD", command: String(cmdMatch[1] || "").trim() || commandUsed };
  const bashMatch = commandUsed.match(/^(?:\/bin\/)?bash(?:\.exe)?\s+-lc\s+([\s\S]+)$/i);
  if (bashMatch) return { shell: "Bash", command: unquoteShellPayload(bashMatch[1]) || commandUsed };
  const shMatch = commandUsed.match(/^(?:\/bin\/)?sh\s+-lc\s+([\s\S]+)$/i);
  if (shMatch) return { shell: "SH", command: unquoteShellPayload(shMatch[1]) || commandUsed };
  return { shell: "PowerShell", command: commandUsed };
};

const deriveVulnKey = (row) => {
  const id = String(row?.id || "").trim();
  if (id) return id;
  const cve = String(row?.cve || "").trim();
  const pkg = String(row?.package?.name || "").trim();
  const sev = String(row?.severity || "").trim();
  return [cve || "vuln", pkg || "pkg", sev || "sev"].join("|");
};

const compactAgentList = (items, limit = 4) => {
  const list = Array.isArray(items) ? items : [];
  if (!list.length) return "-";
  const mapped = list.map((item) => {
    const id = formatAgentId(item?.id || item?.agent_id || "");
    const name = String(item?.name || item?.agent_name || "").trim();
    return name ? `${id}:${name}` : id || "-";
  });
  if (mapped.length <= limit) return mapped.join(", ");
  return `${mapped.slice(0, limit).join(", ")} +${mapped.length - limit} more`;
};

const normalizeHistoryRows = (rows) => {
  const list = Array.isArray(rows) ? rows : [];
  return list
    .map((row) => {
      if (Array.isArray(row)) {
        const commandMeta = resolveShellAndCommand(row[7] ?? null);
        const action = String(row[2] || "");
        return {
          id: Number(row[0] || 0),
          status: String(row[3] || ""),
          target: String(row[1] || ""),
          action,
          startedAt: row[5] || "",
          finishedAt: row[6] || "",
          shell: commandMeta.shell,
          command: commandMeta.command,
        };
      }
      const commandMeta = resolveShellAndCommand(row?.args);
      return {
        id: Number(row?.id || 0),
        status: String(row?.status || ""),
        target: String(row?.agent || ""),
        action: String(row?.action || row?.action_id || row?.playbook || ""),
        startedAt: row?.started_at || row?.startedAt || "",
        finishedAt: row?.finished_at || row?.finishedAt || "",
        shell: commandMeta.shell,
        command: commandMeta.command,
      };
    })
    .filter((row) => row.id > 0 && String(row.action || "").toLowerCase().includes("global-shell"))
    .sort((left, right) => right.id - left.id);
};

const buildVulnerabilityContext = (rows, scope) => ({
  source: "wazuh-vulnerabilities",
  selected_count: rows.length,
  scope,
  selected_vulnerabilities: rows.slice(0, 60).map((row) => ({
    id: row?.id || "",
    cve: row?.cve || "",
    title: row?.title || "",
    severity: row?.severity || "",
    score: row?.score,
    package: {
      name: row?.package?.name || "",
      version: row?.package?.version || "",
      source: row?.package?.source || "",
      condition: row?.package?.condition || "",
    },
    affected_count: Number(row?.affected_count || 0),
  })),
});

export default function PatchWorkbench() {
  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [agentsError, setAgentsError] = useState("");

  const [targetMode, setTargetMode] = useState("agent");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [multiPickAgentId, setMultiPickAgentId] = useState("");
  const [agentSearch, setAgentSearch] = useState("");

  const [vulnerabilityRows, setVulnerabilityRows] = useState([]);
  const [vulnerabilityLoading, setVulnerabilityLoading] = useState(false);
  const [vulnerabilityError, setVulnerabilityError] = useState("");
  const [vulnerabilitySummary, setVulnerabilitySummary] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    affected_agents: 0,
    source: "-",
  });
  const [vulnerabilityQuery, setVulnerabilityQuery] = useState("");
  const [selectedVulnKeys, setSelectedVulnKeys] = useState([]);
  const [vulnPage, setVulnPage] = useState(1);
  const [vulnPageSize, setVulnPageSize] = useState(25);

  const [shell, setShell] = useState("powershell");
  const [runAsSystem, setRunAsSystem] = useState(false);
  const [allowDestructive, setAllowDestructive] = useState(false);
  const [command, setCommand] = useState("");
  const [justification, setJustification] = useState("");
  const [runStatus, setRunStatus] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPageSize, setHistoryPageSize] = useState(15);
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [activeExecutionMode, setActiveExecutionMode] = useState("auto");

  const loadAgents = useCallback(async (force = false) => {
    setAgentsLoading(true);
    setAgentsError("");
    try {
      const [agentRes, groupsRes] = await Promise.all([
        getAgents(undefined, {
          force,
          limit: 5000,
          status: "active,connected,online",
          compact: true,
        }),
        getAgentGroups(),
      ]);

      const parsedAgents = normalizeAgents(agentRes?.data)
        .map((agent) => {
          const normalizedGroups = toAgentGroups(agent);
          return {
            id: formatAgentId(agent?.id || agent?.agent_id),
            name: String(agent?.name || agent?.hostname || "").trim(),
            status: agentStatus(agent),
            platform: agentPlatform(agent),
            groups: normalizedGroups,
            groupText: normalizedGroups.join(", "),
          };
        })
        .filter((agent) => agent.id);
      setAgents(parsedAgents);

      const groupRows = Array.isArray(groupsRes?.data) ? groupsRes.data : [];
      const fromApi = groupRows
        .map((group) => String(group?.name || group?.id || group || "").trim())
        .filter(Boolean);
      setGroups(fromApi);
    } catch (err) {
      setAgents([]);
      setGroups([]);
      setAgentsError(formatApiError(err, "Failed to load connected agents."));
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  const loadHistory = useCallback(async (force = false) => {
    setHistoryLoading(true);
    try {
      const response = await getExecutions(
        { limit: 60, q: "global-shell", include_latest_output: false },
        { force }
      );
      const rows = normalizeHistoryRows(response?.data);
      setHistory(rows);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAgents();
    void loadHistory();
  }, [loadAgents, loadHistory]);

  const connectedAgents = useMemo(
    () => agents.filter((agent) => CONNECTED_STATUSES.has(agent.status)),
    [agents]
  );

  const normalizedTargetValue = useMemo(() => formatAgentId(targetValue), [targetValue]);
  const normalizedGroupValue = useMemo(() => String(targetValue || "").trim(), [targetValue]);
  const selectedAgentSet = useMemo(
    () => new Set(targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)),
    [targetAgentIds]
  );

  const availableGroups = useMemo(() => {
    const names = new Set();
    groups.forEach((group) => {
      const text = String(group || "").trim();
      if (text) names.add(text);
    });
    connectedAgents.forEach((agent) => {
      (agent.groups || []).forEach((group) => {
        const text = String(group || "").trim();
        if (text) names.add(text);
      });
    });
    return Array.from(names).sort((left, right) => left.localeCompare(right));
  }, [connectedAgents, groups]);

  const filteredAgents = useMemo(() => {
    const query = String(agentSearch || "").trim().toLowerCase();
    if (!query) return connectedAgents;
    return connectedAgents.filter((agent) =>
      agent.id.toLowerCase().includes(query)
      || String(agent.name || "").toLowerCase().includes(query)
      || String(agent.groupText || "").toLowerCase().includes(query)
    );
  }, [agentSearch, connectedAgents]);

  const selectedMultiAgents = useMemo(
    () => connectedAgents.filter((agent) => selectedAgentSet.has(agent.id)),
    [connectedAgents, selectedAgentSet]
  );

  const scopedConnectedAgents = useMemo(() => {
    if (targetMode === "agent") {
      if (!normalizedTargetValue) return [];
      return connectedAgents.filter((agent) => agent.id === normalizedTargetValue);
    }
    if (targetMode === "multi") {
      if (!selectedAgentSet.size) return [];
      return connectedAgents.filter((agent) => selectedAgentSet.has(agent.id));
    }
    if (targetMode === "group") {
      const key = normalizedGroupValue.toLowerCase();
      if (!key) return [];
      return connectedAgents.filter((agent) =>
        (agent.groups || []).some((group) => String(group || "").trim().toLowerCase() === key)
      );
    }
    return connectedAgents;
  }, [connectedAgents, normalizedGroupValue, normalizedTargetValue, selectedAgentSet, targetMode]);

  const scopeParams = useMemo(() => {
    if (targetMode === "agent") {
      return normalizedTargetValue ? { agent_id: normalizedTargetValue } : null;
    }
    if (targetMode === "multi") {
      return selectedAgentSet.size ? { agent_ids: Array.from(selectedAgentSet).join(",") } : null;
    }
    if (targetMode === "group") {
      return normalizedGroupValue ? { group: normalizedGroupValue } : null;
    }
    return {};
  }, [normalizedGroupValue, normalizedTargetValue, selectedAgentSet, targetMode]);

  useEffect(() => {
    if (targetMode !== "agent") return;
    if (normalizedTargetValue && connectedAgents.some((agent) => agent.id === normalizedTargetValue)) return;
    const firstConnected = connectedAgents[0]?.id || "";
    setTargetValue(firstConnected);
  }, [connectedAgents, normalizedTargetValue, targetMode]);

  const scopeLabel = useMemo(() => {
    if (targetMode === "agent") return normalizedTargetValue || "No agent selected";
    if (targetMode === "multi") return `${selectedAgentSet.size} agent(s) selected`;
    if (targetMode === "group") return normalizedGroupValue ? `Group: ${normalizedGroupValue}` : "No group selected";
    return "Fleet";
  }, [normalizedGroupValue, normalizedTargetValue, selectedAgentSet.size, targetMode]);

  const shellTargetPlatform = SHELL_PLATFORM_MAP[shell] || "windows";
  const shellTargetLabel = shellTargetPlatform === "linux" ? "Linux" : "Windows";

  const eligibleScopedAgents = useMemo(
    () => scopedConnectedAgents.filter((agent) => agent.platform === shellTargetPlatform),
    [scopedConnectedAgents, shellTargetPlatform]
  );

  const loadVulnerabilities = useCallback(async () => {
    if (scopeParams === null) {
      setVulnerabilityRows([]);
      setVulnerabilitySummary((current) => ({ ...current, total: 0 }));
      return;
    }
    setVulnerabilityLoading(true);
    setVulnerabilityError("");
    try {
      const fetchLimit = targetMode === "fleet" ? 250 : VULN_FETCH_LIMIT;
      const response = await getVulnerabilities({
        ...(scopeParams || {}),
        limit: fetchLimit,
        compact: true,
        include_remediation: false,
      });
      const payload = response?.data || {};
      const rows = Array.isArray(payload?.items) ? payload.items : [];
      setVulnerabilityRows(rows);
      setVulnerabilitySummary({
        total: Number(payload?.summary?.total || rows.length || 0),
        critical: Number(payload?.summary?.critical || 0),
        high: Number(payload?.summary?.high || 0),
        medium: Number(payload?.summary?.medium || 0),
        low: Number(payload?.summary?.low || 0),
        affected_agents: Number(payload?.summary?.affected_agents || 0),
        source: String(payload?.source || "-"),
      });
    } catch (err) {
      setVulnerabilityRows([]);
      setVulnerabilitySummary({
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        affected_agents: 0,
        source: "-",
      });
      setVulnerabilityError(formatApiError(err, "Failed to load vulnerabilities."));
    } finally {
      setVulnerabilityLoading(false);
    }
  }, [scopeParams, targetMode]);

  useEffect(() => {
    void loadVulnerabilities();
  }, [loadVulnerabilities]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      void loadHistory(true);
    }, 20000);
    return () => window.clearInterval(timer);
  }, [loadHistory]);

  useEffect(() => {
    setSelectedVulnKeys((current) => {
      const valid = new Set(vulnerabilityRows.map((row) => deriveVulnKey(row)));
      const next = current.filter((key) => valid.has(key));
      return next.length === current.length ? current : next;
    });
  }, [vulnerabilityRows]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(history.length / historyPageSize));
    if (historyPage > totalPages) setHistoryPage(totalPages);
  }, [history.length, historyPage, historyPageSize]);

  const filteredVulnerabilities = useMemo(() => {
    const query = String(vulnerabilityQuery || "").trim().toLowerCase();
    const rows = [...vulnerabilityRows].sort((left, right) => {
      const leftRank = VULN_SEVERITY_ORDER[String(left?.severity || "").toLowerCase()] ?? 99;
      const rightRank = VULN_SEVERITY_ORDER[String(right?.severity || "").toLowerCase()] ?? 99;
      if (leftRank !== rightRank) return leftRank - rightRank;
      return String(left?.cve || left?.id || "").localeCompare(String(right?.cve || right?.id || ""));
    });
    if (!query) return rows;
    return rows.filter((row) => {
      const blob = [
        row?.id,
        row?.cve,
        row?.title,
        row?.severity,
        row?.package?.name,
        row?.package?.version,
        row?.package?.source,
      ]
        .map((item) => String(item || "").toLowerCase())
        .join(" ");
      return blob.includes(query);
    });
  }, [vulnerabilityQuery, vulnerabilityRows]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredVulnerabilities.length / vulnPageSize));
    if (vulnPage > totalPages) setVulnPage(totalPages);
  }, [filteredVulnerabilities.length, vulnPage, vulnPageSize]);

  const pagedVulnerabilities = useMemo(() => {
    const start = (vulnPage - 1) * vulnPageSize;
    return filteredVulnerabilities.slice(start, start + vulnPageSize);
  }, [filteredVulnerabilities, vulnPage, vulnPageSize]);

  const selectedVulnSet = useMemo(() => new Set(selectedVulnKeys), [selectedVulnKeys]);
  const selectedVulnerabilityRows = useMemo(
    () => vulnerabilityRows.filter((row) => selectedVulnSet.has(deriveVulnKey(row))),
    [selectedVulnSet, vulnerabilityRows]
  );

  const allVisibleSelected = useMemo(() => {
    if (!pagedVulnerabilities.length) return false;
    return pagedVulnerabilities.every((row) => selectedVulnSet.has(deriveVulnKey(row)));
  }, [pagedVulnerabilities, selectedVulnSet]);

  const pagedHistory = useMemo(() => {
    const start = (historyPage - 1) * historyPageSize;
    return history.slice(start, start + historyPageSize);
  }, [history, historyPage, historyPageSize]);

  const activeHistoryRow = useMemo(
    () => history.find((row) => Number(row.id) === Number(activeExecutionId)) || null,
    [activeExecutionId, history]
  );
  const activeHistoryRowIsLive = isExecutionLive(activeHistoryRow?.status);

  useEffect(() => {
    if (activeExecutionMode === "manual") {
      if (!activeExecutionId) return;
      const exists = history.some((row) => Number(row.id) === Number(activeExecutionId));
      if (exists) return;
      setActiveExecutionId(null);
      setActiveExecutionMode("auto");
      return;
    }

    const currentLive = history.some(
      (row) => Number(row.id) === Number(activeExecutionId) && isExecutionLive(row.status)
    );
    if (currentLive) return;

    const latestLiveRow = history.find((row) => isExecutionLive(row.status));
    setActiveExecutionId(latestLiveRow ? latestLiveRow.id : null);
  }, [activeExecutionId, activeExecutionMode, history]);

  const toggleVulnerabilitySelection = useCallback((key) => {
    setSelectedVulnKeys((current) => (
      current.includes(key)
        ? current.filter((item) => item !== key)
        : [...current, key]
    ));
  }, []);

  const toggleVisibleVulnerabilities = useCallback(() => {
    const visibleKeys = pagedVulnerabilities.map((row) => deriveVulnKey(row));
    setSelectedVulnKeys((current) => {
      const selected = new Set(current);
      const shouldSelectAll = !visibleKeys.every((key) => selected.has(key));
      if (shouldSelectAll) visibleKeys.forEach((key) => selected.add(key));
      else visibleKeys.forEach((key) => selected.delete(key));
      return Array.from(selected);
    });
  }, [pagedVulnerabilities]);

  const runPatchCommand = useCallback(async () => {
    const rawCommand = String(command || "").trim();
    if (!rawCommand) {
      setRunStatus("Command is required.");
      return;
    }
    if (shellTargetPlatform === "linux" && hasInlineLinuxPassword(rawCommand)) {
      setRunStatus(
        "Do not include sudo password text in commands. Use password-free command text, enable Run as admin, and keep per-agent C2F_SSH credentials in env."
      );
      return;
    }
    if (scopeParams === null) {
      setRunStatus("Select a valid agent scope first.");
      return;
    }
    if (!eligibleScopedAgents.length) {
      setRunStatus(`No connected ${shellTargetLabel} agents in this scope for shell "${shell}".`);
      return;
    }

    setSubmitting(true);
    setRunStatus("Queueing global-shell patch execution...");
    try {
      const payload = {
        shell,
        command: rawCommand,
        async: true,
        run_as_system: Boolean(runAsSystem),
        allow_destructive: Boolean(allowDestructive),
        justification: justification.trim().length >= 12
          ? justification.trim()
          : `Patch workbench execution (${shell})`,
      };
      if (selectedVulnerabilityRows.length) {
        payload.vulnerability_context = buildVulnerabilityContext(selectedVulnerabilityRows, {
          target_mode: targetMode,
          target_value: targetMode === "agent" ? normalizedTargetValue : normalizedGroupValue,
          target_agent_ids: targetMode === "multi" ? Array.from(selectedAgentSet) : undefined,
        });
      }

      if (targetMode === "agent") payload.agent_id = normalizedTargetValue;
      else if (targetMode === "group") payload.group = normalizedGroupValue;
      else if (targetMode === "multi") payload.agent_ids = Array.from(selectedAgentSet);
      else payload.agent_id = "all";

      const response = await runGlobalShell(payload);
      const data = response?.data || {};
      const executionId = Number(data?.execution_id || 0) || null;
      if (executionId) {
        setActiveExecutionMode("auto");
        setActiveExecutionId(executionId);
      }
      setRunStatus(
        `Queued run${executionId ? ` #${executionId}` : ""} for ${Number(data?.summary?.targeted_agents || 0)} connected ${shellTargetLabel} agent(s).`
      );
      await loadHistory(true);
      setHistoryOpen(true);
    } catch (err) {
      setRunStatus(formatApiError(err, "Failed to queue patch execution."));
    } finally {
      setSubmitting(false);
    }
  }, [
    allowDestructive,
    command,
    eligibleScopedAgents.length,
    justification,
    loadHistory,
    normalizedGroupValue,
    normalizedTargetValue,
    runAsSystem,
    scopeParams,
    selectedAgentSet,
    selectedVulnerabilityRows,
    shell,
    shellTargetLabel,
    shellTargetPlatform,
    targetMode,
  ]);

  return (
    <div className="page patch-workbench-page page-route-patch-workbench">
      <div className="page-header">
        <div>
          <h2>Patch Workbench</h2>
          <p className="muted">
            One-page patch flow: choose scope, optionally select vulnerabilities, run global shell command, and track live execution.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" type="button" onClick={() => void loadAgents(true)} disabled={agentsLoading}>
            {agentsLoading ? "Refreshing Agents..." : "Refresh Agents"}
          </button>
          <button className="btn secondary" type="button" onClick={() => void loadVulnerabilities()} disabled={vulnerabilityLoading}>
            {vulnerabilityLoading ? "Refreshing Vulnerabilities..." : "Refresh Vulnerabilities"}
          </button>
          <button className="btn secondary" type="button" onClick={() => void loadHistory(true)} disabled={historyLoading}>
            {historyLoading ? "Refreshing History..." : "Refresh History"}
          </button>
        </div>
      </div>

      {agentsError ? <div className="empty-state">Agent feed: {agentsError}</div> : null}
      {vulnerabilityError ? <div className="empty-state">Vulnerabilities feed: {vulnerabilityError}</div> : null}

      <div className="stat-grid patch-workbench-stat-grid">
        <div className="stat-card">
          <div className="stat-label">Scope</div>
          <div className="stat-value patch-workbench-stat-text">{scopeLabel}</div>
          <div className="stat-sub">Connected in scope: {scopedConnectedAgents.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Shell Target</div>
          <div className="stat-value patch-workbench-stat-text">{shellTargetLabel}</div>
          <div className="stat-sub">Eligible now: {eligibleScopedAgents.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Selected Vulns</div>
          <div className="stat-value">{selectedVulnerabilityRows.length}</div>
          <div className="stat-sub">Total in feed: {filteredVulnerabilities.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Severity Mix</div>
          <div className="stat-value patch-workbench-stat-text">
            C:{vulnerabilitySummary.critical} H:{vulnerabilitySummary.high}
          </div>
          <div className="stat-sub">M:{vulnerabilitySummary.medium} L:{vulnerabilitySummary.low}</div>
        </div>
      </div>

      <div className="card patch-workbench-scope-card">
        <div className="card-header">
          <div>
            <h3>1) Target Scope</h3>
            <p className="muted">Select fleet, group, multiple agents, or a single agent before loading vulnerabilities.</p>
          </div>
        </div>
        <div className="list">
          <div className="list-item readable">
            <div className="page-actions">
              <select className="input" value={targetMode} onChange={(event) => setTargetMode(event.target.value)}>
                <option value="fleet">Fleet (all connected agents)</option>
                <option value="group">Group</option>
                <option value="multi">Multiple agents</option>
                <option value="agent">Single agent</option>
              </select>
            </div>

            {targetMode === "group" ? (
              <div className="page-actions mt-10">
                <select className="input" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
                  <option value="">Select group</option>
                  {availableGroups.map((group) => (
                    <option key={group} value={group}>{group}</option>
                  ))}
                </select>
              </div>
            ) : null}

            {targetMode === "agent" ? (
              <div className="page-actions mt-10">
                <select className="input" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
                  <option value="">Select agent</option>
                  {connectedAgents.map((agent) => (
                    <option key={`single-agent-${agent.id}`} value={agent.id}>
                      {agent.id} - {agent.name || "-"}{agent.groupText ? ` (${agent.groupText})` : ""}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            {targetMode === "multi" ? (
              <div className="mt-10">
                <div className="page-actions">
                  <input
                    className="input"
                    value={agentSearch}
                    onChange={(event) => setAgentSearch(event.target.value)}
                    placeholder="Search by ID, name, group"
                  />
                  <select
                    className="input patch-workbench-agent-picker"
                    value={multiPickAgentId}
                    onChange={(event) => setMultiPickAgentId(formatAgentId(event.target.value))}
                  >
                    <option value="">Pick connected agent</option>
                    {filteredAgents.map((agent) => (
                      <option key={`pick-agent-${agent.id}`} value={agent.id}>
                        {agent.id} - {agent.name || "-"}
                      </option>
                    ))}
                  </select>
                  <button
                    className="btn secondary"
                    type="button"
                    onClick={() => {
                      if (!multiPickAgentId) return;
                      setTargetAgentIds((current) => (
                        current.includes(multiPickAgentId) ? current : [...current, multiPickAgentId]
                      ));
                      setMultiPickAgentId("");
                    }}
                  >
                    Add
                  </button>
                  <button
                    className="btn secondary"
                    type="button"
                    onClick={() => setTargetAgentIds(filteredAgents.map((agent) => agent.id))}
                  >
                    Select Visible
                  </button>
                  <button className="btn secondary" type="button" onClick={() => setTargetAgentIds([])}>
                    Clear
                  </button>
                </div>
                <div className="meta-line mt-8">Selected: {selectedAgentSet.size}</div>
                <div className="list mt-8 patch-workbench-selected-agents">
                  {selectedMultiAgents.length === 0 ? (
                    <div className="empty-state">No agents selected yet.</div>
                  ) : (
                    selectedMultiAgents.map((agent) => (
                      <div key={`selected-${agent.id}`} className="list-item split readable">
                        <span>{agent.id} - {agent.name || "-"}</span>
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() => {
                            setTargetAgentIds((current) => current.filter((id) => id !== agent.id));
                          }}
                        >
                          Remove
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>

      <div className="patch-workbench-main-grid">
        <div className="card patch-workbench-vuln-card">
          <div className="card-header">
            <div>
              <h3>2) Vulnerabilities</h3>
              <p className="muted">
                Source: {vulnerabilitySummary.source}. Affected agents: {vulnerabilitySummary.affected_agents}. Select rows to include patch context.
              </p>
            </div>
          </div>
          <div className="page-actions mt-8">
            <input
              className="input"
              value={vulnerabilityQuery}
              onChange={(event) => setVulnerabilityQuery(event.target.value)}
              placeholder="Filter by CVE, package, title, severity"
            />
          </div>
          <div className="table-scroll patch-workbench-vuln-scroll">
            <table className="table compact readable">
              <thead>
                <tr>
                  <th className="patch-workbench-check-col">
                    <input type="checkbox" checked={allVisibleSelected} onChange={toggleVisibleVulnerabilities} />
                  </th>
                  <th>Severity</th>
                  <th>Vulnerability</th>
                  <th>Package</th>
                  <th>Affected Agents</th>
                </tr>
              </thead>
              <tbody>
                {pagedVulnerabilities.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="text-center">
                      {vulnerabilityLoading ? "Loading vulnerabilities..." : "No vulnerabilities in current scope."}
                    </td>
                  </tr>
                ) : (
                  pagedVulnerabilities.map((row) => {
                    const key = deriveVulnKey(row);
                    const selected = selectedVulnSet.has(key);
                    return (
                      <tr key={key} className={selected ? "selected" : ""}>
                        <td>
                          <input
                            type="checkbox"
                            checked={selected}
                            onChange={() => toggleVulnerabilitySelection(key)}
                          />
                        </td>
                        <td>
                          <span className={`status-pill ${severityTone(row?.severity)}`}>
                            {titleCase(row?.severity)}
                          </span>
                        </td>
                        <td>
                          <div>{row?.cve || row?.id || "-"}</div>
                          <div className="meta-line">{row?.title || "-"}</div>
                        </td>
                        <td>
                          <div>{row?.package?.name || "-"}</div>
                          <div className="meta-line">
                            {row?.package?.version || "-"} | {row?.package?.source || "-"}
                          </div>
                        </td>
                        <td>
                          <div>{Number(row?.affected_count || 0)} agent(s)</div>
                          <div className="meta-line">{compactAgentList(row?.affected_agents, 3)}</div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <Pager
            total={filteredVulnerabilities.length}
            page={vulnPage}
            pageSize={vulnPageSize}
            onPageChange={setVulnPage}
            onPageSizeChange={(size) => {
              setVulnPageSize(size);
              setVulnPage(1);
            }}
            pageSizeOptions={[25, 50, 100]}
            label="vulnerabilities"
          />
        </div>

        <div className="patch-workbench-side-stack">
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Selected Vulnerabilities</h3>
                <p className="muted">These selected rows are attached to the execution context.</p>
              </div>
            </div>
            <div className="list patch-workbench-selection-list">
              {selectedVulnerabilityRows.length === 0 ? (
                <div className="empty-state">No vulnerabilities selected yet.</div>
              ) : (
                selectedVulnerabilityRows.map((row) => {
                  const key = deriveVulnKey(row);
                  return (
                    <div key={`selected-vuln-${key}`} className="list-item split readable">
                      <span>{row?.cve || row?.id || "-"} | {row?.package?.name || "-"}</span>
                      <button className="btn secondary" type="button" onClick={() => toggleVulnerabilitySelection(key)}>
                        Remove
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="card patch-workbench-command-card">
        <div className="card-header">
          <div>
            <h3>3) Command Runner</h3>
            <p className="muted">Choose shell, enter command, and run against selected scope.</p>
          </div>
        </div>
        <div className="list">
          <div className="list-item readable">
            <div className="muted">Shell</div>
            <div className="page-actions mt-8">
              <select className="input" value={shell} onChange={(event) => setShell(event.target.value)}>
                <option value="powershell">PowerShell</option>
                <option value="cmd">CMD</option>
                <option value="bash">Bash</option>
                <option value="sh">SH</option>
              </select>
            </div>
            <label className="mt-10 inline-check">
              <input type="checkbox" checked={runAsSystem} onChange={(event) => setRunAsSystem(Boolean(event.target.checked))} />
              <span className="muted">Run as admin ({shellTargetPlatform === "windows" ? "SYSTEM" : "sudo/root"})</span>
            </label>
            <label className="mt-10 inline-check">
              <input type="checkbox" checked={allowDestructive} onChange={(event) => setAllowDestructive(Boolean(event.target.checked))} />
              <span className="muted">Allow destructive commands</span>
            </label>
          </div>

          <div className="list-item readable">
            <div className="muted">Command</div>
            <textarea
              className="input mt-8 mono"
              rows={8}
              value={command}
              onChange={(event) => setCommand(event.target.value)}
              placeholder={
                shell === "powershell"
                  ? "Example: Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot"
                  : shell === "cmd"
                    ? "Example: winget upgrade --all"
                    : "Example: apt-get update && apt-get upgrade -y"
              }
            />
            {shellTargetPlatform === "linux" ? (
              <div className="meta-line mt-8">
                Linux tip: do not type password in command text. Enable "Run as admin" and use per-agent env credentials
                (`C2F_SSH_USERNAME_*` and `C2F_SSH_PASSWORD_*`).
              </div>
            ) : null}
          </div>

          <div className="list-item readable">
            <div className="muted">Justification (optional)</div>
            <input
              className="input mt-8"
              value={justification}
              onChange={(event) => setJustification(event.target.value)}
              placeholder="Reason for this patch command"
            />
          </div>

          <div className="page-actions">
            <button className="btn" type="button" onClick={runPatchCommand} disabled={submitting}>
              {submitting ? "Queueing..." : "Run Patch Command"}
            </button>
          </div>
          {runStatus ? <div className="empty-state patch-workbench-run-status">{runStatus}</div> : null}
        </div>
      </div>

      <div className="card patch-workbench-live-card">
        <div className="card-header">
          <div>
            <h3>4) Live Execution Status</h3>
            <p className="muted">
              {activeHistoryRow
                ? activeExecutionMode === "manual" || !activeHistoryRowIsLive
                  ? `History run #${activeHistoryRow.id} (${activeHistoryRow.status || "-"})`
                  : `Live run #${activeHistoryRow.id} (${activeHistoryRow.status || "-"})`
                : "No live run right now. Start a command, or click a history row to inspect full evidence."}
            </p>
          </div>
        </div>
        {!activeExecutionId ? (
          <div className="empty-state">No execution selected yet.</div>
        ) : (
          <ExecutionStream executionId={activeExecutionId} showRelatedAlerts={false} />
        )}
      </div>

      <div className="card patch-workbench-history-card">
        <div className="card-header">
          <div>
            <h3>5) Execution History</h3>
            <p className="muted">Open when needed. Click any row to inspect in live status section above.</p>
          </div>
          <div className="page-actions">
            <button className="btn secondary" type="button" onClick={() => setHistoryOpen((current) => !current)}>
              {historyOpen ? "Hide History" : "Show History"}
            </button>
          </div>
        </div>

        {historyOpen ? (
          <>
            <div className="table-scroll patch-workbench-history-scroll">
              <table className="table compact readable">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Status</th>
                    <th>Target</th>
                    <th>Shell</th>
                    <th>Command</th>
                    <th>Started</th>
                    <th>Finished</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedHistory.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="text-center">
                        {historyLoading ? "Loading history..." : "No global-shell executions found."}
                      </td>
                    </tr>
                  ) : (
                    pagedHistory.map((row) => (
                      <tr
                        key={`history-${row.id}`}
                        className={`clickable ${Number(activeExecutionId) === Number(row.id) ? "selected" : ""}`}
                        onClick={() => {
                          setActiveExecutionMode("manual");
                          setActiveExecutionId(row.id);
                        }}
                      >
                        <td>{row.id}</td>
                        <td>
                          <span className={`status-pill ${statusTone(row.status)}`}>{row.status || "-"}</span>
                        </td>
                        <td>{row.target || "-"}</td>
                        <td>{row.shell || "-"}</td>
                        <td className="ws-normal patch-workbench-command-cell" title={row.command || "-"}>
                          {row.command || "-"}
                        </td>
                        <td><RelativeTimestamp value={row.startedAt} /></td>
                        <td><RelativeTimestamp value={row.finishedAt} /></td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            <Pager
              total={history.length}
              page={historyPage}
              pageSize={historyPageSize}
              onPageChange={setHistoryPage}
              onPageSizeChange={(size) => {
                setHistoryPageSize(size);
                setHistoryPage(1);
              }}
              pageSizeOptions={[10, 15, 25, 50]}
              label="execution rows"
            />
          </>
        ) : (
          <div className="empty-state">History is collapsed.</div>
        )}
      </div>
    </div>
  );
}

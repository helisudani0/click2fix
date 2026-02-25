import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import ExecutionStream from "../components/ExecutionStream";
import Pager from "../components/Pager";
import { closeVulnerabilityLocal, getActions, getAgents, getAgentGroups, getVulnerabilities, runAction } from "../api/wazuh";
import { formatWazuhTimestamp } from "../utils/time";

const SEVERITIES = ["critical", "high", "medium", "low"];
const PLAN_MODES = {
  auto: "Auto",
  recommended: "Recommended",
  optional: "Optional",
};

const normalizeAgents = (data) => {
  if (Array.isArray(data)) return data;
  if (data?.data?.affected_items) return data.data.affected_items;
  if (data?.affected_items) return data.affected_items;
  if (data?.items) return data.items;
  return [];
};

const formatAgentId = (value) => {
  if (value === null || value === undefined) return "";
  const raw = String(value).trim();
  if (!raw) return "";
  return /^[0-9]+$/.test(raw) && raw.length < 3 ? raw.padStart(3, "0") : raw;
};

const severityClass = (value) => {
  const key = String(value || "").toLowerCase();
  if (key === "critical" || key === "high") return "failed";
  if (key === "medium") return "pending";
  if (key === "low") return "success";
  return "neutral";
};

const titleCase = (value) => {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "-";
  return text[0].toUpperCase() + text.slice(1);
};

const compactList = (items = []) => {
  const list = Array.isArray(items) ? items : [];
  return list.join(", ");
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const INITIAL_FETCH_LIMIT = 2500;
const FETCH_LIMIT_MAX = 20000;
const UPDATE_ACTION_IDS = new Set([
  "package-update",
  "software-install-upgrade",
  "fleet-software-update",
  "patch-windows",
  "windows-os-update",
  "patch-linux",
]);

const extractMetricValue = (text, key) => {
  const source = String(text || "");
  const match = source.match(new RegExp(`\\b${key}=([^\\s\\r\\n]+)`, "i"));
  return match ? String(match[1] || "").trim() : "";
};

const extractMetricInt = (text, key) => {
  const raw = extractMetricValue(text, key);
  if (!raw) return null;
  const parsed = Number.parseInt(raw, 10);
  return Number.isNaN(parsed) ? null : parsed;
};

const isUpdateAction = (actionId) => UPDATE_ACTION_IDS.has(String(actionId || "").trim().toLowerCase());

const isUpdateRowSuccessful = (row, allowWaitingReboot = true) => {
  if (!row?.ok) return false;
  const stdout = String(row?.stdout || "");
  const outcome = extractMetricValue(stdout, "outcome").toUpperCase();
  const failed = extractMetricInt(stdout, "updates_failed");
  const remaining = extractMetricInt(stdout, "updates_remaining");
  const unresolved = extractMetricInt(stdout, "updates_unresolved");
  const waitingReboot = allowWaitingReboot && outcome === "WAITING_REBOOT";
  const outcomeOk = outcome === "SUCCESS" || waitingReboot;
  const failedOk = failed === null || failed === 0;
  const remainingOk = remaining === null || remaining === 0;
  const unresolvedOk = unresolved === null || unresolved === 0;
  return outcomeOk && failedOk && remainingOk && unresolvedOk;
};

const isVerifiedUpdateStep = (actionId, runResponse) => {
  const action = String(actionId || "").trim().toLowerCase();
  if (!isUpdateAction(action)) return false;
  const result = runResponse?.data?.result;
  const rows = Array.isArray(result?.results) ? result.results : [];
  if (!rows.length) return false;
  return rows.every((row) => isUpdateRowSuccessful(row, false));
};

const extractExecutionIdFromError = (err) => {
  const direct = err?.response?.data?.execution_id;
  if (direct !== undefined && direct !== null && String(direct).trim()) return String(direct).trim();
  const detail = String(err?.response?.data?.detail || err?.message || "");
  const match = detail.match(/\bexecution_id=(\d+)\b/i);
  return match ? match[1] : "";
};

const isRunSuccessful = (actionId, runResponse) => {
  const payload = runResponse?.data || {};
  const status = String(payload?.status || "").trim().toUpperCase();
  if (status && status !== "SUCCESS") return false;
  const result = payload?.result;
  if (!result || typeof result !== "object") return true;
  if (typeof result.ok === "boolean") {
    if (!result.ok) return false;
    if (!Array.isArray(result.results)) return true;
  }
  if (Array.isArray(result.results) && result.results.length) {
    if (!result.results.every((row) => Boolean(row?.ok))) return false;
    if (isUpdateAction(actionId)) {
      return result.results.every((row) => isUpdateRowSuccessful(row, true));
    }
    return true;
  }
  if (isUpdateAction(actionId)) return false;
  return true;
};

const formatArgs = (args) => {
  if (!args || typeof args !== "object") return "-";
  const entries = Object.entries(args).filter((entry) => {
    const value = entry[1];
    return value !== undefined && value !== null && String(value).trim() !== "";
  });
  if (!entries.length) return "-";
  return entries.map(([key, value]) => `${key}=${value}`).join(", ");
};

const buildExecutionPlan = (rows, pickSteps) => {
  const stepPicker =
    typeof pickSteps === "function"
      ? pickSteps
      : (row) => (Array.isArray(row?.remediation?.steps) ? row.remediation.steps : []);
  const planMap = new Map();
  (rows || []).forEach((row) => {
    const rowId = String(row?.id || row?.cve || row?.title || "").trim();
    const rowSteps = stepPicker(row);
    rowSteps.forEach((step) => {
      const actionId = String(step?.action_id || "").trim();
      const args = step?.args && typeof step.args === "object" ? step.args : {};
      const agentIds = Array.isArray(step?.agent_ids)
        ? step.agent_ids.map((id) => String(id || "").trim()).filter(Boolean)
        : [];
      const mode = String(step?.mode || "auto");
      if (!actionId || !agentIds.length) return;
      const key = `${actionId}|${JSON.stringify(args)}`;
      if (!planMap.has(key)) {
        planMap.set(key, {
          action_id: actionId,
          args,
          agent_ids: new Set(),
          vulnerability_ids: new Set(),
          modes: new Set(),
        });
      }
      const entry = planMap.get(key);
      agentIds.forEach((id) => entry.agent_ids.add(id));
      if (rowId) entry.vulnerability_ids.add(rowId);
      if (mode) entry.modes.add(mode);
    });
  });

  return Array.from(planMap.values()).map((entry) => ({
    action_id: entry.action_id,
    args: entry.args,
    agent_ids: Array.from(entry.agent_ids).sort(),
    vulnerability_ids: Array.from(entry.vulnerability_ids),
    modes: Array.from(entry.modes),
  }));
};

export default function Vulnerabilities() {
  const navigate = useNavigate();
  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [targetMode, setTargetMode] = useState("fleet");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [agentSearch, setAgentSearch] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState([...SEVERITIES]);
  const [justification, setJustification] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [fixingKey, setFixingKey] = useState("");
  const [rowFixingId, setRowFixingId] = useState("");
  const [items, setItems] = useState([]);
  const [summary, setSummary] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
    records: 0,
    affected_agents: 0,
  });
  const [targetAgents, setTargetAgents] = useState({
    critical: [],
    high: [],
    medium: [],
    low: [],
  });
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [source, setSource] = useState("-");
  const [error, setError] = useState("");
  const [liveEnabled, setLiveEnabled] = useState(true);
  const [availableActionIds, setAvailableActionIds] = useState([]);
  const [feedPage, setFeedPage] = useState(1);
  const [feedPageSize, setFeedPageSize] = useState(50);
  const [fetchLimit, setFetchLimit] = useState(INITIAL_FETCH_LIMIT);
  const [truncated, setTruncated] = useState(false);
  const [queryLimit, setQueryLimit] = useState(INITIAL_FETCH_LIMIT);

  const loadAgents = useCallback(async () => {
    try {
      const res = await getAgents(undefined, { limit: 5000 });
      const list = normalizeAgents(res.data).map((row) => ({
        id: formatAgentId(row.id || row.agent_id),
        name: String(row.name || row.hostname || row.id || row.agent_id || "-"),
        status: String(row.status || "unknown"),
        group: Array.isArray(row.groups)
          ? row.groups.join(", ")
          : String(row.group || row.group_name || ""),
      }));
      setAgents(list.filter((row) => row.id));
    } catch {
      setAgents([]);
    }
  }, []);

  const loadGroups = useCallback(async () => {
    try {
      const res = await getAgentGroups();
      const raw = Array.isArray(res.data) ? res.data : [];
      setGroups(raw.map((group) => String(group.name || group.id || group)).filter(Boolean));
    } catch {
      setGroups([]);
    }
  }, []);

  const loadActions = useCallback(async () => {
    try {
      const res = await getActions();
      const list = Array.isArray(res?.data) ? res.data : [];
      const ids = list
        .map((row) => String(row?.id || "").trim().toLowerCase())
        .filter(Boolean);
      setAvailableActionIds(Array.from(new Set(ids)));
    } catch {
      setAvailableActionIds([]);
    }
  }, []);

  const buildScopeParams = useCallback(() => {
    if (targetMode === "group") {
      return targetValue.trim() ? { group: targetValue.trim() } : null;
    }
    if (targetMode === "agent") {
      return targetValue.trim() ? { agent_id: formatAgentId(targetValue.trim()) } : null;
    }
    if (targetMode === "multi") {
      return targetAgentIds.length ? { agent_ids: targetAgentIds.join(",") } : null;
    }
    return {};
  }, [targetMode, targetValue, targetAgentIds]);

  const loadVulns = useCallback(async () => {
    const scope = buildScopeParams();
    if (scope === null) {
      setStatus("Choose a valid target before loading vulnerabilities.");
      setTruncated(false);
      return;
    }

      setLoading(true);
      setStatus("");
      setError("");
      try {
      const params = { ...scope, limit: fetchLimit };
      const res = await getVulnerabilities(params);
      const payload = res.data || {};
      setItems(Array.isArray(payload.items) ? payload.items : []);
      setSummary({
        critical: Number(payload.summary?.critical || 0),
        high: Number(payload.summary?.high || 0),
        medium: Number(payload.summary?.medium || 0),
        low: Number(payload.summary?.low || 0),
        unknown: Number(payload.summary?.unknown || 0),
        total: Number(payload.summary?.total || 0),
        records: Number(payload.summary?.records || 0),
        affected_agents: Number(payload.summary?.affected_agents || 0),
      });
      setTargetAgents({
        critical: Array.isArray(payload.target_agents?.critical) ? payload.target_agents.critical : [],
        high: Array.isArray(payload.target_agents?.high) ? payload.target_agents.high : [],
        medium: Array.isArray(payload.target_agents?.medium) ? payload.target_agents.medium : [],
        low: Array.isArray(payload.target_agents?.low) ? payload.target_agents.low : [],
      });
      setTruncated(Boolean(payload.truncated));
      setQueryLimit(Number(payload.query_limit || fetchLimit));
      setSource(String(payload.source || "-"));
      setError(String(payload.error || ""));
    } catch (err) {
      setItems([]);
      setSummary({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
        total: 0,
        records: 0,
        affected_agents: 0,
      });
      setTargetAgents({ critical: [], high: [], medium: [], low: [] });
      setSource("-");
      setError(err.response?.data?.detail || err.message || "Failed to load vulnerabilities.");
      setStatus("");
      setTruncated(false);
      setQueryLimit(fetchLimit);
    } finally {
      setLoading(false);
    }
  }, [buildScopeParams, fetchLimit]);

  useEffect(() => {
    loadAgents();
    loadGroups();
    loadActions();
  }, [loadAgents, loadGroups, loadActions]);

  useEffect(() => {
    loadVulns();
  }, [loadVulns]);

  useEffect(() => {
    if (!liveEnabled) return undefined;
    const timer = setInterval(() => {
      loadVulns();
    }, 30000);
    return () => clearInterval(timer);
  }, [liveEnabled, loadVulns]);

  const filteredAgents = useMemo(() => {
    const q = agentSearch.trim().toLowerCase();
    if (!q) return agents.slice(0, 80);
    return agents
      .filter((agent) => {
        return (
          String(agent.id).toLowerCase().includes(q) ||
          String(agent.name).toLowerCase().includes(q) ||
          String(agent.group).toLowerCase().includes(q)
        );
      })
      .slice(0, 80);
  }, [agents, agentSearch]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(items.length / feedPageSize));
    if (feedPage > totalPages) {
      setFeedPage(totalPages);
    }
  }, [items.length, feedPage, feedPageSize]);

  const pagedItems = useMemo(() => {
    const start = (feedPage - 1) * feedPageSize;
    return items.slice(start, start + feedPageSize);
  }, [items, feedPage, feedPageSize]);

  const selectedRowsForPlan = useMemo(() => {
    const selected = new Set(selectedSeverities.map((value) => String(value).toLowerCase()));
    return (items || []).filter((row) => selected.has(String(row?.severity || "").toLowerCase()));
  }, [items, selectedSeverities]);

  const availableActionSet = useMemo(
    () => new Set((availableActionIds || []).map((id) => String(id || "").toLowerCase())),
    [availableActionIds]
  );

  const filterExecutableSteps = useCallback(
    (steps) => {
      const list = Array.isArray(steps) ? steps : [];
      if (!availableActionSet.size) return list;
      return list.filter((step) =>
        availableActionSet.has(String(step?.action_id || "").trim().toLowerCase())
      );
    },
    [availableActionSet]
  );

  const autoPlan = useMemo(
    () => filterExecutableSteps(buildExecutionPlan(selectedRowsForPlan)),
    [selectedRowsForPlan, filterExecutableSteps]
  );

  const recommendedPlan = useMemo(
    () =>
      filterExecutableSteps(buildExecutionPlan(selectedRowsForPlan, (row) => {
        const remediation = row?.remediation || {};
        return [
          ...(Array.isArray(remediation.verification_steps) ? remediation.verification_steps : []),
          ...(Array.isArray(remediation.investigation_steps) ? remediation.investigation_steps : []),
        ];
      })),
    [selectedRowsForPlan, filterExecutableSteps]
  );

  const optionalPlan = useMemo(
    () =>
      filterExecutableSteps(buildExecutionPlan(selectedRowsForPlan, (row) =>
        Array.isArray(row?.remediation?.optional_steps) ? row.remediation.optional_steps : []
      )),
    [selectedRowsForPlan, filterExecutableSteps]
  );

  const fallbackPlan = useMemo(
    () =>
      filterExecutableSteps(buildExecutionPlan(selectedRowsForPlan, (row) =>
        Array.isArray(row?.remediation?.fallback_steps) ? row.remediation.fallback_steps : []
      )),
    [selectedRowsForPlan, filterExecutableSteps]
  );

  const manualSteps = useMemo(() => {
    const set = new Set();
    selectedRowsForPlan.forEach((row) => {
      const list = Array.isArray(row?.remediation?.manual_steps) ? row.remediation.manual_steps : [];
      list.forEach((step) => {
        const text = String(step || "").trim();
        if (text) set.add(text);
      });
    });
    return Array.from(set);
  }, [selectedRowsForPlan]);

  const manualOnlyCount = useMemo(
    () =>
      selectedRowsForPlan.filter((row) => {
        const remediation = row?.remediation || {};
        const hasAuto = Array.isArray(remediation.steps) && remediation.steps.length > 0;
        const coverage = String(remediation.coverage || "").toLowerCase();
        return !hasAuto || coverage === "manual" || coverage === "investigate-first";
      }).length,
    [selectedRowsForPlan]
  );

  const executePlanSteps = useCallback(
    async (steps, justificationText) => {
      const executionIds = [];
      const runs = [];
      const errors = [];
      for (const step of steps) {
        const payload = {
          action_id: step.action_id,
          agent_ids: step.agent_ids,
          args: step.args,
          justification: justification.trim() || justificationText,
        };
        try {
          const res = await runAction(payload);
          const executionId = res?.data?.execution_id || null;
          if (executionId) {
            executionIds.push(executionId);
            setActiveExecutionId(executionId);
          }
          const ok = isRunSuccessful(step.action_id, res);
          if (!ok) errors.push(`${step.action_id}: execution reported failed/partial result.`);
          runs.push({ actionId: step.action_id, response: res, ok, error: ok ? "" : "execution failed" });
        } catch (err) {
          const executionId = extractExecutionIdFromError(err);
          if (executionId) {
            executionIds.push(executionId);
            setActiveExecutionId(executionId);
          }
          const msg = String(err?.response?.data?.detail || err?.message || "execution failed");
          errors.push(`${step.action_id}: ${msg}`);
          runs.push({ actionId: step.action_id, response: null, ok: false, error: msg });
        }
      }
      return {
        runs,
        executionIds,
        failures: runs.filter((run) => !run.ok).length,
        errors,
        total: steps.length,
      };
    },
    [justification]
  );

  const toggleSeverity = (severity) => {
    setSelectedSeverities((prev) => {
      if (prev.includes(severity)) return prev.filter((value) => value !== severity);
      return [...prev, severity];
    });
  };

  const runFix = async (severity) => {
    const rows = items.filter((row) => String(row?.severity || "").toLowerCase() === String(severity || "").toLowerCase());
    const steps = filterExecutableSteps(buildExecutionPlan(rows));
    const fallbackSteps = filterExecutableSteps(buildExecutionPlan(rows, (row) =>
      Array.isArray(row?.remediation?.fallback_steps) ? row.remediation.fallback_steps : []
    ));
    const manualCount = rows.filter((row) => !(Array.isArray(row?.remediation?.steps) && row.remediation.steps.length)).length;
    if (!steps.length && !fallbackSteps.length) {
      setStatus(`No auto-remediation mapped for ${severity}. Manual/investigation required for ${manualCount || rows.length} vulnerability entries.`);
      return;
    }

    setFixingKey(severity);
    setStatus("");
    setActiveExecutionId(null);
    try {
      const executionIds = [];
      const primary = await executePlanSteps(
        steps,
        `Severity remediation (${severity}) from vulnerability feed`
      );
      executionIds.push(...primary.executionIds);
      let fallbackRuns = null;
      if (primary.failures > 0 && fallbackSteps.length) {
        fallbackRuns = await executePlanSteps(
          fallbackSteps,
          `Fallback remediation (${severity}) after primary step failure`
        );
        executionIds.push(...fallbackRuns.executionIds);
      }
      const allExecutionIds = Array.from(new Set(executionIds));
      const totalFailures = primary.failures + (fallbackRuns?.failures || 0);
      setStatus(
        allExecutionIds.length
          ? `Remediation started for ${severity} via ${steps.length} primary step(s)${fallbackRuns ? ` + ${fallbackSteps.length} fallback step(s)` : ""}. Runs: ${allExecutionIds.join(", ")}.${totalFailures ? ` Some runs failed (${totalFailures}); check execution output.` : ""}${manualCount ? ` Manual follow-up needed for ${manualCount} entries.` : ""}`
          : `Remediation attempted for ${severity}.${totalFailures ? ` Failures: ${totalFailures}.` : ""}${manualCount ? ` Manual follow-up needed for ${manualCount} entries.` : ""}`
      );
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message || "Failed to run remediation.");
    } finally {
      setFixingKey("");
    }
  };

  const runFixAllVisible = async () => {
    const rows = items.filter((row) =>
      selectedSeverities.includes(String(row?.severity || "").toLowerCase())
    );
    const steps = filterExecutableSteps(buildExecutionPlan(rows));
    const fallbackSteps = filterExecutableSteps(buildExecutionPlan(rows, (row) =>
      Array.isArray(row?.remediation?.fallback_steps) ? row.remediation.fallback_steps : []
    ));
    const manualCount = rows.filter((row) => !(Array.isArray(row?.remediation?.steps) && row.remediation.steps.length)).length;
    if (!steps.length && !fallbackSteps.length) {
      setStatus(`No auto-remediation steps. Manual/investigation required for ${manualCount || rows.length} entries.`);
      return;
    }
    setFixingKey("all");
    setStatus("");
    setActiveExecutionId(null);
    try {
      const label = selectedSeverities.map((severity) => titleCase(severity)).join(", ");
      const executionIds = [];
      const primary = await executePlanSteps(
        steps,
        `Bulk vulnerability remediation for severities: ${label}`
      );
      executionIds.push(...primary.executionIds);
      let fallbackRuns = null;
      if (primary.failures > 0 && fallbackSteps.length) {
        fallbackRuns = await executePlanSteps(
          fallbackSteps,
          `Bulk fallback vulnerability remediation for severities: ${label}`
        );
        executionIds.push(...fallbackRuns.executionIds);
      }
      const allExecutionIds = Array.from(new Set(executionIds));
      const totalFailures = primary.failures + (fallbackRuns?.failures || 0);
      setStatus(
        allExecutionIds.length
          ? `Bulk remediation started via ${steps.length} primary step(s)${fallbackRuns ? ` + ${fallbackSteps.length} fallback step(s)` : ""}. Runs: ${allExecutionIds.join(", ")}.${totalFailures ? ` Some runs failed (${totalFailures}); review execution details.` : ""}${manualCount ? ` Manual follow-up needed for ${manualCount} entries.` : ""}`
          : `Bulk remediation attempted.${totalFailures ? ` Failures: ${totalFailures}.` : ""}${manualCount ? ` Manual follow-up needed for ${manualCount} entries.` : ""}`
      );
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message || "Failed to run bulk remediation.");
    } finally {
      setFixingKey("");
    }
  };

  const verifyVulnerabilityCleared = useCallback(async (row, attempts = 8, intervalMs = 15000) => {
    const agentIds = (Array.isArray(row?.affected_agents) ? row.affected_agents : [])
      .map((agent) => formatAgentId(agent?.id))
      .filter(Boolean);
    if (!agentIds.length) return false;
    const vulnId = String(row?.id || "").trim();
    if (!vulnId) return false;

    for (let i = 0; i < attempts; i += 1) {
      try {
        const res = await getVulnerabilities({
          agent_ids: agentIds.join(","),
          include_resolved: false,
          limit: 2000,
        });
        const latest = Array.isArray(res?.data?.items) ? res.data.items : [];
        const stillPresent = latest.some((item) => String(item?.id || "").trim() === vulnId);
        if (!stillPresent) return true;
      } catch {
        // Best-effort verification loop; retry on transient API errors.
      }
      await sleep(intervalMs);
    }
    return false;
  }, []);

  const runFeedFix = async (row) => {
    const remediation = row?.remediation || {};
    const steps = filterExecutableSteps(Array.isArray(remediation.steps) ? remediation.steps : []);
    const fallbackSteps = filterExecutableSteps(Array.isArray(remediation.fallback_steps) ? remediation.fallback_steps : []);
    if (!steps.length && !fallbackSteps.length) {
      const manual = Array.isArray(remediation.manual_steps) ? remediation.manual_steps : [];
      setStatus(
        manual.length
          ? `No auto-remediation for this vulnerability. Manual steps: ${manual.join(" | ")}`
          : "No mapped remediation steps for this vulnerability."
      );
      return;
    }

    setRowFixingId(String(row.id || ""));
    setStatus("");
    setActiveExecutionId(null);
    try {
      const title =
        row?.cve
        || (String(row?.title || "").toLowerCase() !== "vulnerability" ? row?.title : "")
        || row?.package?.name
        || row?.id;
      const justificationBase = `Vulnerability remediation from feed: ${title}`;
      const primary = await executePlanSteps(steps, justificationBase);
      const executedSteps = [...primary.runs];
      const executionIds = [...primary.executionIds];
      let fallbackRuns = null;
      if (primary.failures > 0 && fallbackSteps.length) {
        fallbackRuns = await executePlanSteps(
          fallbackSteps,
          `Fallback remediation from feed: ${title}`
        );
        executedSteps.push(...fallbackRuns.runs);
        executionIds.push(...fallbackRuns.executionIds);
      }

      const dedupExecutionIds = Array.from(new Set(executionIds));
      if (dedupExecutionIds.length) {
        setStatus(
          `Started ${steps.length} primary step(s)${fallbackRuns ? ` + ${fallbackSteps.length} fallback step(s)` : ""} for ${row?.cve || row?.title || row?.id}. Runs: ${dedupExecutionIds.join(", ")}. Verifying vulnerability clearance...`
        );
        const verificationCandidates = executedSteps.filter((step) => isUpdateAction(step.actionId));
        const endpointVerified =
          verificationCandidates.length > 0 &&
          verificationCandidates.every((step) => isVerifiedUpdateStep(step.actionId, step.response));
        void (async () => {
          const cleared = await verifyVulnerabilityCleared(row);
          if (cleared) {
            setStatus(
              `Verified: ${row?.cve || row?.title || row?.id} is no longer reported for targeted endpoint(s).`
            );
            await loadVulns();
            return;
          }
          if (endpointVerified) {
            const closePayload = {
              vulnerability_id: String(row?.id || "").trim(),
              agent_ids: (Array.isArray(row?.affected_agents) ? row.affected_agents : [])
                .map((agent) => formatAgentId(agent?.id))
                .filter(Boolean),
              execution_id: dedupExecutionIds[dedupExecutionIds.length - 1] || null,
              reason: "Endpoint remediation verified by action output; Wazuh feed not yet cleared.",
            };
            if (closePayload.vulnerability_id && closePayload.agent_ids.length) {
              try {
                await closeVulnerabilityLocal(closePayload);
                setStatus(
                  `Endpoint remediation verified for ${row?.cve || row?.title || row?.id}. Hidden locally until Wazuh feed reflects clearance.`
                );
                await loadVulns();
                return;
              } catch {
                // Ignore local-close failures and fall back to feed status message.
              }
            }
          }
          setStatus(
            `Execution completed, but Wazuh still reports ${row?.cve || row?.title || row?.id}. It will remain visible until the feed confirms fix.`
          );
        })();
      } else {
        setStatus("No executable remediation steps resolved for this vulnerability.");
      }
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message || "Failed to run vulnerability remediation.");
    } finally {
      setRowFixingId("");
    }
  };

  const buildGlobalShellPrefill = useCallback((row) => {
    const remediation = row?.remediation && typeof row.remediation === "object" ? row.remediation : {};
    const manualShell = remediation.manual_shell && typeof remediation.manual_shell === "object"
      ? remediation.manual_shell
      : null;
    const command = String(manualShell?.command || "").trim();
    if (!command) return null;

    const explicitAgentIds = Array.isArray(manualShell?.agent_ids)
      ? manualShell.agent_ids.map((id) => formatAgentId(id)).filter(Boolean)
      : [];
    const rowAgentIds = Array.isArray(row?.affected_agents)
      ? row.affected_agents.map((agent) => formatAgentId(agent?.id)).filter(Boolean)
      : [];
    const agentIds = explicitAgentIds.length ? explicitAgentIds : rowAgentIds;
    if (!agentIds.length) return null;
    const mode = agentIds.length === 1 ? "agent" : "multi";
    const target = mode === "agent" ? agentIds[0] : "";
    const targetIds = mode === "multi" ? agentIds : [];

    const vulnLabel = row?.cve || row?.title || row?.id || "vulnerability";
    const reason = String(manualShell?.reason || "").trim();
    const sourceKey = String(manualShell?.source || "").trim().toLowerCase();
    const isAiGenerated = sourceKey === "ai-generated" || sourceKey === "ai-heuristic";
    const modelHint = isAiGenerated
      ? "AI-generated"
      : "Manual";
    const justificationText = [
      `${modelHint} remediation from Vulnerabilities feed: ${vulnLabel}`,
      reason,
      justification.trim(),
    ]
      .filter(Boolean)
      .join(" | ");

    return {
      shell: String(manualShell?.shell || "powershell").trim().toLowerCase() === "cmd" ? "cmd" : "powershell",
      command,
      targetMode: mode,
      targetValue: target,
      targetAgentIds: targetIds,
      runAsSystem: Boolean(manualShell?.run_as_system),
      verifyKb: String(manualShell?.verify_kb || "").trim(),
      verifyMinBuild: String(manualShell?.verify_min_build || "").trim(),
      verifyStdoutContains: String(manualShell?.verify_stdout_contains || "").trim(),
      justification: justificationText,
    };
  }, [justification]);

  const openManualShell = useCallback((row) => {
    const prefill = buildGlobalShellPrefill(row);
    if (!prefill) {
      setStatus("No Global Shell command is available for this vulnerability (missing command or affected agent IDs).");
      return;
    }
    navigate("/global-shell", {
      state: {
        prefill,
        source: "vulnerabilities",
        vulnerability: {
          id: row?.id || "",
          cve: row?.cve || "",
          title: row?.title || "",
          severity: row?.severity || "",
        },
      },
    });
  }, [buildGlobalShellPrefill, navigate]);

  const loadMoreResults = () => {
    setFetchLimit((prev) => Math.min(prev * 2, FETCH_LIMIT_MAX));
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Vulnerabilities</h2>
          <p className="muted">
            Wazuh vulnerability view with one-click remediation by severity.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={loadVulns} disabled={loading}>
            {loading ? "Loading..." : "Refresh"}
          </button>
          <button className="btn secondary" onClick={() => setLiveEnabled((v) => !v)}>
            Live: {liveEnabled ? "On" : "Off"}
          </button>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}
      {error ? <div className="empty-state">Error: {error}</div> : null}
      {truncated ? (
        <div className="empty-state">
          Results are capped at {queryLimit} source records for fast response.
          <div className="page-actions mt-8">
            <button className="btn secondary" onClick={loadMoreResults} disabled={loading || fetchLimit >= FETCH_LIMIT_MAX}>
              {fetchLimit >= FETCH_LIMIT_MAX ? "Max Limit Reached" : "Load More Results"}
            </button>
          </div>
        </div>
      ) : null}

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Scope & Filters</h3>
            <p className="muted">Select endpoint scope, severities, and run remediation.</p>
          </div>
        </div>
        <div className="page-actions">
          <select className="input" value={targetMode} onChange={(e) => setTargetMode(e.target.value)}>
            <option value="fleet">Fleet</option>
            <option value="group">Group</option>
            <option value="agent">Single agent</option>
            <option value="multi">Multiple agents</option>
          </select>

          {targetMode === "group" ? (
            <select className="input" value={targetValue} onChange={(e) => setTargetValue(e.target.value)}>
              <option value="">Select group</option>
              {groups.map((group) => (
                <option key={group} value={group}>
                  {group}
                </option>
              ))}
            </select>
          ) : null}

          {targetMode === "agent" ? (
            <select className="input" value={targetValue} onChange={(e) => setTargetValue(e.target.value)}>
              <option value="">Select agent</option>
              {agents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.id} - {agent.name}
                </option>
              ))}
            </select>
          ) : null}
        </div>

        {targetMode === "multi" ? (
          <>
            <input
              className="input"
              placeholder="Search agents by ID, name, or group"
              value={agentSearch}
              onChange={(e) => setAgentSearch(e.target.value)}
            />
            <div className="list">
              {filteredAgents.map((agent) => {
                const selected = targetAgentIds.includes(agent.id);
                return (
                  <button
                    key={agent.id}
                    className={`list-item ${selected ? "selected" : ""}`}
                    onClick={() =>
                      setTargetAgentIds((prev) =>
                        prev.includes(agent.id)
                          ? prev.filter((id) => id !== agent.id)
                          : [...prev, agent.id]
                      )
                    }
                  >
                    <div>
                      <strong>{agent.id}</strong> - {agent.name}
                      <div className="muted">{agent.group || "No group"}</div>
                    </div>
                    <span className={`status-pill ${selected ? "success" : "neutral"}`}>
                      {selected ? "Selected" : agent.status}
                    </span>
                  </button>
                );
              })}
            </div>
          </>
        ) : null}

        <div className="page-actions">
          {SEVERITIES.map((severity) => (
            <label key={severity} className="muted inline-check tight">
              <input
                type="checkbox"
                checked={selectedSeverities.includes(severity)}
                onChange={() => toggleSeverity(severity)}
              />
              {titleCase(severity)}
            </label>
          ))}
        </div>

        <textarea
          className="input"
          placeholder="Remediation justification (optional but recommended)"
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
        />

        <div className="page-actions">
          <button className="btn secondary" onClick={runFixAllVisible} disabled={loading || fixingKey === "all"}>
            {fixingKey === "all" ? "Running..." : "Fix Selected Severities"}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Execution Plan Preview</h3>
            <p className="muted">
              Preview for selected severities in current scope before running remediation.
            </p>
          </div>
        </div>
        <div className="stat-grid">
          <div className="stat-card">
            <div className="stat-label">Auto Steps</div>
            <div className="stat-value">{autoPlan.length}</div>
            <div className="stat-sub">Executable now</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Recommended</div>
            <div className="stat-value">{recommendedPlan.length}</div>
            <div className="stat-sub">Validation / hunt steps</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Optional</div>
            <div className="stat-value">{optionalPlan.length}</div>
            <div className="stat-sub">IR follow-up steps</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Fallback</div>
            <div className="stat-value">{fallbackPlan.length}</div>
            <div className="stat-sub">Auto on failure</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Manual Review</div>
            <div className="stat-value">{manualOnlyCount}</div>
            <div className="stat-sub">Vulns without full automation</div>
          </div>
        </div>

        {autoPlan.length ? (
          <div className="table-scroll">
            <table className="table readable compact">
              <thead>
                <tr>
                  <th>Mode</th>
                  <th>Action</th>
                  <th>Args</th>
                  <th>Targets</th>
                  <th>Mapped Vulns</th>
                </tr>
              </thead>
              <tbody>
                {autoPlan.map((step) => (
                  <tr key={`auto-${step.action_id}-${JSON.stringify(step.args)}`}>
                    <td>
                      <span className="status-pill success">{PLAN_MODES.auto}</span>
                    </td>
                    <td>{step.action_id}</td>
                    <td className="muted">{formatArgs(step.args)}</td>
                    <td>{step.agent_ids.length}</td>
                    <td>{step.vulnerability_ids.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">No auto-executable steps for selected vulnerabilities.</div>
        )}

        {recommendedPlan.length ? (
          <div className="table-scroll">
            <table className="table readable compact">
              <thead>
                <tr>
                  <th>Mode</th>
                  <th>Action</th>
                  <th>Args</th>
                  <th>Targets</th>
                  <th>Mapped Vulns</th>
                </tr>
              </thead>
              <tbody>
                {recommendedPlan.map((step) => (
                  <tr key={`recommended-${step.action_id}-${JSON.stringify(step.args)}`}>
                    <td>
                      <span className="status-pill pending">{PLAN_MODES.recommended}</span>
                    </td>
                    <td>{step.action_id}</td>
                    <td className="muted">{formatArgs(step.args)}</td>
                    <td>{step.agent_ids.length}</td>
                    <td>{step.vulnerability_ids.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        {optionalPlan.length ? (
          <div className="table-scroll">
            <table className="table readable compact">
              <thead>
                <tr>
                  <th>Mode</th>
                  <th>Action</th>
                  <th>Args</th>
                  <th>Targets</th>
                  <th>Mapped Vulns</th>
                </tr>
              </thead>
              <tbody>
                {optionalPlan.map((step) => (
                  <tr key={`optional-${step.action_id}-${JSON.stringify(step.args)}`}>
                    <td>
                      <span className="status-pill neutral">{PLAN_MODES.optional}</span>
                    </td>
                    <td>{step.action_id}</td>
                    <td className="muted">{formatArgs(step.args)}</td>
                    <td>{step.agent_ids.length}</td>
                    <td>{step.vulnerability_ids.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        {fallbackPlan.length ? (
          <div className="table-scroll">
            <table className="table readable compact">
              <thead>
                <tr>
                  <th>Mode</th>
                  <th>Action</th>
                  <th>Args</th>
                  <th>Targets</th>
                  <th>Mapped Vulns</th>
                </tr>
              </thead>
              <tbody>
                {fallbackPlan.map((step) => (
                  <tr key={`fallback-${step.action_id}-${JSON.stringify(step.args)}`}>
                    <td>
                      <span className="status-pill pending">Fallback</span>
                    </td>
                    <td>{step.action_id}</td>
                    <td className="muted">{formatArgs(step.args)}</td>
                    <td>{step.agent_ids.length}</td>
                    <td>{step.vulnerability_ids.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        {manualSteps.length ? (
          <div className="empty-state">
            Manual steps: {manualSteps.join(" | ")}
          </div>
        ) : null}
      </div>

      <div className="stat-grid">
        {SEVERITIES.map((severity) => (
          <div className="stat-card" key={severity}>
            <div className="stat-label">{titleCase(severity)}</div>
            <div className="stat-value">{Number(summary?.[severity] || 0)}</div>
            <div className="stat-sub">
              Agents affected: {Array.isArray(targetAgents?.[severity]) ? targetAgents[severity].length : 0}
            </div>
            <div className="page-actions">
              <button
                className="btn secondary"
                onClick={() => runFix(severity)}
                disabled={loading || fixingKey === severity}
              >
                {fixingKey === severity ? "Running..." : `Fix ${titleCase(severity)}`}
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Vulnerability Feed</h3>
            <p className="muted">
              Source: {source}. Unique vulnerabilities: {summary.total}. Records scanned: {summary.records}. Affected agents: {summary.affected_agents}.
            </p>
          </div>
        </div>
        <div className="table-scroll">
          <table className="table readable compact">
            <thead>
              <tr>
                <th>CVE / Title</th>
                <th>Severity</th>
                <th>Package</th>
                <th>Affected</th>
                <th>Condition</th>
                <th>Last Seen</th>
                <th>References</th>
                <th>Recommended Fix</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr>
                  <td colSpan={9} className="muted">
                    No vulnerabilities in this scope/filter.
                  </td>
                </tr>
              ) : (
                pagedItems.map((row) => {
                  const refs = Array.isArray(row.references) ? row.references : [];
                  const firstRef = refs[0] || row.scanner_reference || "";
                  const manualShell = row?.remediation?.manual_shell && typeof row.remediation.manual_shell === "object"
                    ? row.remediation.manual_shell
                    : null;
                  const manualCommand = String(manualShell?.command || "").trim();
                  return (
                    <tr key={row.id}>
                      <td>
                        <div>{row.cve || "-"}</div>
                        <div className="muted">{row.title || "-"}</div>
                      </td>
                      <td>
                        <span className={`status-pill ${severityClass(row.severity)}`}>
                          {titleCase(row.severity)}
                        </span>
                        {row.score !== null && row.score !== undefined ? (
                          <div className="muted">CVSS {row.score}</div>
                        ) : null}
                      </td>
                      <td>
                        <div>{row.package?.name || "-"}</div>
                        <div className="muted">{row.package?.version || "-"}</div>
                      </td>
                      <td>
                        <div>{row.affected_count || 0} agent(s)</div>
                        <div className="muted">
                          {compactList(
                            (row.affected_agents || []).map(
                              (agent) => `${agent.id}${agent.name ? `:${agent.name}` : ""}`
                            ),
                            3
                          )}
                        </div>
                      </td>
                      <td>{row.package?.condition || "-"}</td>
                      <td>{formatWazuhTimestamp(row.last_seen)}</td>
                      <td>
                        {firstRef ? (
                          <a href={firstRef} target="_blank" rel="noreferrer">
                            Open ({refs.length || 1})
                          </a>
                        ) : (
                          <span className="muted">-</span>
                        )}
                        
                      </td>
                      <td>
                        <div>{row.remediation?.summary || "-"}</div>
                        <div className="muted">
                          Coverage: {titleCase(
                            row.remediation?.coverage
                              || ((row.remediation?.steps || []).length ? "automated" : "manual")
                          )} | Confidence:{" "}
                          {titleCase(row.remediation?.confidence || "low")}
                        </div>
                        <div className="muted">
                          Auto: {(row.remediation?.steps || []).length} | Recommended:{" "}
                          {((row.remediation?.verification_steps || []).length +
                            (row.remediation?.investigation_steps || []).length) || 0}{" "}
                          | Optional: {(row.remediation?.optional_steps || []).length || 0}{" "}
                          | Fallback: {(row.remediation?.fallback_steps || []).length || 0}
                        </div>
                        <div className="muted">
                          {(row.remediation?.steps || [])
                            .map((step) => `${step.action_id}${step.args?.package ? `(${step.args.package})` : ""}`)
                            .join(" | ") || "No direct auto-remediation step."}
                          {Array.isArray(row.remediation?.fallback_steps) && row.remediation.fallback_steps.length
                            ? ` | fallback: ${row.remediation.fallback_steps.map((step) => step.action_id).join(" | ")}`
                            : ""}
                        </div>
                        {manualCommand ? (
                          <div className="muted">
                            {(String(manualShell?.source || "").toLowerCase() === "ai-generated"
                              || String(manualShell?.source || "").toLowerCase() === "ai-heuristic")
                              ? "Generated operator-ready PowerShell command available in Global Shell."
                              : "Manual Global Shell fallback available."}
                          </div>
                        ) : null}
                        {manualCommand && manualShell?.strategy ? (
                          <div className="muted">
                            Strategy: {String(manualShell.strategy)}
                          </div>
                        ) : null}
                        {manualCommand && manualShell?.reason ? (
                          <div className="muted">
                            {String(manualShell.reason)}
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <button
                          className="btn secondary"
                          onClick={() => runFeedFix(row)}
                          disabled={rowFixingId === String(row.id || "")}
                        >
                          {rowFixingId === String(row.id || "") ? "Running..." : "Fix This"}
                        </button>
                        <button
                          className="btn secondary mt-8"
                          onClick={() => openManualShell(row)}
                          disabled={!manualCommand}
                          title={manualCommand ? "Open Global Shell with prefilled command and targets" : "No manual shell command provided for this vulnerability"}
                        >
                          Manual Shell
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        <Pager
          total={items.length}
          page={feedPage}
          pageSize={feedPageSize}
          onPageChange={setFeedPage}
          onPageSizeChange={(size) => {
            setFeedPageSize(size);
            setFeedPage(1);
          }}
          pageSizeOptions={[25, 50, 100]}
          label="vulnerabilities"
        />
      </div>

      {activeExecutionId ? (
        <ExecutionStream executionId={activeExecutionId} title={`Remediation Run #${activeExecutionId}`} />
      ) : null}
    </div>
  );
}

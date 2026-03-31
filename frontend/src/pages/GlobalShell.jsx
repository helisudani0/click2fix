import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import ExecutionStream from "../components/ExecutionStream";
import Pager from "../components/Pager";
import RelativeTimestamp from "../components/RelativeTimestamp";
import SideDrawer from "../components/SideDrawer";
import {
  getAgents,
  getExecutions,
  getSystemAiConfig,
  runGlobalShell,
  suggestGlobalShellCommand,
} from "../api/wazuh";
import { formatApiError } from "../utils/httpErrors";
import { buildHumanReadableOutput, normalizeOutputText, summarizeReadableOutput } from "../utils/output";

const CONNECTED_STATUSES = new Set(["active", "connected", "online"]);
const FLEET_TARGETS = new Set(["all", "*", "fleet", "all-active"]);
const TARGET_MODE_LABELS = {
  agent: "Single agent",
  multi: "Multiple agents",
  group: "Specific group",
  fleet: "Fleet",
};
const asFlag = (value, defaultValue) => {
  if (value === undefined || value === null || value === "") return defaultValue;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return defaultValue;
};
const ASSIST_ENV_ENABLED = asFlag(
  import.meta.env.VITE_C2F_AI_FEATURES_ENABLED,
  asFlag(import.meta.env.VITE_AI_REMEDIATION_ENABLED, true)
);
const looksLikeAssistantUnavailable = (text) => {
  const lowered = String(text || "").toLowerCase();
  return (
    lowered.includes("ai remediation is disabled")
    || lowered.includes("ai features are disabled")
    || lowered.includes("unsupported ai provider")
    || lowered.includes("requires api_key")
  );
};
const WINDOWS_UPDATE_PRESET_COMMAND =
  "Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot";
const WINDOWS_UPDATE_SCAN_PRESET_COMMAND =
  "Get-WindowsUpdate -MicrosoftUpdate";
const TARGETED_UPGRADE_PRESET_COMMAND =
  "winget upgrade --id PACKAGE_HINT --exact";
const UPGRADE_PRESETS = [
  {
    id: "windows-update-scan",
    label: "Windows Update Scan",
    shell: "powershell",
    runAsSystem: true,
    description: "List pending Windows updates (no install).",
    command: WINDOWS_UPDATE_SCAN_PRESET_COMMAND,
  },
  {
    id: "windows-update",
    label: "Windows Security Updates",
    shell: "powershell",
    runAsSystem: true,
    description: "Install pending Windows updates. Requires PSWindowsUpdate.",
    command: WINDOWS_UPDATE_PRESET_COMMAND,
  },
  {
    id: "winget-all",
    label: "Winget Upgrade All",
    shell: "powershell",
    runAsSystem: false,
    description: "Upgrade all upgradable winget-managed packages.",
    command: "winget upgrade --all",
  },
  {
    id: "choco-all",
    label: "Chocolatey Upgrade All",
    shell: "powershell",
    runAsSystem: false,
    description: "Upgrade all Chocolatey packages.",
    command: "choco upgrade all -y",
  },
  {
    id: "targeted-fallback",
    label: "Targeted Package Upgrade",
    shell: "powershell",
    runAsSystem: false,
    description: "Set PACKAGE_HINT and run a direct winget package upgrade.",
    command: TARGETED_UPGRADE_PRESET_COMMAND,
  },
];

const normalizeAgents = (data) => {
  if (Array.isArray(data)) return data;
  if (data?.data?.affected_items) return data.data.affected_items;
  if (data?.affected_items) return data.affected_items;
  if (data?.items) return data.items;
  return [];
};

const formatAgentId = (raw) => {
  if (raw === null || raw === undefined) return "";
  const str = String(raw).trim();
  if (!str) return "";
  return /^[0-9]+$/.test(str) && str.length < 3 ? str.padStart(3, "0") : str;
};

const toAgentGroups = (agent) => {
  const values = [];
  const appendValue = (value) => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) {
      value.forEach((item) => appendValue(item));
      return;
    }
    const text = String(value).trim();
    if (!text) return;
    if (text.includes(",")) {
      text.split(",").forEach((part) => appendValue(part));
      return;
    }
    values.push(text);
  };
  appendValue(agent?.group);
  appendValue(agent?.groups);
  appendValue(agent?.group_name);
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

const parseExcludeIds = (value) =>
  new Set(
    String(value || "")
      .split(",")
      .map((item) => formatAgentId(item))
      .filter(Boolean)
  );

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
      if (typeof candidate === "string" && candidate.trim()) {
        return candidate.trim();
      }
    }
    const firstString = Object.values(parsed).find((item) => typeof item === "string" && item.trim());
    return typeof firstString === "string" ? firstString.trim() : "";
  }
  if (typeof parsed === "string") return parsed.trim();
  return "";
};

const resolveShellAndCommand = (argsValue) => {
  const commandUsed = extractCommandFromArgs(argsValue);
  if (!commandUsed) return { shell: "-", commandUsed: "", command: "" };
  const cmdMatch = commandUsed.match(/^cmd(?:\.exe)?\s+\/c\s+([\s\S]+)$/i);
  if (cmdMatch) {
    const raw = String(cmdMatch[1] || "").trim();
    return { shell: "CMD", commandUsed, command: raw || commandUsed };
  }
  return { shell: "PowerShell", commandUsed, command: commandUsed.trim() };
};

const summarizeConsolePreview = (value, limit = 180) => {
  const text = summarizeReadableOutput(value, limit);
  if (!text) return "";
  return text;
};

const summarizeRawPreview = (value, limit = 180) => {
  const text = normalizeOutputText(value);
  if (!text) return "";
  if (text.length <= limit) return text;
  return `${text.slice(0, limit)}...`;
};

const formatTargetLabel = (raw) => {
  const value = String(raw || "").trim();
  if (!value) return "-";
  const lowered = value.toLowerCase();
  if (lowered.startsWith("multi:")) {
    const ids = value
      .slice(value.indexOf(":") + 1)
      .split(",")
      .map((part) => formatAgentId(part))
      .filter(Boolean);
    if (!ids.length) return "0 agents";
    const lead = ids.slice(0, 3).join(", ");
    return `${ids.length} agent(s): ${lead}${ids.length > 3 ? ", ..." : ""}`;
  }
  if (lowered.startsWith("group:")) {
    const group = value.slice(value.indexOf(":") + 1).trim();
    return `Group: ${group || "-"}`;
  }
  if (FLEET_TARGETS.has(lowered)) return "Fleet";
  return value;
};

const formatTargetHealth = (row) => {
  const total = Number(row?.summary?.total || row?.targetCount || 0);
  const success = Number(row?.summary?.success || row?.targetSuccess || 0);
  const failed = Number(row?.summary?.failed || row?.targetFailed || 0);
  if (!total) return "";
  return failed > 0 ? `${success}/${total} ok | ${failed} failed` : `${success}/${total} ok`;
};

const normalizeExecutions = (rows) => {
  const list = Array.isArray(rows) ? rows : [];
  return list
    .map((row) => {
      const action = row?.action || row?.playbook || "";
      const commandMeta = resolveShellAndCommand(row?.args);
      const latestStdout = row?.latest_stdout || "";
      const latestStderr = row?.latest_stderr || "";
      const cleanOutputPreview = summarizeConsolePreview(
        buildHumanReadableOutput(latestStdout, latestStderr, { status: row?.status || "" }),
        220
      );
      const rawOutputPreview = summarizeRawPreview(latestStderr || latestStdout, 220);
      return {
        id: row?.id,
        action,
        agent: row?.agent || "",
        targetLabel: formatTargetLabel(row?.agent || ""),
        status: row?.status || "",
        startedAt: row?.started_at || row?.startedAt || "",
        finishedAt: row?.finished_at || row?.finishedAt || "",
        shell: commandMeta.shell,
        command: commandMeta.command || commandMeta.commandUsed || "",
        commandUsed: commandMeta.commandUsed || "",
        outputPreview: rawOutputPreview || "",
        cleanOutputPreview: cleanOutputPreview || "",
        targetCount: Number(row?.target_count || 0),
        targetSuccess: Number(row?.target_success || 0),
        targetFailed: Number(row?.target_failed || row?.summary?.failed || 0),
        summary: row?.summary || null,
      };
    })
    .filter((row) => row.id && String(row.action || "").toLowerCase().includes("global-shell"));
};

const statusTone = (status) => {
  const value = String(status || "").toUpperCase();
  if (value === "SUCCESS") return "success";
  if (["FAILED", "ERROR", "KILLED"].includes(value)) return "failed";
  if (["RUNNING", "PAUSED", "PENDING", "PENDING_VERIFICATION", "QUEUED", "CANCELLED", "PARTIAL"].includes(value)) return "pending";
  return "neutral";
};

export default function GlobalShell() {
  const location = useLocation();
  const prefillAppliedRef = useRef("");
  const [agents, setAgents] = useState([]);
  const [agentsError, setAgentsError] = useState("");
  const [agentsLoading, setAgentsLoading] = useState(true);

  const [shell, setShell] = useState("powershell");
  const [command, setCommand] = useState("");
  const [runAsSystem, setRunAsSystem] = useState(false);
  const [assistantPrompt, setAssistantPrompt] = useState("");
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [assistantPlan, setAssistantPlan] = useState(null);
  const [assistantEnabled, setAssistantEnabled] = useState(ASSIST_ENV_ENABLED);
  const [assistantDisabledReason, setAssistantDisabledReason] = useState("");
  const [autoRemediate, setAutoRemediate] = useState(false);
  const [maxAttempts, setMaxAttempts] = useState(3);
  const [vulnerabilityContext, setVulnerabilityContext] = useState(null);
  const [upgradePreset, setUpgradePreset] = useState("");
  const [verifyKb, setVerifyKb] = useState("");
  const [verifyMinBuild, setVerifyMinBuild] = useState("");
  const [verifyStdoutContains, setVerifyStdoutContains] = useState("");
  const [targetMode, setTargetMode] = useState("fleet");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [multiPickAgentId, setMultiPickAgentId] = useState("");
  const [excludeIdsText, setExcludeIdsText] = useState("");
  const [justification, setJustification] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [status, setStatus] = useState("");
  const [historyLoading, setHistoryLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [targetPage, setTargetPage] = useState(1);
  const [targetPageSize, setTargetPageSize] = useState(50);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPageSize, setHistoryPageSize] = useState(25);

  const loadAgents = useCallback(async (force = false) => {
    setAgentsLoading(true);
    setAgentsError("");
    try {
      const res = await getAgents(undefined, {
        force,
        limit: 5000,
        status: "active,connected,online",
        compact: true,
      });
      const parsed = normalizeAgents(res.data)
        .map((agent) => {
          const groups = toAgentGroups(agent);
          return {
            id: formatAgentId(agent?.id || agent?.agent_id),
            name: String(agent?.name || agent?.hostname || "").trim(),
            status: agentStatus(agent),
            platform: agentPlatform(agent),
            groups,
            groupText: groups.join(", "),
          };
        })
        .filter((agent) => agent.id);
      setAgents(parsed);
    } catch (err) {
      setAgents([]);
      setAgentsError(formatApiError(err, "Failed to load agents."));
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  const loadHistory = useCallback(async (force = false) => {
    setHistoryLoading(true);
    try {
      const res = await getExecutions({ limit: 120, q: "global-shell" }, { force });
      const rows = normalizeExecutions(res.data);
      setHistory(rows);
      setActiveExecutionId((current) => {
        if (current && rows.some((row) => Number(row.id) === Number(current))) {
          return current;
        }
        return null;
      });
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const refreshAssistantAvailability = useCallback(async () => {
    try {
      const res = await getSystemAiConfig();
      const node = res?.data?.ai_config || {};
      const enabled = Boolean(node?.enabled);
      setAssistantEnabled(enabled);
      setAssistantDisabledReason(
        enabled ? "" : "AI assistant is disabled. Enable it in Org Admin / Platform AI Configuration."
      );
      return enabled;
    } catch {
      setAssistantEnabled(ASSIST_ENV_ENABLED);
      setAssistantDisabledReason(
        ASSIST_ENV_ENABLED ? "" : "AI assistant is disabled. Enable it in Org Admin / Platform AI Configuration."
      );
      return ASSIST_ENV_ENABLED;
    }
  }, []);

  useEffect(() => {
    loadAgents();
    loadHistory();
    void refreshAssistantAvailability();
  }, [loadAgents, loadHistory, refreshAssistantAvailability]);

  const connectedAgents = useMemo(
    () => agents.filter((agent) => CONNECTED_STATUSES.has(agent.status)),
    [agents]
  );

  const connectedWindows = useMemo(
    () => connectedAgents.filter((agent) => agent.platform === "windows"),
    [connectedAgents]
  );

  const availableGroups = useMemo(() => {
    const names = new Set();
    connectedWindows.forEach((agent) => {
      (agent.groups || []).forEach((group) => {
        if (group) names.add(group);
      });
    });
    return Array.from(names).sort((left, right) => left.localeCompare(right));
  }, [connectedWindows]);

  const selectedAgentSet = useMemo(
    () => new Set(targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)),
    [targetAgentIds]
  );

  const selectedMultiAgents = useMemo(
    () => connectedWindows.filter((agent) => selectedAgentSet.has(agent.id)),
    [connectedWindows, selectedAgentSet]
  );

  useEffect(() => {
    if (connectedWindows.length === 0) return;
    setTargetAgentIds((prev) => {
      const valid = new Set(connectedWindows.map((agent) => agent.id));
      const next = prev.map((id) => formatAgentId(id)).filter((id) => valid.has(id));
      return next.length === prev.length ? prev : next;
    });
  }, [connectedWindows]);

  useEffect(() => {
    if (targetMode !== "multi") setMultiPickAgentId("");
  }, [targetMode]);

  useEffect(() => {
    const state = location?.state && typeof location.state === "object" ? location.state : null;
    const prefill = state?.prefill && typeof state.prefill === "object" ? state.prefill : null;
    if (!prefill) return;
    const fingerprint = JSON.stringify(prefill);
    if (prefillAppliedRef.current === fingerprint) return;
    prefillAppliedRef.current = fingerprint;

    const mode = String(prefill.targetMode || "").trim().toLowerCase();
    if (["agent", "multi", "group", "fleet"].includes(mode)) {
      setTargetMode(mode);
    }

    const prefillShell = String(prefill.shell || "").trim().toLowerCase();
    if (prefillShell === "cmd" || prefillShell === "powershell") {
      setShell(prefillShell);
    }
    if (typeof prefill.command === "string") {
      setCommand(prefill.command);
    }
    if (typeof prefill.assistantPrompt === "string") {
      setAssistantPrompt(prefill.assistantPrompt.trim());
    }
    if (typeof prefill.verifyKb === "string") {
      setVerifyKb(prefill.verifyKb.trim());
    } else {
      setVerifyKb("");
    }
    if (typeof prefill.verifyMinBuild === "string") {
      setVerifyMinBuild(prefill.verifyMinBuild.trim());
    } else {
      setVerifyMinBuild("");
    }
    if (typeof prefill.verifyStdoutContains === "string") {
      setVerifyStdoutContains(prefill.verifyStdoutContains.trim());
    } else {
      setVerifyStdoutContains("");
    }
    if (typeof prefill.runAsSystem === "boolean") {
      setRunAsSystem(prefill.runAsSystem);
    } else {
      setRunAsSystem(false);
    }
    if (typeof prefill.autoRemediate === "boolean") {
      setAutoRemediate(prefill.autoRemediate);
    } else {
      setAutoRemediate(false);
    }
    if (prefill.maxAttempts !== undefined && prefill.maxAttempts !== null) {
      const parsedAttempts = Number.parseInt(String(prefill.maxAttempts), 10);
      if (!Number.isNaN(parsedAttempts)) {
        setMaxAttempts(Math.max(1, Math.min(8, parsedAttempts)));
      }
    }
    const vulnCtx =
      (state?.vulnerabilityContext && typeof state.vulnerabilityContext === "object" ? state.vulnerabilityContext : null)
      || (prefill?.vulnerabilityContext && typeof prefill.vulnerabilityContext === "object" ? prefill.vulnerabilityContext : null)
      || (state?.vulnerability && typeof state.vulnerability === "object" ? state.vulnerability : null);
    setVulnerabilityContext(vulnCtx);
    setUpgradePreset("");
    if (typeof prefill.targetValue === "string" || typeof prefill.targetValue === "number") {
      setTargetValue(String(prefill.targetValue || "").trim());
    } else {
      setTargetValue("");
    }
    if (Array.isArray(prefill.targetAgentIds)) {
      setTargetAgentIds(
        prefill.targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)
      );
    } else {
      setTargetAgentIds([]);
    }
    if (typeof prefill.justification === "string") {
      setJustification(prefill.justification);
    }
    if (Array.isArray(prefill.excludeAgentIds)) {
      setExcludeIdsText(
        prefill.excludeAgentIds
          .map((id) => formatAgentId(id))
          .filter(Boolean)
          .join(",")
      );
    }
    setStatus("Loaded prefilled Global Shell context.");
  }, [location]);

  const normalizedTargetValue = useMemo(() => formatAgentId(targetValue), [targetValue]);
  const normalizedGroupValue = useMemo(() => String(targetValue || "").trim(), [targetValue]);

  const scopedTargets = useMemo(() => {
    if (targetMode === "agent") {
      if (!normalizedTargetValue) return [];
      return connectedWindows.filter((agent) => agent.id === normalizedTargetValue);
    }
    if (targetMode === "multi") {
      if (!selectedAgentSet.size) return [];
      return connectedWindows.filter((agent) => selectedAgentSet.has(agent.id));
    }
    if (targetMode === "group") {
      const key = normalizedGroupValue.toLowerCase();
      if (!key) return [];
      return connectedWindows.filter((agent) =>
        (agent.groups || []).some((group) => String(group || "").trim().toLowerCase() === key)
      );
    }
    return connectedWindows;
  }, [connectedWindows, normalizedGroupValue, normalizedTargetValue, selectedAgentSet, targetMode]);

  const excludeSet = useMemo(() => parseExcludeIds(excludeIdsText), [excludeIdsText]);

  const previewTargets = useMemo(
    () => scopedTargets.filter((agent) => !excludeSet.has(agent.id)),
    [scopedTargets, excludeSet]
  );

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(previewTargets.length / targetPageSize));
    if (targetPage > totalPages) {
      setTargetPage(totalPages);
    }
  }, [previewTargets.length, targetPage, targetPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(history.length / historyPageSize));
    if (historyPage > totalPages) {
      setHistoryPage(totalPages);
    }
  }, [history.length, historyPage, historyPageSize]);

  const pagedTargets = useMemo(() => {
    const start = (targetPage - 1) * targetPageSize;
    return previewTargets.slice(start, start + targetPageSize);
  }, [previewTargets, targetPage, targetPageSize]);

  const pagedHistory = useMemo(() => {
    const start = (historyPage - 1) * historyPageSize;
    return history.slice(start, start + historyPageSize);
  }, [history, historyPage, historyPageSize]);

  const selectedHistory = useMemo(
    () => history.find((row) => Number(row.id) === Number(activeExecutionId)) || null,
    [history, activeExecutionId]
  );

  const effectiveCommand = useMemo(() => {
    const base = command.trim();
    if (!base) return "";
    if (shell === "cmd") return `cmd.exe /c ${base}`;
    return base;
  }, [shell, command]);
  const asyncLaunchWarning = useMemo(() => {
    if (shell !== "powershell") return "";
    const text = String(command || "");
    if (!text.trim()) return "";
    const chunks = text.split(/[\r\n;]+/).map((part) => part.trim()).filter(Boolean);
    const hasStartWithoutWait = chunks.some(
      (chunk) => /\bStart-Process\b/i.test(chunk) && !/\s-Wait\b/i.test(chunk)
    );
    if (!hasStartWithoutWait) return "";
    return "This command uses Start-Process without -Wait. Global Shell will report launch success, not child-process completion.";
  }, [shell, command]);
  const selectedUpgradePreset = useMemo(
    () => UPGRADE_PRESETS.find((item) => item.id === upgradePreset) || null,
    [upgradePreset]
  );
  const applyUpgradePreset = useCallback((presetId) => {
    const preset = UPGRADE_PRESETS.find((item) => item.id === presetId);
    if (!preset) return;
    setShell(preset.shell);
    setRunAsSystem(Boolean(preset.runAsSystem));
    setCommand(preset.command);
    setVerifyKb("");
    setVerifyMinBuild("");
    setVerifyStdoutContains("");
    setStatus(`Loaded preset: ${preset.label}`);
  }, []);

  const generateAssistantCommand = useCallback(async () => {
    let ready = assistantEnabled;
    if (!ready) {
      ready = await refreshAssistantAvailability();
    }
    if (!ready) {
      setStatus(assistantDisabledReason || "AI assistant is disabled. Enable it in Org Admin.");
      return;
    }
    const prompt = assistantPrompt.trim();
    const vulnContext = vulnerabilityContext && typeof vulnerabilityContext === "object"
      ? vulnerabilityContext
      : null;
    if (!prompt && !vulnContext) {
      setStatus("Provide an assistant prompt (or vulnerability context) to generate a command.");
      return;
    }

    setAssistantLoading(true);
    try {
      const res = await suggestGlobalShellCommand({
        shell,
        prompt: prompt || undefined,
        vulnerability_context: vulnContext || undefined,
      });
      const data = res?.data || {};
      const plan = data?.plan && typeof data.plan === "object" ? data.plan : null;
      const recommended = data?.recommended && typeof data.recommended === "object"
        ? data.recommended
        : (plan?.recommended && typeof plan.recommended === "object" ? plan.recommended : null);
      setAssistantPlan(plan);
      if (recommended?.command) {
        setCommand(String(recommended.command));
        if (typeof recommended.run_as_system === "boolean") {
          setRunAsSystem(Boolean(recommended.run_as_system));
        }
        if (!verifyKb && recommended.verify_kb) {
          setVerifyKb(String(recommended.verify_kb));
        }
        if (!verifyMinBuild && recommended.verify_min_build) {
          setVerifyMinBuild(String(recommended.verify_min_build));
        }
        setStatus(`Assistant generated command (${String(recommended.strategy || "best-fit")}).`);
      } else {
        setStatus("Assistant could not infer a safe command from the provided prompt/context.");
      }
    } catch (err) {
      const statusCode = Number(err?.response?.status || 0);
      const detail = err?.response?.data?.detail;
      const detailText = typeof detail === "string"
        ? detail
        : (detail?.message || detail?.error || "");
      if (statusCode === 503 || looksLikeAssistantUnavailable(detailText || err.message)) {
        setAssistantEnabled(false);
        setAutoRemediate(false);
        setAssistantPlan(null);
        setAssistantDisabledReason(detailText || "AI assistant is currently unavailable.");
      }
      setStatus(formatApiError(err, detailText || "Failed to generate assistant command."));
    } finally {
      setAssistantLoading(false);
    }
  }, [assistantDisabledReason, assistantEnabled, assistantPrompt, refreshAssistantAvailability, shell, vulnerabilityContext, verifyKb, verifyMinBuild]);

  useEffect(() => {
    if (assistantEnabled) return;
    setAutoRemediate(false);
  }, [assistantEnabled]);

  const runFleetCommand = async () => {
    const raw = command.trim();
    const prompt = assistantEnabled ? assistantPrompt.trim() : "";
    const hasVulnerabilityContext = assistantEnabled && Boolean(vulnerabilityContext && typeof vulnerabilityContext === "object");
    if (!raw && !prompt && !hasVulnerabilityContext) {
      setStatus(
        assistantEnabled
          ? "Command is required (or provide an assistant prompt/context)."
          : "Command is required while AI assistant is disabled."
      );
      return;
    }
    if (targetMode === "agent" && !normalizedTargetValue) {
      setStatus("Select a single agent ID.");
      return;
    }
    if (targetMode === "multi" && !selectedAgentSet.size) {
      setStatus("Select one or more agents.");
      return;
    }
    if (targetMode === "group" && !normalizedGroupValue) {
      setStatus("Select a target group.");
      return;
    }
    if (previewTargets.length === 0) {
      setStatus("No connected Windows agents available for the selected target scope.");
      return;
    }

    setSubmitting(true);
    setStatus("Queueing global command...");
    try {
      const effectiveRunAsSystem = Boolean(runAsSystem);
      const rawJustification = justification.trim();
      const autoJustification = `Global shell execution via console (${shell}).`;
      const effectiveJustification = rawJustification.length >= 12 ? rawJustification : autoJustification;
      const payload = {
        shell,
        async: true,
        run_as_system: effectiveRunAsSystem,
        justification: effectiveJustification,
      };
      if (raw) payload.command = raw;
      if (prompt) payload.assistant_prompt = prompt;
      if (hasVulnerabilityContext) payload.vulnerability_context = vulnerabilityContext;
      if (assistantEnabled && autoRemediate) {
        payload.auto_remediate = true;
        payload.max_attempts = Math.max(1, Math.min(8, Number(maxAttempts) || 3));
      }
      const verifyKbValue = verifyKb.trim();
      const verifyBuildValue = verifyMinBuild.trim();
      const verifyStdoutValue = verifyStdoutContains.trim();
      if (verifyKbValue) payload.verify_kb = verifyKbValue;
      if (verifyBuildValue) payload.verify_min_build = verifyBuildValue;
      if (verifyStdoutValue) payload.verify_stdout_contains = verifyStdoutValue;
      if (targetMode === "agent") payload.agent_id = normalizedTargetValue;
      else if (targetMode === "multi") payload.agent_ids = Array.from(selectedAgentSet);
      else if (targetMode === "group") payload.group = normalizedGroupValue;
      else payload.agent_id = "all";
      if (excludeSet.size) payload.exclude_agent_ids = Array.from(excludeSet);

      const res = await runGlobalShell(payload);
      const data = res?.data || {};
      const summary = data.summary || {};
      const executionId = data.execution_id || null;
      if (executionId) {
        setActiveExecutionId(executionId);
      }
      setStatus(
        `Queued run${executionId ? ` #${executionId}` : ""} for ${summary.targeted_agents || 0} connected Windows agent(s).`
      );
      await loadHistory(true);
    } catch (err) {
      const detail = err?.response?.data?.detail;
      const detailText = typeof detail === "string"
        ? detail
        : (detail?.message || detail?.error || "");
      setStatus(formatApiError(err, detailText || "Failed to queue global command."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="page global-shell-page page-route-global-shell">
      <div className="page-header">
        <div>
          <h2>Global Shell Console</h2>
          <p className="muted">
            Run PowerShell or CMD commands across connected Windows agents with full execution evidence.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={() => loadAgents(true)} disabled={agentsLoading}>
            {agentsLoading ? "Refreshing..." : "Refresh Targets"}
          </button>
          <button className="btn secondary" onClick={() => loadHistory(true)} disabled={historyLoading}>
            {historyLoading ? "Refreshing..." : "Refresh History"}
          </button>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}
      {agentsError ? <div className="empty-state">Agent load error: {agentsError}</div> : null}

      <div className="mission-grid">
        <div className="mission-card">
          <div className="mission-label">Connected Agents</div>
          <div className="mission-value">{connectedAgents.length}</div>
          <div className="mission-meta">Wazuh status: active/connected/online</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Connected Windows</div>
          <div className="mission-value">{connectedWindows.length}</div>
          <div className="mission-meta">PowerShell/CMD eligible</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Target Mode</div>
          <div className="mission-value">{TARGET_MODE_LABELS[targetMode] || targetMode}</div>
          <div className="mission-meta">Exclusions configured: {excludeSet.size}</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Targeted Now</div>
          <div className="mission-value">{previewTargets.length}</div>
          <div className="mission-meta">Selected scope minus exclusions</div>
        </div>
      </div>

      <div className="split-view global-shell-workspace">
        <div className="card global-shell-target-card" data-tour-id="global-shell-drawer">
          <div className="card-header">
            <div>
              <h3>Target Preview</h3>
              <p className="muted">Connected Windows endpoints selected for execution.</p>
            </div>
          </div>
          <div className="table-scroll h-36vh">
            <table className="table compact readable">
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Name</th>
                  <th>Group</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {previewTargets.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="text-center">
                      No targets available.
                    </td>
                  </tr>
                ) : (
                  pagedTargets.map((agent) => (
                    <tr key={`target-${agent.id}`} data-agent-id={agent.id}>
                      <td>{agent.id}</td>
                      <td>{agent.name || "-"}</td>
                      <td>{agent.groupText || "-"}</td>
                      <td>{agent.status || "-"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <Pager
            total={previewTargets.length}
            page={targetPage}
            pageSize={targetPageSize}
            onPageChange={setTargetPage}
            onPageSizeChange={(size) => {
              setTargetPageSize(size);
              setTargetPage(1);
            }}
            pageSizeOptions={[25, 50, 100]}
            label="targets"
          />
        </div>

        <div className="card global-shell-builder-card">
          <div className="card-header">
            <div>
              <h3>Command Builder</h3>
              <p className="muted">Target scope, shell choice, and command plan.</p>
            </div>
          </div>

          <div className="list">
            <div className="list-item readable">
              <div className="muted">Targets</div>
              <div className="page-actions mt-8">
                <select
                  className="input"
                  value={targetMode}
                  onChange={(e) => {
                    setTargetMode(e.target.value);
                    setTargetPage(1);
                  }}
                >
                  <option value="fleet">Fleet (all connected Windows)</option>
                  <option value="multi">Multiple agents</option>
                  <option value="agent">Single agent</option>
                  <option value="group">Specific group</option>
                </select>
              </div>

              {targetMode === "multi" ? (
                <div className="mt-10">
                  <div className="page-actions">
                    <select
                      className="input"
                      value={multiPickAgentId}
                      onChange={(e) => setMultiPickAgentId(formatAgentId(e.target.value))}
                    >
                      <option value="">Select connected agent</option>
                      {connectedWindows.map((agent) => (
                        <option key={`multi-agent-${agent.id}`} value={agent.id}>
                          {agent.id} - {agent.name || "-"}{agent.groupText ? ` (${agent.groupText})` : ""}
                        </option>
                      ))}
                    </select>
                    <button
                      className="btn secondary"
                      type="button"
                      onClick={() => {
                        if (!multiPickAgentId) return;
                        setTargetAgentIds((prev) => {
                          const ids = new Set(prev.map((id) => formatAgentId(id)).filter(Boolean));
                          ids.add(multiPickAgentId);
                          return Array.from(ids);
                        });
                      }}
                      disabled={!multiPickAgentId}
                    >
                      Add
                    </button>
                    <button
                      className="btn secondary"
                      type="button"
                      onClick={() => setTargetAgentIds(connectedWindows.map((agent) => agent.id))}
                    >
                      All
                    </button>
                    <button
                      className="btn secondary"
                      type="button"
                      onClick={() => setTargetAgentIds([])}
                    >
                      Clear
                    </button>
                  </div>
                  <div className="meta-line mt-6">Selected: {selectedAgentSet.size}</div>
                  <div className="list mt-10">
                    {selectedMultiAgents.length === 0 ? (
                      <div className="empty-state">No agents selected yet.</div>
                    ) : (
                      selectedMultiAgents.map((agent) => (
                        <div key={`selected-agent-${agent.id}`} className="list-item split readable" data-agent-id={agent.id}>
                          <span>{agent.id} - {agent.name || "-"}</span>
                          <button
                            className="btn secondary"
                            type="button"
                            onClick={() => {
                              setTargetAgentIds((prev) =>
                                prev
                                  .map((id) => formatAgentId(id))
                                  .filter((id) => id && id !== agent.id)
                              );
                            }}
                          >
                            Remove
                          </button>
                        </div>
                      ))
                    )}
                    {connectedWindows.length === 0 ? (
                      <div className="meta-line">No connected Windows agents available.</div>
                    ) : null}
                    <div className="meta-line">
                      Tip: Use "All" for quick fleet subset, then remove specific endpoints.
                    </div>
                  </div>
                </div>
              ) : targetMode === "group" ? (
                <div className="page-actions mt-10">
                  <select className="input" value={targetValue} onChange={(e) => setTargetValue(e.target.value)}>
                    <option value="">Select group</option>
                    {availableGroups.map((group) => (
                      <option key={group} value={group}>{group}</option>
                    ))}
                  </select>
                </div>
              ) : targetMode === "agent" ? (
                <div className="page-actions mt-10">
                  <select
                    className="input"
                    value={targetValue}
                    onChange={(e) => setTargetValue(e.target.value)}
                  >
                    <option value="">Select agent</option>
                    {connectedWindows.map((agent) => (
                      <option key={`single-agent-${agent.id}`} value={agent.id}>
                        {agent.id} - {agent.name || "-"}{agent.groupText ? ` (${agent.groupText})` : ""}
                      </option>
                    ))}
                  </select>
                </div>
              ) : null}
            </div>

            <div className="list-item readable">
              <div className="muted">Shell Type</div>
              <div className="page-actions mt-8">
                <select className="input" value={shell} onChange={(e) => setShell(e.target.value)}>
                  <option value="powershell">PowerShell</option>
                  <option value="cmd">CMD</option>
                </select>
              </div>
              <label className="mt-10 inline-check">
                <input
                  type="checkbox"
                  checked={runAsSystem}
                  onChange={(e) => setRunAsSystem(Boolean(e.target.checked))}
                />
                <span className="muted">Run as SYSTEM (administrator context)</span>
              </label>
            </div>

            <div className="list-item readable">
              <div className="muted">AI Command Assistant</div>
              <textarea
                className="input mt-8"
                value={assistantPrompt}
                onChange={(e) => setAssistantPrompt(e.target.value)}
                rows={3}
                placeholder="Describe the task or vulnerability fix you want (example: Upgrade Google Chrome on affected endpoints)."
              />
              <div className="page-actions mt-8">
                <button
                  className="btn secondary"
                  type="button"
                  onClick={generateAssistantCommand}
                  disabled={assistantLoading}
                >
                  {assistantLoading ? "Generating..." : "Generate Command"}
                </button>
                <button
                  className="btn secondary"
                  type="button"
                  onClick={() => void refreshAssistantAvailability()}
                  disabled={assistantLoading}
                >
                  Refresh AI Status
                </button>
              </div>
              {!assistantEnabled ? (
                <div className="meta-line mt-8">
                  {assistantDisabledReason || "AI assistant is disabled for now. Use manual commands."}
                </div>
              ) : null}
              <div className="meta-line mt-8">
                AI setup: use Org Admin / Platform AI Configuration, or set `C2F_AI_FEATURES_ENABLED=true` with `C2F_LLM_API_KEY` in `.env.appliance`.
              </div>
              {assistantPlan?.recommended?.reason ? (
                <div className="meta-line mt-8">
                  {String(assistantPlan.recommended.reason)}
                </div>
              ) : null}
              {assistantPlan?.recommended?.strategy ? (
                <div className="meta-line mt-8">
                  Strategy: {String(assistantPlan.recommended.strategy)}
                </div>
              ) : null}
              <label className="mt-10 inline-check">
                <input
                  type="checkbox"
                  checked={autoRemediate}
                  onChange={(e) => setAutoRemediate(Boolean(e.target.checked))}
                  disabled={!assistantEnabled}
                />
                <span className="muted">Auto-remediate loop (retry with fallback commands)</span>
              </label>
              {assistantEnabled && autoRemediate ? (
                <div className="page-actions mt-8">
                  <input
                    className="input"
                    type="number"
                    min={1}
                    max={8}
                    value={maxAttempts}
                    onChange={(e) => {
                      const parsed = Number.parseInt(e.target.value || "3", 10);
                      if (Number.isNaN(parsed)) return;
                      setMaxAttempts(Math.max(1, Math.min(8, parsed)));
                    }}
                  />
                  <span className="muted">Max attempts (1-8)</span>
                </div>
              ) : null}
            </div>

            <div className="list-item readable">
              <div className="muted">Upgrade Preset (optional)</div>
              <div className="page-actions mt-8">
                <select
                  className="input"
                  value={upgradePreset}
                  onChange={(e) => {
                    const value = e.target.value;
                    setUpgradePreset(value);
                    if (value) applyUpgradePreset(value);
                  }}
                >
                  <option value="">Custom command</option>
                  {UPGRADE_PRESETS.map((preset) => (
                    <option key={preset.id} value={preset.id}>
                      {preset.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="meta-line mt-8">
                {selectedUpgradePreset?.description || "Load a prebuilt upgrade command, then edit if needed."}
              </div>
            </div>

            <div className="list-item readable">
              <div className="muted">Command</div>
              <textarea
                className="input mt-8 mono"
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                rows={8}
                placeholder={
                  shell === "powershell"
                    ? "Example: Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion"
                    : "Example: ipconfig /all"
                }
              />
              {asyncLaunchWarning ? (
                <div className="meta-line mt-8">{asyncLaunchWarning}</div>
              ) : null}
            </div>

            <div className="list-item readable">
              <div className="muted">Effective Command</div>
              <div className="meta-line ws-normal mt-8">
                {effectiveCommand || "-"}
              </div>
              {(verifyKb || verifyMinBuild || verifyStdoutContains) ? (
                <div className="meta-line mt-8">
                  Verification checks: {verifyKb ? `KB ${verifyKb}` : ""}
                  {verifyKb && verifyMinBuild ? " | " : ""}
                  {verifyMinBuild ? `Min build ${verifyMinBuild}` : ""}
                  {(verifyKb || verifyMinBuild) && verifyStdoutContains ? " | " : ""}
                  {verifyStdoutContains ? `Stdout contains "${verifyStdoutContains}"` : ""}
                </div>
              ) : null}
            </div>

            <div className="list-item readable">
              <div className="muted">Exclude Agent IDs (optional)</div>
              <input
                className="input mt-8"
                value={excludeIdsText}
                onChange={(e) => setExcludeIdsText(e.target.value)}
                placeholder="Example: 001,004,013"
              />
            </div>

            <div className="list-item readable">
              <div className="muted">Justification (optional)</div>
              <input
                className="input mt-8"
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
                placeholder="Reason for global command"
              />
            </div>

            <div className="page-actions">
              <button className="btn" onClick={runFleetCommand} disabled={submitting}>
                {submitting ? "Queueing..." : "Run Global Command"}
              </button>
            </div>
          </div>
        </div>

      </div>

      <div className="card global-shell-history-card">
        <div className="card-header">
          <div>
            <h3>Shell Execution History</h3>
            <p className="muted">Recent global shell runs with command and output previews.</p>
          </div>
        </div>
        <div className="table-scroll h-44vh global-shell-history-scroll">
          <table className="table compact readable global-shell-history-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Status</th>
                <th>Targets</th>
                <th>Shell</th>
                <th>Command</th>
                <th>Latest Output</th>
                <th>Started</th>
                <th>Finished</th>
              </tr>
            </thead>
            <tbody>
              {history.length === 0 ? (
                <tr>
                  <td colSpan="8" className="text-center">
                    No shell execution history yet.
                  </td>
                </tr>
              ) : (
                pagedHistory.map((row) => (
                  <tr
                    key={`hist-${row.id}`}
                    className={`clickable ${Number(activeExecutionId) === Number(row.id) ? "selected" : ""}`}
                    onClick={() => setActiveExecutionId(row.id)}
                  >
                    <td>{row.id}</td>
                    <td>
                      <span className={`status-pill ${statusTone(row.status)}`}>
                        {row.status || "-"}
                      </span>
                    </td>
                    <td className="ws-normal">
                      <div className="global-shell-agent-cell">
                        <span className="agent-count">{row.targetLabel || row.agent || "-"}</span>
                        {formatTargetHealth(row) ? (
                          <span className="agent-id">{formatTargetHealth(row)}</span>
                        ) : null}
                      </div>
                    </td>
                    <td>
                      <span
                        className={`shell-type-pill ${String(row.shell || "")
                          .toLowerCase()
                          .includes("cmd")
                          ? "cmd"
                          : String(row.shell || "")
                              .toLowerCase()
                              .includes("bash") || String(row.shell || "").toLowerCase().includes("sh")
                            ? "bash"
                            : String(row.shell || "").toLowerCase().includes("power")
                              ? "ps"
                              : ""}`}
                      >
                        {row.shell || "-"}
                      </span>
                    </td>
                    <td className="ws-normal" title={row.command || "-"}>
                      {row.command || "-"}
                    </td>
                    <td className="ws-normal" title={row.outputPreview || "-"}>
                      <span className="shell-output-preview">
                        {row.outputPreview || "-"}
                      </span>
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
          pageSizeOptions={[10, 25, 50]}
          label="shell runs"
        />
      </div>

      {!selectedHistory ? (
        <div className="empty-state">Select a run from history to inspect full output and execution proof.</div>
      ) : null}

      <SideDrawer
        open={Boolean(selectedHistory)}
        onClose={() => setActiveExecutionId(null)}
        title={selectedHistory ? `Global Shell Run #${selectedHistory.id}` : "Global Shell Run"}
        subtitle={selectedHistory ? `${selectedHistory.targetLabel || selectedHistory.agent || "-"} | ${selectedHistory.status || "-"}` : ""}
      >
        {selectedHistory ? (
          <div className="drawer-grid">
            <div className="panel-stack">
            <div className="card shell-run-detail">
              <div className="card-header">
                <div>
                  <h3>Run Command</h3>
                  <p className="muted">Shell context and sanitized preview for rapid debugging.</p>
                </div>
              </div>
              <div className="run-meta-grid">
                <div className="kv-row">
                  <span className="kv-key run-meta-label">Shell</span>
                  <span className="kv-value run-meta-value">{selectedHistory.shell || "-"}</span>
                </div>
                <div className="kv-row">
                  <span className="kv-key run-meta-label">Status</span>
                  <span className="kv-value run-meta-value">
                    <span className={`status-pill ${statusTone(selectedHistory.status)}`}>{selectedHistory.status || "-"}</span>
                  </span>
                </div>
                <div className="kv-row">
                  <span className="kv-key run-meta-label">Started</span>
                  <span className="kv-value run-meta-value"><RelativeTimestamp value={selectedHistory.startedAt} /></span>
                </div>
                <div className="kv-row">
                  <span className="kv-key run-meta-label">Finished</span>
                  <span className="kv-value run-meta-value"><RelativeTimestamp value={selectedHistory.finishedAt} /></span>
                </div>
              </div>
              <details className="ticketing-detail-section shell-run-section" open>
                <summary className="shell-run-section-title">Command</summary>
                <pre className="shell-run-command-block">{selectedHistory.command || "-"}</pre>
              </details>
              <details className="ticketing-detail-section shell-run-section">
                <summary className="shell-run-section-title">Clean Output Preview</summary>
                <pre className="shell-output-block">{selectedHistory.cleanOutputPreview || "-"}</pre>
              </details>
              <details className="ticketing-detail-section shell-run-section">
                <summary className="shell-run-section-title">Raw Output Preview</summary>
                <pre className="shell-output-block">{selectedHistory.outputPreview || "-"}</pre>
              </details>
            </div>
          </div>
          <details className="ticketing-detail-section shell-run-section">
            <summary className="shell-run-section-title">Execution Steps</summary>
            <ExecutionStream executionId={selectedHistory.id} />
          </details>
          </div>
        ) : null}
      </SideDrawer>
    </div>
  );
}


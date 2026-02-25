import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import ExecutionStream from "../components/ExecutionStream";
import Pager from "../components/Pager";
import { getAgents, getExecutions, runGlobalShell } from "../api/wazuh";
import { buildHumanReadableOutput, summarizeReadableOutput } from "../utils/output";
import { formatWazuhTimestamp } from "../utils/time";

const CONNECTED_STATUSES = new Set(["active", "connected", "online"]);
const FLEET_TARGETS = new Set(["all", "*", "fleet", "all-active"]);
const TARGET_MODE_LABELS = {
  agent: "Single agent",
  multi: "Multiple agents",
  group: "Agent group",
  fleet: "Fleet",
};
const WINDOWS_UPDATE_PRESET_COMMAND =
  "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
  + "if(-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)){"
  + "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null;"
  + "Install-Module PSWindowsUpdate -Scope AllUsers -Force -Confirm:$false -ErrorAction Stop | Out-Null"
  + "};"
  + "Import-Module PSWindowsUpdate -ErrorAction Stop;"
  + "Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -AutoReboot -ErrorAction Stop";
const WINDOWS_UPDATE_SCAN_PRESET_COMMAND =
  "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
  + "if(-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)){"
  + "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue | Out-Null;"
  + "Install-Module PSWindowsUpdate -Scope AllUsers -Force -Confirm:$false -ErrorAction Stop | Out-Null"
  + "};"
  + "Import-Module PSWindowsUpdate -ErrorAction Stop;"
  + "Get-WindowsUpdate -MicrosoftUpdate | Select-Object -First 60 Title,KB,Size";
const TARGETED_UPGRADE_PRESET_COMMAND =
  "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
  + "$pkg='PACKAGE_HINT';$updated=$false;"
  + "if(Get-Command winget -ErrorAction SilentlyContinue){"
  + "& winget upgrade --id $pkg --exact --silent --accept-package-agreements --accept-source-agreements --include-unknown | Out-Host;"
  + "if($LASTEXITCODE -eq 0){$updated=$true};"
  + "if(-not $updated){"
  + "& winget upgrade --query $pkg --silent --accept-package-agreements --accept-source-agreements --include-unknown | Out-Host;"
  + "if($LASTEXITCODE -eq 0){$updated=$true}"
  + "}"
  + "};"
  + "if(-not $updated -and (Get-Command choco -ErrorAction SilentlyContinue)){"
  + "& choco upgrade $pkg -y --no-progress --limit-output | Out-Host;"
  + "if($LASTEXITCODE -eq 0){$updated=$true}"
  + "};"
  + "if(-not $updated){throw ('No supported upgrade path succeeded for '+$pkg)};"
  + "Write-Output ('Package update attempted for '+$pkg);";
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
    description: "Install pending Windows security/OS updates.",
    command: WINDOWS_UPDATE_PRESET_COMMAND,
  },
  {
    id: "winget-all",
    label: "Winget Upgrade All",
    shell: "powershell",
    runAsSystem: false,
    description: "Upgrade all upgradable winget-managed packages.",
    command: "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements",
  },
  {
    id: "choco-all",
    label: "Chocolatey Upgrade All",
    shell: "powershell",
    runAsSystem: false,
    description: "Upgrade all Chocolatey packages.",
    command: "choco upgrade all -y --no-progress --limit-output",
  },
  {
    id: "targeted-fallback",
    label: "Targeted Package Upgrade",
    shell: "powershell",
    runAsSystem: false,
    description: "Set PACKAGE_HINT and try winget, then Chocolatey.",
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
  const text = String(value || "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();
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
  const total = Number(row?.targetCount || 0);
  const success = Number(row?.targetSuccess || 0);
  if (!total) return "";
  return `${success}/${total} ok`;
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
        buildHumanReadableOutput(latestStdout, latestStderr),
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
      };
    })
    .filter((row) => row.id && String(row.action || "").toLowerCase().includes("global-shell"));
};

const statusTone = (status) => {
  const value = String(status || "").toUpperCase();
  if (value === "SUCCESS") return "success";
  if (["FAILED", "ERROR", "KILLED"].includes(value)) return "failed";
  if (["RUNNING", "PAUSED", "PENDING", "QUEUED", "CANCELLED"].includes(value)) return "pending";
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
  const [upgradePreset, setUpgradePreset] = useState("");
  const [verifyKb, setVerifyKb] = useState("");
  const [verifyMinBuild, setVerifyMinBuild] = useState("");
  const [verifyStdoutContains, setVerifyStdoutContains] = useState("");
  const [targetMode, setTargetMode] = useState("fleet");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [targetSearch, setTargetSearch] = useState("");
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
      setAgentsError(err.response?.data?.detail || err.message || "Failed to load agents.");
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
        return rows.length ? rows[0].id : null;
      });
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAgents();
    loadHistory();
  }, [loadAgents, loadHistory]);

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

  useEffect(() => {
    if (connectedWindows.length === 0) return;
    setTargetAgentIds((prev) => {
      const valid = new Set(connectedWindows.map((agent) => agent.id));
      const next = prev.map((id) => formatAgentId(id)).filter((id) => valid.has(id));
      return next.length === prev.length ? prev : next;
    });
  }, [connectedWindows]);

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
    setStatus("Loaded prefilled Global Shell command from vulnerability context.");
  }, [location]);

  const targetPickList = useMemo(() => {
    const q = targetSearch.trim().toLowerCase();
    if (!q) return connectedWindows.slice(0, 120);
    return connectedWindows
      .filter((agent) =>
        agent.id.toLowerCase().includes(q)
        || String(agent.name || "").toLowerCase().includes(q)
        || String(agent.groupText || "").toLowerCase().includes(q)
      )
      .slice(0, 120);
  }, [connectedWindows, targetSearch]);

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

  const runFleetCommand = async () => {
    const raw = command.trim();
    if (!raw) {
      setStatus("Command is required.");
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
        command: raw,
        async: true,
        run_as_system: effectiveRunAsSystem,
        justification: effectiveJustification,
      };
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
      setStatus(detailText || err.message || "Failed to queue global command.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="page">
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

      <div className="split-view">
        <div className="card">
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
                  <option value="agent">Single agent</option>
                  <option value="multi">Multiple agents</option>
                  <option value="group">Agent group</option>
                  <option value="fleet">Fleet (all connected Windows)</option>
                </select>
              </div>

              {targetMode === "multi" ? (
                <div className="mt-10">
                  <div className="page-actions">
                    <input
                      className="input"
                      value={targetSearch}
                      onChange={(e) => setTargetSearch(e.target.value)}
                      placeholder="Search connected Windows agents..."
                    />
                    <button
                      className="btn secondary"
                      type="button"
                      onClick={() => setTargetAgentIds(connectedWindows.map((a) => a.id))}
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
                  <div className="meta-line mt-6">Selected: {selectedAgentSet.size}</div>
                  <div className="list-scroll mt-10 h-240">
                    <div className="list">
                      {targetPickList.length === 0 ? (
                        <div className="empty-state">No connected Windows agents match your search.</div>
                      ) : (
                        targetPickList.map((agent) => {
                          const checked = selectedAgentSet.has(agent.id);
                          return (
                            <label key={`target-${agent.id}`} className="list-item clickable readable">
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={(e) => {
                                  const next = e.target.checked;
                                  setTargetAgentIds((prev) => {
                                    const current = new Set(prev.map((id) => formatAgentId(id)).filter(Boolean));
                                    if (next) current.add(agent.id);
                                    else current.delete(agent.id);
                                    return Array.from(current);
                                  });
                                }}
                                className="mr-10"
                              />
                              {agent.name || agent.id} ({agent.id}){agent.groupText ? ` - ${agent.groupText}` : ""}
                            </label>
                          );
                        })
                      )}
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
                  <input
                    className="input"
                    value={targetValue}
                    onChange={(e) => setTargetValue(e.target.value)}
                    placeholder="Agent ID (example: 004)"
                    list="globalShellAgentIds"
                  />
                  <datalist id="globalShellAgentIds">
                    {connectedWindows.slice(0, 150).map((agent) => (
                      <option key={`agent-${agent.id}`} value={agent.id}>
                        {agent.name}
                      </option>
                    ))}
                  </datalist>
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
              <label className="mt-10 page-actions" style={{ alignItems: "center", gap: "8px" }}>
                <input
                  type="checkbox"
                  checked={runAsSystem}
                  onChange={(e) => setRunAsSystem(Boolean(e.target.checked))}
                />
                <span className="muted">Run as SYSTEM (administrator context)</span>
              </label>
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

        <div className="panel-stack">
          <div className="card">
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
                      <tr key={`target-${agent.id}`}>
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

          <div className="card">
            <div className="card-header">
              <div>
                <h3>Shell Execution History</h3>
                <p className="muted">Recent global shell runs with command and output previews.</p>
              </div>
            </div>
            <div className="table-scroll h-44vh">
              <table className="table compact readable">
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
                          {row.targetLabel || row.agent || "-"}
                          {formatTargetHealth(row) ? (
                            <div className="meta-line">{formatTargetHealth(row)}</div>
                          ) : null}
                        </td>
                        <td>{row.shell || "-"}</td>
                        <td className="ws-normal" title={row.command || "-"}>
                          {row.command || "-"}
                        </td>
                        <td className="ws-normal" title={row.outputPreview || "-"}>
                          {row.outputPreview || "-"}
                        </td>
                        <td>{formatWazuhTimestamp(row.startedAt)}</td>
                        <td>{formatWazuhTimestamp(row.finishedAt)}</td>
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
	            {selectedHistory ? (
	              <div className="list-item readable mt-10">
	                <div className="muted">Selected Run Command</div>
	                <div className="meta-line mt-6">Shell: {selectedHistory.shell || "-"}</div>
	                <pre className="code-block mt-10">{selectedHistory.command || "-"}</pre>
	                <div className="muted mt-10">Clean Output Preview (Human-readable)</div>
	                <pre className="code-block mt-10">{selectedHistory.cleanOutputPreview || "-"}</pre>
	                <div className="muted mt-10">Raw Output Preview</div>
	                <pre className="code-block mt-10">{selectedHistory.outputPreview || "-"}</pre>
	              </div>
	            ) : null}
          </div>
        </div>
      </div>

      {activeExecutionId ? (
        <ExecutionStream executionId={activeExecutionId} title={`Global Shell Run #${activeExecutionId}`} />
      ) : (
        <div className="empty-state">Select a run from history to inspect full output and execution proof.</div>
      )}
    </div>
  );
}

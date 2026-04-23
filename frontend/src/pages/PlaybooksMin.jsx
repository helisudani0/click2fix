import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  executePlaybook,
  getActions,
  getAgentGroups,
  getAgents,
  getPlaybook,
  getPlaybooks,
  requestApproval,
  savePlaybook,
  seedDefaultPlaybooks,
} from "../api/wazuh";
import PlaybookEditor from "../components/PlaybookEditor";
import { formatApiError } from "../utils/httpErrors";
import {
  buildMatrixPlaybookDraft,
  commandMatrixToPlaybookStep,
  filterMatrixCommands,
  getMatrixCommandById,
  MIN_COMMAND_MATRIX,
  MIN_COMMAND_MATRIX_BUNDLES,
} from "./minCommandMatrix";

const CONNECTED_STATUSES = new Set(["active", "connected", "online"]);
const PLAYBOOK_GLOBAL_SHELL_ACTION = {
  id: "global-shell",
  label: "Global Shell",
  description: "Execute a reviewed shell command on selected endpoints.",
  category: "response",
  risk: "critical",
  inputs: [
    { name: "command", label: "Command", required: true, placeholder: "Get-Service WazuhSvc" },
    { name: "verify_kb", label: "Verify KB", placeholder: "KB5075912" },
    { name: "verify_min_build", label: "Verify Min Build", placeholder: "19045.6937" },
    { name: "verify_stdout_contains", label: "Verify stdout contains", placeholder: "Running" },
    { name: "run_as_system", label: "Run as SYSTEM", placeholder: "false" },
  ],
  capabilities: {
    validation: [{ field: "run_as_system", default: "false" }],
  },
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
  const value = String(raw).trim();
  if (!value) return "";
  return /^[0-9]+$/.test(value) && value.length < 3 ? value.padStart(3, "0") : value;
};

const toDisplay = (value, fallback = "-") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) {
    const list = value.map((item) => toDisplay(item, "")).filter(Boolean);
    return list.length ? list.join(", ") : fallback;
  }
  if (typeof value === "object") {
    for (const key of ["label", "name", "id", "title", "text", "value"]) {
      if (value[key] !== null && value[key] !== undefined && typeof value[key] !== "object") {
        return String(value[key]);
      }
    }
    return fallback;
  }
  return String(value);
};

const normalizeStepActionId = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (raw.toLowerCase() === "custom-os-command") return "global-shell";
  return raw;
};

const agentPlatform = (agent) => {
  const node = agent?.os;
  const osName = typeof node === "object" && node
    ? String(node.name || node.platform || node.full || "")
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

const mergePlaybookActions = (items = []) => {
  const merged = new Map();
  [...items, PLAYBOOK_GLOBAL_SHELL_ACTION].forEach((item) => {
    const id = String(item?.id || "").trim();
    if (!id) return;
    merged.set(id, item);
  });
  return Array.from(merged.values()).sort((left, right) =>
    String(left?.label || left?.id || "").localeCompare(String(right?.label || right?.id || ""))
  );
};

const parseExcludeIds = (value) =>
  new Set(
    String(value || "")
      .split(",")
      .map((item) => formatAgentId(item))
      .filter(Boolean)
  );

function normalizePlaybook(payload) {
  if (!payload || typeof payload !== "object") return null;
  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  return {
    ...payload,
    name: payload.name || "manual-playbook",
    description: payload.description || "Custom response workflow",
    source: payload.source && typeof payload.source === "object" ? payload.source : { mode: "manual" },
    steps: steps.map((step, idx) => ({
      id: step.id || `step_${idx + 1}`,
      action: normalizeStepActionId(step.action || step.command) || "endpoint-healthcheck",
      args: step.args && typeof step.args === "object" && !Array.isArray(step.args) ? step.args : {},
      reason: step.reason || "Playbook step",
    })),
  };
}

const blankPlaybook = () =>
  normalizePlaybook({
    name: "manual-playbook",
    description: "Manually authored playbook.",
    source: { mode: "manual" },
    steps: [
      {
        id: "step_1",
        action: "endpoint-healthcheck",
        args: {},
        reason: "Validate endpoint reachability before deeper response steps.",
      },
    ],
  });

export default function PlaybooksMin({ onExecutionCreated }) {
  const [playbooks, setPlaybooks] = useState([]);
  const [actions, setActions] = useState([]);
  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [draft, setDraft] = useState(blankPlaybook());
  const [selectedPlaybookName, setSelectedPlaybookName] = useState("");
  const [editorOpened, setEditorOpened] = useState(false);

  const [playbookSearch, setPlaybookSearch] = useState("");
  const [playbookPick, setPlaybookPick] = useState("");
  const [matrixSearch, setMatrixSearch] = useState("");
  const [matrixPlatform, setMatrixPlatform] = useState("all");
  const [matrixCommandPick, setMatrixCommandPick] = useState("");
  const [matrixBundlePick, setMatrixBundlePick] = useState("");
  const [targetType, setTargetType] = useState("fleet");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [targetSearch, setTargetSearch] = useState("");
  const [multiPickAgentId, setMultiPickAgentId] = useState("");
  const [excludeAgents, setExcludeAgents] = useState("");
  const [justification, setJustification] = useState("");
  const [dryRun, setDryRun] = useState(false);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const builderRef = useRef(null);

  const openBuilder = useCallback(() => {
    setEditorOpened(true);
    window.setTimeout(() => {
      builderRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 40);
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      await seedDefaultPlaybooks({ force: false }).catch(() => null);
      const [playbookRes, actionRes, agentRes, groupRes] = await Promise.all([
        getPlaybooks(),
        getActions().catch(() => ({ data: [] })),
        getAgents(undefined, { limit: 5000, compact: true, status: "active,connected,online" }).catch(() => ({ data: [] })),
        getAgentGroups().catch(() => ({ data: [] })),
      ]);
      const playbookList = Array.isArray(playbookRes?.data) ? playbookRes.data : [];
      setPlaybooks(playbookList);
      if (!playbookPick && playbookList.length) setPlaybookPick(playbookList[0]);
      setActions(mergePlaybookActions(Array.isArray(actionRes?.data) ? actionRes.data : []));

      const normalizedAgents = normalizeAgents(agentRes?.data).map((row) => ({
        id: formatAgentId(row.id || row.agent_id),
        name: String(row.name || row.hostname || row.id || row.agent_id || "-"),
        group: Array.isArray(row.groups)
          ? row.groups.join(", ")
          : String(row.group || row.group_name || ""),
        groups: Array.isArray(row.groups)
          ? row.groups.map((group) => String(group || "").trim()).filter(Boolean)
          : String(row.group || row.group_name || "")
              .split(",")
              .map((group) => String(group || "").trim())
              .filter(Boolean),
        status: String(row.status || "unknown"),
        platform: agentPlatform(row),
      }));
      setAgents(normalizedAgents.filter((agent) => agent.id));

      setGroups(
        (Array.isArray(groupRes?.data) ? groupRes.data : [])
          .map((group) => String(group.name || group.id || group).trim())
          .filter(Boolean)
      );
      setStatus("");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to refresh playbook catalogs."));
    } finally {
      setLoading(false);
    }
  }, [playbookPick]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    setTargetAgentIds((current) => current.filter((id) => agents.some((agent) => agent.id === id)));
  }, [agents]);

  const filteredPlaybooks = useMemo(() => {
    const query = playbookSearch.trim().toLowerCase();
    if (!query) return playbooks;
    return playbooks.filter((name) => name.toLowerCase().includes(query));
  }, [playbookSearch, playbooks]);

  const effectiveMatrixPlatform = useMemo(() => {
    if (matrixPlatform !== "all") return matrixPlatform;
    if (targetType === "os_linux") return "linux";
    if (targetType === "os_windows") return "windows";
    return "all";
  }, [matrixPlatform, targetType]);

  const matrixCommands = useMemo(
    () => filterMatrixCommands(MIN_COMMAND_MATRIX, { query: matrixSearch, platform: effectiveMatrixPlatform }),
    [effectiveMatrixPlatform, matrixSearch]
  );

  useEffect(() => {
    if (!matrixCommands.length) {
      if (matrixCommandPick) setMatrixCommandPick("");
      return;
    }
    if (!matrixCommandPick || !matrixCommands.some((command) => command.id === matrixCommandPick)) {
      setMatrixCommandPick(String(matrixCommands[0]?.id || ""));
    }
  }, [matrixCommandPick, matrixCommands]);

  const matrixBundles = useMemo(() => {
    if (effectiveMatrixPlatform === "all") return MIN_COMMAND_MATRIX_BUNDLES;
    return MIN_COMMAND_MATRIX_BUNDLES.filter((bundle) => String(bundle.platform || "all").toLowerCase() === effectiveMatrixPlatform);
  }, [effectiveMatrixPlatform]);

  useEffect(() => {
    if (!matrixBundles.length) {
      if (matrixBundlePick) setMatrixBundlePick("");
      return;
    }
    if (!matrixBundlePick || !matrixBundles.some((bundle) => bundle.id === matrixBundlePick)) {
      setMatrixBundlePick(String(matrixBundles[0]?.id || ""));
    }
  }, [matrixBundlePick, matrixBundles]);

  const connectedAgents = useMemo(
    () => agents.filter((agent) => CONNECTED_STATUSES.has(String(agent.status || "").toLowerCase())),
    [agents]
  );
  const selectedAgentSet = useMemo(
    () => new Set(targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)),
    [targetAgentIds]
  );
  const excludeSet = useMemo(() => parseExcludeIds(excludeAgents), [excludeAgents]);
  const normalizedTargetValue = useMemo(() => formatAgentId(targetValue), [targetValue]);
  const normalizedGroupValue = useMemo(() => String(targetValue || "").trim(), [targetValue]);

  const targetPickList = useMemo(() => {
    const query = targetSearch.trim().toLowerCase();
    const list = connectedAgents.filter((agent) => !query || (
      agent.id.toLowerCase().includes(query)
      || String(agent.name || "").toLowerCase().includes(query)
      || String(agent.group || "").toLowerCase().includes(query)
    ));
    return list.slice(0, 160);
  }, [connectedAgents, targetSearch]);

  const scopedTargets = useMemo(() => {
    if (targetType === "agent") {
      if (!normalizedTargetValue) return [];
      return connectedAgents.filter((agent) => agent.id === normalizedTargetValue);
    }
    if (targetType === "multi") {
      if (!selectedAgentSet.size) return [];
      return connectedAgents.filter((agent) => selectedAgentSet.has(agent.id));
    }
    if (targetType === "group") {
      const key = normalizedGroupValue.toLowerCase();
      if (!key) return [];
      return connectedAgents.filter((agent) =>
        (agent.groups || []).some((group) => String(group || "").toLowerCase() === key)
      );
    }
    if (targetType === "os_windows") return connectedAgents.filter((agent) => agent.platform === "windows");
    if (targetType === "os_linux") return connectedAgents.filter((agent) => agent.platform === "linux");
    return connectedAgents;
  }, [connectedAgents, normalizedGroupValue, normalizedTargetValue, selectedAgentSet, targetType]);

  const previewTargets = useMemo(
    () => scopedTargets.filter((agent) => !excludeSet.has(agent.id)),
    [excludeSet, scopedTargets]
  );

  const buildTargetPayload = useCallback(() => {
    if (targetType === "group") return normalizedGroupValue ? { group: normalizedGroupValue } : {};
    if (targetType === "fleet") return { agent_id: "all" };
    if (targetType === "multi" || targetType === "os_windows" || targetType === "os_linux") {
      return { agent_ids: scopedTargets.map((agent) => agent.id) };
    }
    return normalizedTargetValue ? { agent_id: normalizedTargetValue } : {};
  }, [normalizedGroupValue, normalizedTargetValue, scopedTargets, targetType]);

  const executableActionIds = useMemo(
    () => new Set(actions.map((item) => String(item?.id || "").trim().toLowerCase()).filter(Boolean)),
    [actions]
  );
  const approvalActionIds = useMemo(() => {
    const ids = new Set(executableActionIds);
    ids.delete("global-shell");
    return ids;
  }, [executableActionIds]);

  const findUnsupportedStepActions = useCallback((steps = [], supportedActionIds = executableActionIds) => {
    const unsupported = [];
    const seen = new Set();
    (Array.isArray(steps) ? steps : []).forEach((step) => {
      if (!step || typeof step !== "object") return;
      const actionId = String(step.action || "").trim();
      const key = actionId.toLowerCase();
      if (!actionId || supportedActionIds.has(key) || seen.has(key)) return;
      seen.add(key);
      unsupported.push(actionId);
    });
    return unsupported;
  }, [executableActionIds]);

  const loadPlaybook = async (name) => {
    setStatus("");
    try {
      const response = await getPlaybook(name);
      const normalized = normalizePlaybook(response.data);
      if (!normalized) {
        setStatus("Playbook payload is empty.");
        return;
      }
      setDraft(normalized);
      setSelectedPlaybookName(name);
      openBuilder();
      setStatus("Playbook loaded into the editor.");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to load playbook."));
    }
  };

  const loadMatrixBundle = () => {
    const bundleDraft = buildMatrixPlaybookDraft(matrixBundlePick);
    if (!bundleDraft) {
      setStatus("Select a valid matrix bundle first.");
      return;
    }
    const normalized = normalizePlaybook(bundleDraft);
    if (!normalized) {
      setStatus("Matrix bundle did not produce a valid playbook payload.");
      return;
    }
    setDraft(normalized);
    setSelectedPlaybookName(`${normalized.name || "matrix-playbook"}.json`);
    openBuilder();
    const bundleLabel = matrixBundles.find((item) => item.id === matrixBundlePick)?.label
      || String(bundleDraft?.name || matrixBundlePick);
    setStatus(`Loaded matrix bundle: ${bundleLabel}`);
  };

  const appendMatrixStep = () => {
    const command = getMatrixCommandById(matrixCommandPick);
    if (!command) {
      setStatus("Pick a matrix command first.");
      return;
    }
    setDraft((current) => {
      const base = normalizePlaybook(current) || blankPlaybook();
      const currentSteps = Array.isArray(base.steps) ? base.steps : [];
      const nextIndex = currentSteps.length + 1;
      const nextStep = commandMatrixToPlaybookStep(command, nextIndex);
      return normalizePlaybook({
        ...base,
        source: {
          mode: "matrix",
          command_id: command.id,
          platform: command.platform,
        },
        steps: [...currentSteps, nextStep],
      });
    });
    openBuilder();
    setStatus(`Appended matrix step: ${command.label}`);
  };

  const handleNewManual = () => {
    setDraft(blankPlaybook());
    setSelectedPlaybookName("");
    openBuilder();
    setStatus("Manual playbook builder is ready.");
  };

  const handleSave = async () => {
    if (!draft?.steps?.length) {
      setStatus("Build or load a playbook before saving.");
      return;
    }
    try {
      const payload = normalizePlaybook(draft);
      await savePlaybook({
        name: payload?.name || "manual-playbook",
        payload,
      });
      await refresh();
      const resolvedName = (payload?.name || "manual-playbook").endsWith(".json")
        ? (payload?.name || "manual-playbook")
        : `${payload?.name || "manual-playbook"}.json`;
      setSelectedPlaybookName(resolvedName);
      setPlaybookPick(resolvedName);
      setStatus("Playbook saved.");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to save playbook."));
    }
  };

  const ensureRunnableTarget = () => {
    const target = buildTargetPayload();
    const hasTarget =
      Boolean(target.agent_id)
      || Boolean(target.group)
      || (Array.isArray(target.agent_ids) && target.agent_ids.length > 0);
    if (!hasTarget) {
      setStatus("Select a valid execution target.");
      return null;
    }
    if (previewTargets.length === 0) {
      setStatus("No agents remain after applying the current target scope and exclusions.");
      return null;
    }
    return target;
  };

  const handleRequestApprovals = async () => {
    if (!draft?.steps?.length) {
      setStatus("Build or load a playbook before requesting approvals.");
      return;
    }
    const unsupported = findUnsupportedStepActions(draft.steps, approvalActionIds);
    if (unsupported.length) {
      setStatus(`Cannot request approvals for unsupported actions (${unsupported.join(", ")}).`);
      return;
    }
    const target = ensureRunnableTarget();
    if (!target) return;

    setStatus("Submitting approvals...");
    try {
      const excludeIds = Array.from(excludeSet);
      const basePayload = {
        ...target,
        ...(excludeIds.length ? { exclude_agent_ids: excludeIds } : {}),
        justification: justification || undefined,
      };
      for (const step of draft.steps) {
        await requestApproval({
          ...basePayload,
          action_id: step.action,
          args: step.args || {},
        });
      }
      setStatus("Approvals requested for all playbook steps.");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to request approvals."));
    }
  };

  const handleExecutePlaybook = async () => {
    if (!draft?.steps?.length) {
      setStatus("Build or load a playbook before execution.");
      return;
    }
    const unsupported = findUnsupportedStepActions(draft.steps);
    if (unsupported.length) {
      setStatus(`Cannot execute with non-executable actions (${unsupported.join(", ")}).`);
      return;
    }
    const target = ensureRunnableTarget();
    if (!target) return;

    setStatus(dryRun ? "Submitting playbook simulation..." : "Submitting playbook execution...");
    try {
      const excludeIds = Array.from(excludeSet);
      const response = await executePlaybook({
        playbook: normalizePlaybook(draft),
        dry_run: dryRun,
        ...target,
        ...(excludeIds.length ? { exclude_agent_ids: excludeIds } : {}),
        justification: justification || undefined,
      });
      if (response?.data?.dry_run || response?.data?.status === "SIMULATED") {
        setStatus("Playbook simulation completed. Review the resolved plan before live execution.");
        return;
      }
      const executionId = Number(response?.data?.execution_id || 0) || null;
      if (executionId && typeof onExecutionCreated === "function") onExecutionCreated(executionId);
      setStatus(executionId ? `Playbook execution queued as run #${executionId}.` : "Playbook execution submitted.");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to execute playbook."));
    }
  };

  const playbookJson = useMemo(
    () => JSON.stringify(normalizePlaybook(draft) || {}, null, 2),
    [draft]
  );

  return (
    <div className="card patch-workbench-command-card">
      <div className="card-header">
        <div>
          <h3>4) Playbook Runner</h3>
          <p className="muted">Load saved templates or build manually, then run across selected scope.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" type="button" onClick={refresh} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button className="btn" type="button" onClick={handleNewManual}>
            New Manual Playbook
          </button>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}

      <div className="list">
        <div className="list-item readable">
          <div className="muted">Command Matrix Playbooks</div>
          <div className="meta-line mt-8">
            Load full matrix bundles or append single matrix steps to the current playbook builder.
          </div>
          <div className="page-actions mt-8">
            <select className="input" value={matrixPlatform} onChange={(event) => setMatrixPlatform(event.target.value)}>
              <option value="all">All matrix platforms</option>
              <option value="windows">Windows matrix</option>
              <option value="linux">Linux matrix</option>
            </select>
            <select className="input" value={matrixBundlePick} onChange={(event) => setMatrixBundlePick(event.target.value)}>
              {matrixBundles.length === 0 ? (
                <option value="">No matrix bundles for selected platform</option>
              ) : (
                matrixBundles.map((bundle) => (
                  <option key={`matrix-bundle-${bundle.id}`} value={bundle.id}>
                    {bundle.label}
                  </option>
                ))
              )}
            </select>
            <button className="btn secondary" type="button" disabled={!matrixBundlePick} onClick={loadMatrixBundle}>
              Load Matrix Bundle
            </button>
          </div>

          <div className="page-actions mt-10">
            <input
              className="input"
              value={matrixSearch}
              onChange={(event) => setMatrixSearch(event.target.value)}
              placeholder="Search matrix commands"
            />
            <select className="input" value={matrixCommandPick} onChange={(event) => setMatrixCommandPick(event.target.value)}>
              {matrixCommands.length === 0 ? (
                <option value="">No matrix commands match current filters</option>
              ) : (
                matrixCommands.map((command) => (
                  <option key={`matrix-command-${command.id}`} value={command.id}>
                    {command.label}
                  </option>
                ))
              )}
            </select>
            <button className="btn secondary" type="button" disabled={!matrixCommandPick} onClick={appendMatrixStep}>
              Append Matrix Step
            </button>
          </div>

          <div className="meta-line mt-8">
            {matrixCommands.length} / {MIN_COMMAND_MATRIX.length} matrix commands visible
          </div>
          <div className="meta-line">
            Effective matrix platform: {effectiveMatrixPlatform === "all" ? "All platforms" : effectiveMatrixPlatform}
          </div>
        </div>
      </div>

      <div className="list">
        <div className="list-item readable">
          <div className="muted">Saved Playbooks</div>
          <div className="meta-line mt-8">Search and load a template into the builder.</div>
          <div className="grid-3 mt-10">
            <input
              className="input"
              placeholder="Search playbooks"
              value={playbookSearch}
              onChange={(event) => setPlaybookSearch(event.target.value)}
            />
            <select className="input" value={playbookPick} onChange={(event) => setPlaybookPick(event.target.value)}>
              <option value="">Select saved playbook</option>
              {filteredPlaybooks.map((name) => (
                <option key={name} value={name}>{name}</option>
              ))}
            </select>
            <div className="page-actions">
              <button
                className="btn secondary"
                type="button"
                disabled={!playbookPick}
                onClick={() => {
                  if (!playbookPick) return;
                  void loadPlaybook(playbookPick);
                }}
              >
                Load Selected
              </button>
            </div>
          </div>
          <div className="meta-line mt-8">
            {filteredPlaybooks.length} template(s) visible
            {selectedPlaybookName ? ` | Loaded: ${selectedPlaybookName}` : ""}
          </div>
        </div>
      </div>

      {editorOpened ? (
        <div className="playbook-builder-stack" ref={builderRef}>
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Playbook Builder</h3>
                <p className="muted">Author or adjust playbook steps before execution.</p>
              </div>
            </div>
            <PlaybookEditor playbook={draft} onChange={setDraft} actions={actions} />
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <h3>Playbook JSON Preview</h3>
                <p className="muted">Raw payload that will be saved or executed.</p>
              </div>
            </div>
            <pre className="code-block">{playbookJson}</pre>
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <h3>Save and Execute</h3>
                <p className="muted">Save draft first, choose target scope, then request approval or execute live.</p>
              </div>
            </div>

            <div className="stat-grid">
              <div className="stat-card">
                <div className="stat-label">Steps</div>
                <div className="stat-value">{Array.isArray(draft?.steps) ? draft.steps.length : 0}</div>
                <div className="stat-sub">{draft?.name || "manual-playbook"}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Targets</div>
                <div className="stat-value">{previewTargets.length}</div>
                <div className="stat-sub">{toDisplay(targetType)}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Mode</div>
                <div className="stat-value">{draft?.source?.mode === "manual" ? "Manual" : "Loaded"}</div>
                <div className="stat-sub">Exclude list: {excludeSet.size}</div>
              </div>
            </div>

            <div className="list">
              <div className="list-item readable">
                <div className="muted">1. Save Draft</div>
                <div className="page-actions mt-8">
                  <button className="btn secondary" type="button" onClick={handleSave}>
                    Save Playbook
                  </button>
                  <span className="meta-line">Persist current builder edits before targeting/execution.</span>
                </div>
              </div>

              <div className="list-item readable">
                <div className="muted">2. Target Scope</div>
                <div className="page-actions mt-8">
                  <select className="input" value={targetType} onChange={(event) => setTargetType(event.target.value)}>
                    <option value="fleet">Fleet (all connected agents)</option>
                    <option value="group">Group</option>
                    <option value="multi">Multiple agents</option>
                    <option value="agent">Single agent</option>
                    <option value="os_windows">Windows agents</option>
                    <option value="os_linux">Linux agents</option>
                  </select>
                </div>

                {targetType === "group" ? (
                  <div className="page-actions mt-10">
                    <select className="input" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
                      <option value="">Select group</option>
                      {groups.map((group) => (
                        <option key={group} value={group}>{group}</option>
                      ))}
                    </select>
                  </div>
                ) : null}

                {targetType === "agent" ? (
                  <div className="page-actions mt-10">
                    <select className="input" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
                      <option value="">Select agent</option>
                      {connectedAgents.map((agent) => (
                        <option key={`playbook-agent-${agent.id}`} value={agent.id}>
                          {agent.id} - {agent.name}{agent.group ? ` (${agent.group})` : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : null}

                {targetType === "multi" ? (
                  <div className="mt-10">
                    <div className="page-actions">
                      <input
                        className="input"
                        value={targetSearch}
                        onChange={(event) => setTargetSearch(event.target.value)}
                        placeholder="Search agents"
                      />
                      <select
                        className="input"
                        value={multiPickAgentId}
                        onChange={(event) => setMultiPickAgentId(formatAgentId(event.target.value))}
                      >
                        <option value="">Pick connected agent</option>
                        {targetPickList.map((agent) => (
                          <option key={`pick-target-${agent.id}`} value={agent.id}>
                            {agent.id} - {agent.name}
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
                      <button className="btn secondary" type="button" onClick={() => setTargetAgentIds(targetPickList.map((agent) => agent.id))}>
                        Select Visible
                      </button>
                      <button className="btn secondary" type="button" onClick={() => setTargetAgentIds([])}>
                        Clear
                      </button>
                    </div>
                    <div className="meta-line mt-8">Selected: {selectedAgentSet.size}</div>
                  </div>
                ) : null}
              </div>

              <div className="list-item readable">
                <div className="muted">Exclude Agent IDs (optional)</div>
                <input
                  className="input mt-8"
                  value={excludeAgents}
                  onChange={(event) => setExcludeAgents(event.target.value)}
                  placeholder="Example: 001,004,013"
                />
              </div>

              <div className="list-item readable">
                <div className="muted">Resolved Target Preview</div>
                <div className="page-actions mt-8">
                  <span className="chip">{previewTargets.length} agent(s)</span>
                  <span className="chip">Mode: {toDisplay(targetType)}</span>
                </div>
                <div className="table-scroll h-240 mt-10">
                  <table className="table compact readable">
                    <thead>
                      <tr>
                        <th>Agent ID</th>
                        <th>Name</th>
                        <th>Group</th>
                        <th>Platform</th>
                      </tr>
                    </thead>
                    <tbody>
                      {previewTargets.length === 0 ? (
                        <tr>
                          <td colSpan="4" className="text-center">No agents match the current target scope.</td>
                        </tr>
                      ) : (
                        previewTargets.slice(0, 120).map((agent) => (
                          <tr key={`preview-${agent.id}`}>
                            <td>{agent.id}</td>
                            <td>{agent.name || "-"}</td>
                            <td>{agent.group || "-"}</td>
                            <td>{agent.platform || "-"}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
                {previewTargets.length > 120 ? <div className="meta-line mt-8">Preview limited to first 120 agents.</div> : null}
              </div>

              <div className="list-item readable">
                <div className="muted">Justification (optional)</div>
                <input
                  className="input mt-8"
                  value={justification}
                  onChange={(event) => setJustification(event.target.value)}
                  placeholder="Reason for approval or live execution"
                />
              </div>
              <div className="list-item readable">
                <label className="inline-check">
                  <input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} />
                  <span>Dry run (simulate only)</span>
                </label>
              </div>
            </div>

            <div className="page-actions">
              <button className="btn secondary" type="button" onClick={handleRequestApprovals}>
                Request Approvals
              </button>
              <button className="btn" type="button" onClick={handleExecutePlaybook}>
                {dryRun ? "Simulate Playbook" : "Execute Playbook"}
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="empty-state">
          Load a saved playbook or start a new manual playbook to open the builder.
        </div>
      )}
    </div>
  );
}

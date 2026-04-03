import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  executePlaybook,
  generatePlaybook,
  getActions,
  getAgents,
  getAgentGroups,
  getPlaybook,
  getPlaybooks,
  getSystemAiConfig,
  requestApproval,
  savePlaybook,
  seedDefaultPlaybooks,
} from "../api/wazuh";
import PlaybookEditor from "../components/PlaybookEditor";
import { formatApiError } from "../utils/httpErrors";

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

function normalizeLegacyTask(task = {}, index = 0) {
  const type = task.type || "";
  if (type === "process_kill") {
    return {
      id: `legacy_process_kill_${index + 1}`,
      action: "kill-process",
      args: { pid: String(task.pid || "1234") },
      reason: "Legacy process kill task",
    };
  }
  if (type === "file_delete") {
    return {
      id: `legacy_file_delete_${index + 1}`,
      action: "quarantine-file",
      args: { path: String(task.path || "C:\\Temp\\suspect.exe") },
      reason: "Legacy file delete task",
    };
  }
  if (type === "patch_install") {
    return {
      id: `legacy_patch_install_${index + 1}`,
      action: "patch-linux",
      args: {},
      reason: "Legacy patch install task",
    };
  }
  return {
    id: `legacy_task_${index + 1}`,
    action: "ioc-scan",
    args: { ioc_set: "baseline-global" },
    reason: "Converted legacy task",
  };
}

function normalizePlaybook(payload) {
  if (!payload || typeof payload !== "object") return null;
  const steps = Array.isArray(payload.steps)
    ? payload.steps
    : Array.isArray(payload.tasks)
      ? payload.tasks.map((task, idx) => normalizeLegacyTask(task, idx))
      : [];
  return {
    ...payload,
    name: payload.name || "manual-playbook",
    description: payload.description || "Custom response workflow",
    steps: steps.map((step, idx) => ({
      id: step.id || `step_${idx + 1}`,
      action: step.action || step.command || "endpoint-healthcheck",
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

const mergePlaybookActions = (items = []) => {
  const merged = new Map();
  items.forEach((item) => {
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

export default function Playbooks() {
  const navigate = useNavigate();
  const [playbooks, setPlaybooks] = useState([]);
  const [actions, setActions] = useState([]);
  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [draft, setDraft] = useState(blankPlaybook());
  const [selectedPlaybookName, setSelectedPlaybookName] = useState("");
  const [editorOpened, setEditorOpened] = useState(false);

  const [alertId, setAlertId] = useState("");
  const [caseId, setCaseId] = useState("");
  const [useAiGeneration, setUseAiGeneration] = useState(true);
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiGoalPrompt, setAiGoalPrompt] = useState("");
  const [playbookSearch, setPlaybookSearch] = useState("");
  const [targetType, setTargetType] = useState("agent");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [targetSearch, setTargetSearch] = useState("");
  const [excludeAgents, setExcludeAgents] = useState("");
  const [justification, setJustification] = useState("");
  const [dryRun, setDryRun] = useState(false);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiDisabledReason, setAiDisabledReason] = useState(
    "AI is disabled. Enable it in Org Admin / Platform AI Configuration."
  );
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
      const [playbookRes, actionRes, agentRes, groupRes, aiCfgRes] = await Promise.all([
        getPlaybooks(),
        getActions().catch(() => ({ data: [] })),
        getAgents(undefined, { limit: 5000 }).catch(() => ({ data: [] })),
        getAgentGroups().catch(() => ({ data: [] })),
        getSystemAiConfig().catch(() => ({ data: { ai_config: { enabled: false } } })),
      ]);
      setPlaybooks(Array.isArray(playbookRes?.data) ? playbookRes.data : []);
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
      }));
      setAgents(normalizedAgents.filter((agent) => agent.id));
      setGroups(
        (Array.isArray(groupRes?.data) ? groupRes.data : [])
          .map((group) => String(group.name || group.id || group).trim())
          .filter(Boolean)
      );
      const aiConfig = aiCfgRes?.data?.ai_config || {};
      const enabled = Boolean(aiConfig?.enabled);
      setAiEnabled(enabled);
      setAiDisabledReason(
        enabled
          ? ""
          : "AI is disabled. Enable it in Org Admin / Platform AI Configuration."
      );
      if (!enabled) {
        setUseAiGeneration(false);
      }
    } catch (err) {
      setStatus(formatApiError(err, "Failed to refresh playbook catalogs."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    setTargetAgentIds((current) => current.filter((id) => agents.some((agent) => agent.id === id)));
  }, [agents]);

  const filteredPlaybooks = useMemo(() => {
    const query = playbookSearch.trim().toLowerCase();
    if (!query) return playbooks;
    return playbooks.filter((name) => name.toLowerCase().includes(query));
  }, [playbookSearch, playbooks]);

  const selectedAgentSet = useMemo(
    () => new Set(targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)),
    [targetAgentIds]
  );
  const excludeSet = useMemo(() => parseExcludeIds(excludeAgents), [excludeAgents]);
  const normalizedTargetValue = useMemo(() => formatAgentId(targetValue), [targetValue]);
  const normalizedGroupValue = useMemo(() => String(targetValue || "").trim(), [targetValue]);

  const targetPickList = useMemo(() => {
    const query = targetSearch.trim().toLowerCase();
    const list = agents.filter((agent) => !query || (
      agent.id.toLowerCase().includes(query)
      || String(agent.name || "").toLowerCase().includes(query)
      || String(agent.group || "").toLowerCase().includes(query)
    ));
    return list.slice(0, 120);
  }, [agents, targetSearch]);

  const scopedTargets = useMemo(() => {
    if (targetType === "agent") {
      if (!normalizedTargetValue) return [];
      return agents.filter((agent) => agent.id === normalizedTargetValue);
    }
    if (targetType === "multi") {
      if (!selectedAgentSet.size) return [];
      return agents.filter((agent) => selectedAgentSet.has(agent.id));
    }
    if (targetType === "group") {
      const key = normalizedGroupValue.toLowerCase();
      if (!key) return [];
      return agents.filter((agent) =>
        (agent.groups || []).some((group) => String(group || "").toLowerCase() === key)
      );
    }
    return agents;
  }, [agents, normalizedGroupValue, normalizedTargetValue, selectedAgentSet, targetType]);

  const previewTargets = useMemo(
    () => scopedTargets.filter((agent) => !excludeSet.has(agent.id)),
    [excludeSet, scopedTargets]
  );

  const buildTargetPayload = useCallback(() => {
    if (targetType === "group") return normalizedGroupValue ? { group: normalizedGroupValue } : {};
    if (targetType === "fleet") return { agent_id: "all" };
    if (targetType === "multi") return { agent_ids: Array.from(selectedAgentSet) };
    return normalizedTargetValue ? { agent_id: normalizedTargetValue } : {};
  }, [normalizedGroupValue, normalizedTargetValue, selectedAgentSet, targetType]);

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

  const handleNewManual = () => {
    setDraft(blankPlaybook());
    setSelectedPlaybookName("");
    openBuilder();
    setStatus("Manual playbook builder is ready.");
  };

  const handleGenerate = async () => {
    if (useAiGeneration && !aiEnabled) {
      setStatus(aiDisabledReason || "AI is disabled. Enable it in Org Admin / Platform AI Configuration.");
      return;
    }
    setStatus("");
    setSelectedPlaybookName("");
    try {
      const parsedCaseId = Number(caseId);
      const response = await generatePlaybook({
        alert_id: alertId || undefined,
        case_id: caseId && Number.isFinite(parsedCaseId) ? parsedCaseId : undefined,
        use_ai: useAiGeneration,
        ai_prompt: useAiGeneration ? (aiPrompt || undefined) : undefined,
      });
      const normalized = normalizePlaybook(response.data);
      if (!normalized) {
        setStatus("Generated playbook payload was empty.");
        return;
      }
      setDraft(normalized);
      openBuilder();
      const agent = normalized.source?.agent_id || "";
      if (agent) {
        setTargetType("agent");
        setTargetValue(agent);
      }
      const mode = String(response?.data?.source?.generation_mode || "").toLowerCase();
      const aiError = String(response?.data?.source?.ai_error || "");
      const unmapped = Array.isArray(response?.data?.source?.unmapped_actions)
        ? response.data.source.unmapped_actions.filter(Boolean)
        : [];
      if (mode === "ai") {
        setStatus("AI-generated playbook loaded into the editor.");
      } else if (mode === "ai_prompt") {
        setStatus(
          unmapped.length
            ? `AI playbook loaded with non-catalog actions (${unmapped.join(", ")}). Review steps before execution.`
            : "AI-generated playbook loaded into the editor."
        );
      } else if (useAiGeneration && aiError) {
        setStatus(`Heuristic playbook loaded (AI fallback): ${aiError}`);
      } else {
        setStatus("Generated playbook loaded into the editor.");
      }
    } catch (err) {
      setStatus(formatApiError(err, "Failed to generate playbook."));
    }
  };

  const handleGenerateFromAiGoal = async () => {
    if (!aiEnabled) {
      setStatus(aiDisabledReason || "AI is disabled. Enable it in Org Admin / Platform AI Configuration.");
      return;
    }
    const prompt = String(aiGoalPrompt || "").trim();
    if (!prompt) {
      setStatus("Describe the playbook goal first, then generate.");
      return;
    }
    setStatus("");
    setSelectedPlaybookName("");
    try {
      const response = await generatePlaybook({
        use_ai: true,
        ai_prompt: prompt,
      });
      const normalized = normalizePlaybook(response.data);
      if (!normalized || !Array.isArray(normalized.steps) || normalized.steps.length === 0) {
        const reason = response?.data?.source?.ai_error
          || "AI did not return valid playbook steps for this request.";
        setStatus(`AI generation failed: ${reason}`);
        return;
      }
      setDraft(normalized);
      openBuilder();
      const unmapped = Array.isArray(response?.data?.source?.unmapped_actions)
        ? response.data.source.unmapped_actions.filter(Boolean)
        : [];
      setStatus(
        unmapped.length
          ? `AI playbook loaded with non-catalog actions (${unmapped.join(", ")}). Review or map these before execution.`
          : "AI playbook loaded into the editor."
      );
    } catch (err) {
      setStatus(formatApiError(err, "Failed to generate AI playbook."));
    }
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
      setSelectedPlaybookName((payload?.name || "manual-playbook").endsWith(".json")
        ? (payload?.name || "manual-playbook")
        : `${payload?.name || "manual-playbook"}.json`);
      setStatus("Playbook saved.");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to save playbook."));
    }
  };

  const ensureRunnableTarget = () => {
    const target = buildTargetPayload();
    const hasTarget =
      Boolean(target.agent_id) ||
      Boolean(target.group) ||
      (Array.isArray(target.agent_ids) && target.agent_ids.length > 0);
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
    const target = ensureRunnableTarget();
    if (!target) return;

    setStatus("Submitting approvals...");
    try {
      const excludeIds = Array.from(excludeSet);
      const parsedCaseId = Number(caseId);
      const effectiveCaseId = caseId && Number.isFinite(parsedCaseId) ? parsedCaseId : undefined;
      const basePayload = {
        ...target,
        ...(excludeIds.length ? { exclude_agent_ids: excludeIds } : {}),
        alert_id: draft.source?.alert_id || alertId || undefined,
        case_id: draft.source?.case_id || effectiveCaseId,
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
    const target = ensureRunnableTarget();
    if (!target) return;

    setStatus(dryRun ? "Simulating playbook..." : "Executing playbook...");
    try {
      const excludeIds = Array.from(excludeSet);
      const parsedCaseId = Number(caseId);
      const effectiveCaseId = caseId && Number.isFinite(parsedCaseId) ? parsedCaseId : undefined;
      const response = await executePlaybook({
        name: draft.name || "manual-playbook",
        payload: normalizePlaybook(draft),
        ...target,
        ...(excludeIds.length ? { exclude_agent_ids: excludeIds } : {}),
        dry_run: dryRun,
        alert_id: draft.source?.alert_id || alertId || undefined,
        case_id: draft.source?.case_id || effectiveCaseId,
        justification: justification || undefined,
      });
      if (response?.data?.dry_run || response?.data?.status === "SIMULATED") {
        setStatus("Playbook simulation completed. Review the resolved plan before live execution.");
        return;
      }
      const executionId = response?.data?.execution_id;
      if (executionId) {
        navigate(`/executions?run=${encodeURIComponent(String(executionId))}`, {
          state: { prefillExecutionId: executionId, source: "playbooks" },
        });
        return;
      }
      setStatus("Playbook execution submitted.");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to execute playbook."));
    }
  };

  const playbookJson = useMemo(
    () => JSON.stringify(normalizePlaybook(draft) || {}, null, 2),
    [draft]
  );

  return (
    <div className="page page-route-playbooks">
      <div className="page-header">
        <div>
          <h2>Playbooks</h2>
          <p className="muted">Generate or manually build playbooks, then run them across single agents, groups, or the fleet.</p>
          <p className="muted">Custom shell-style steps are blocked. Playbooks can use approved catalog actions only.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={refresh} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button className="btn" onClick={handleNewManual}>
            New Manual Playbook
          </button>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}

      <div className="grid-2 playbooks-source-grid">
        <div className="card playbooks-saved-card">
          <div className="card-header">
            <div>
              <h3>Saved Playbooks</h3>
              <p className="muted">Load an existing template into the editor, then adjust steps or targets as needed.</p>
            </div>
          </div>
          <div className="page-actions playbooks-search-row">
            <input
              className="input"
              placeholder="Search playbooks"
              value={playbookSearch}
              onChange={(event) => setPlaybookSearch(event.target.value)}
            />
          </div>
          {filteredPlaybooks.length === 0 ? (
            <div className="empty-state">No playbooks available.</div>
          ) : (
            <div className="list-scroll h-240">
              <div className="list">
                {filteredPlaybooks.map((name) => (
                  <button
                    key={name}
                    type="button"
                    className={`list-item clickable readable ${selectedPlaybookName === name ? "selected" : ""}`}
                    onClick={() => loadPlaybook(name)}
                  >
                    <strong>{name}</strong>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="card playbooks-generate-card">
          <div className="card-header">
            <div>
              <h3>Generate From Alert or Case</h3>
              <p className="muted">Keep the existing generator, but land the result in the same manual editor.</p>
            </div>
          </div>

          <div className="playbook-generate-row">
            <div className="playbook-generate-fields">
              <input
                className="input"
                placeholder="Alert ID"
                value={alertId}
                onChange={(event) => setAlertId(event.target.value)}
              />
              <input
                className="input"
                placeholder="Case ID"
                value={caseId}
                onChange={(event) => setCaseId(event.target.value)}
              />
            </div>
            <div className="playbook-generate-action">
              <button className="btn" onClick={handleGenerate}>
                Generate
              </button>
            </div>
          </div>

          <div className="list mt-10">
            <div className="list-item readable">
              <label className="inline-check">
                <input
                  type="checkbox"
                  checked={useAiGeneration}
                  disabled={!aiEnabled}
                  onChange={(event) => setUseAiGeneration(event.target.checked)}
                />
                <span>Use AI Assist for higher-precision steps</span>
              </label>
            </div>
            {useAiGeneration ? (
              <div className="list-item readable">
                <div className="muted">AI Instructions (optional)</div>
                <textarea
                  className="input mt-8"
                  rows={3}
                  value={aiPrompt}
                  disabled={!aiEnabled}
                  onChange={(event) => setAiPrompt(event.target.value)}
                  placeholder="Example: prioritize containment first, keep user impact low, avoid reboot actions."
                />
                <div className="meta-line mt-8">
                  {aiEnabled
                    ? "AI is enabled from Org Admin / Platform AI Configuration."
                    : (aiDisabledReason || "AI is disabled. Enable it in Org Admin / Platform AI Configuration.")}
                </div>
              </div>
            ) : null}
          </div>
          <div className="meta-line">
            Generated playbooks are editable. You can still save, modify, or replace every step before execution.
          </div>
        </div>
      </div>

      <div className="card playbooks-ai-card">
        <div className="list-item readable">
          <div className="muted">AI Playbook Generator</div>
          <div className="meta-line mt-8">
            Describe the response plan you need. AI will generate steps into the same manual editor.
          </div>
          <textarea
            className="input mt-8"
            rows={4}
            value={aiGoalPrompt}
            disabled={!aiEnabled}
            onChange={(event) => setAiGoalPrompt(event.target.value)}
            placeholder="Example: isolate endpoint, block suspicious outbound IPs, collect memory+forensics, then run SCA rescan."
          />
          <div className="page-actions mt-10">
            <button className="btn" onClick={handleGenerateFromAiGoal} disabled={!aiEnabled}>
              Generate From AI Goal
            </button>
          </div>
          <div className="meta-line mt-8">
            {aiEnabled
              ? "AI is enabled from Org Admin / Platform AI Configuration."
              : (aiDisabledReason || "AI is disabled. Enable it in Org Admin / Platform AI Configuration.")}
          </div>
          <div className="meta-line mt-8">
            Prompt mode can include non-catalog action IDs in JSON when needed. Map or edit those steps before execution.
          </div>
        </div>
      </div>

      {editorOpened ? (
        <div className="playbook-builder-stack" ref={builderRef}>
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Playbook Builder</h3>
                <p className="muted">Manually author the workflow or edit a generated/saved playbook step by step.</p>
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
                <div className="stat-label">Source</div>
                <div className="stat-value">{draft?.source?.mode === "manual" ? "Manual" : "Generated"}</div>
                <div className="stat-sub">
                  Alert {draft?.source?.alert_id || alertId || "n/a"} | Case {draft?.source?.case_id || caseId || "n/a"}
                </div>
              </div>
            </div>

            <div className="list">
              <div className="list-item readable">
                <div className="muted">1. Save Draft</div>
                <div className="page-actions mt-8">
                  <button className="btn secondary" onClick={handleSave}>
                    Save Playbook
                  </button>
                  <span className="meta-line">Persist current builder edits before targeting/execution.</span>
                </div>
              </div>

              <div className="list-item readable">
                <div className="muted">2. Target Scope</div>
                <div className="page-actions mt-8">
                  <select className="input" value={targetType} onChange={(event) => setTargetType(event.target.value)}>
                    <option value="agent">Single agent</option>
                    <option value="multi">Multiple agents</option>
                    <option value="group">Specific group</option>
                    <option value="fleet">Fleet (all)</option>
                  </select>
                </div>

                {targetType === "multi" ? (
                  <div className="mt-10">
                    <div className="page-actions">
                      <input
                        className="input"
                        value={targetSearch}
                        onChange={(event) => setTargetSearch(event.target.value)}
                        placeholder="Search agents to select..."
                      />
                      <button
                        type="button"
                        className="btn secondary"
                        onClick={() => setTargetAgentIds(targetPickList.map((agent) => agent.id))}
                      >
                        Select All
                      </button>
                      <button
                        type="button"
                        className="btn secondary"
                        onClick={() => setTargetAgentIds([])}
                      >
                        Clear
                      </button>
                    </div>
                    <div className="meta-line mt-6">Selected: {selectedAgentSet.size}</div>
                    <div className="list-scroll mt-10 h-240">
                      <div className="list">
                        {targetPickList.length === 0 ? (
                          <div className="empty-state">No agents match the current search.</div>
                        ) : (
                          targetPickList.map((agent) => {
                            const checked = selectedAgentSet.has(agent.id);
                            return (
                              <label key={`target-${agent.id}`} className="list-item clickable readable">
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={(event) => {
                                    const enabled = event.target.checked;
                                    setTargetAgentIds((current) => {
                                      const next = new Set(current.map((id) => formatAgentId(id)).filter(Boolean));
                                      if (enabled) next.add(agent.id);
                                      else next.delete(agent.id);
                                      return Array.from(next);
                                    });
                                  }}
                                  className="mr-10"
                                />
                                {agent.name} ({agent.id}){agent.group ? ` - ${agent.group}` : ""}
                              </label>
                            );
                          })
                        )}
                      </div>
                    </div>
                  </div>
                ) : targetType === "group" ? (
                  <div className="page-actions mt-10">
                    <select className="input" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
                      <option value="">Select group</option>
                      {groups.map((group) => (
                        <option key={group} value={group}>
                          {group}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : targetType === "agent" ? (
                  <div className="page-actions mt-10">
                    <input
                      className="input"
                      value={targetValue}
                      onChange={(event) => setTargetValue(event.target.value)}
                      placeholder="Agent ID (example: 004)"
                      list="playbookAgentIds"
                    />
                    <datalist id="playbookAgentIds">
                      {agents.slice(0, 120).map((agent) => (
                        <option key={`agent-${agent.id}`} value={agent.id}>
                          {agent.name}
                        </option>
                      ))}
                    </datalist>
                  </div>
                ) : (
                  <div className="meta-line mt-10">Fleet targets every known agent unless excluded below.</div>
                )}
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
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {previewTargets.length === 0 ? (
                        <tr>
                          <td colSpan="4" className="text-center">
                            No agents match the current target scope.
                          </td>
                        </tr>
                      ) : (
                        previewTargets.slice(0, 120).map((agent) => (
                          <tr key={`preview-${agent.id}`}>
                            <td>{agent.id}</td>
                            <td>{agent.name || "-"}</td>
                            <td>{agent.group || "-"}</td>
                            <td>{agent.status || "-"}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
                {previewTargets.length > 120 ? (
                  <div className="meta-line mt-8">Preview limited to the first 120 agents.</div>
                ) : null}
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
                  <input
                    type="checkbox"
                    checked={dryRun}
                    onChange={(event) => setDryRun(event.target.checked)}
                  />
                  <span>Dry run (simulate only)</span>
                </label>
              </div>
            </div>

            <div className="page-actions">
              <button className="btn secondary" onClick={handleRequestApprovals}>
                Request Approvals
              </button>
              <button className="btn" onClick={handleExecutePlaybook}>
                {dryRun ? "Simulate Playbook" : "Execute Playbook"}
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="empty-state">
          Generate from Alert/Case, generate from AI prompt, load a saved playbook, or start a new manual playbook to open the builder.
        </div>
      )}
    </div>
  );
}


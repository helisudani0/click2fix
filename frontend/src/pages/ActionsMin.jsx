import { useCallback, useEffect, useMemo, useState } from "react";
import { getActions, getAgents, runAction } from "../api/wazuh";
import { formatApiError } from "../utils/httpErrors";

const CONNECTED_STATUSES = new Set(["active", "connected", "online"]);
const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);
const WINDOWS_ONLY_ACTION_IDS = new Set([
  "patch-windows",
  "windows-os-update",
  "rollback-kb",
  "hide-kb",
  "remove-kb",
  "disable-guest",
  "run-ps",
  "run-cmd",
]);
const LINUX_ONLY_ACTION_IDS = new Set([
  "patch-linux",
  "run-bash",
  "run-sh",
]);

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

const toGroups = (agent) => {
  const out = [];
  const append = (value) => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) {
      value.forEach((item) => append(item));
      return;
    }
    const text = String(value).trim();
    if (!text) return;
    if (text.includes(",")) {
      text.split(",").forEach((item) => append(item));
      return;
    }
    out.push(text);
  };
  append(agent?.group);
  append(agent?.groups);
  append(agent?.group_name);
  return Array.from(new Set(out));
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

const actionLabel = (action) => String(action?.label || action?.name || action?.id || "").trim();
const actionCategory = (action) => String(action?.category || action?.type || "Uncategorized").trim() || "Uncategorized";
const actionSupportedPlatforms = (action) => {
  const values = Array.isArray(action?.capabilities?.supported_os)
    ? action.capabilities.supported_os
    : [];
  const explicit = values.map((item) => String(item || "").trim().toLowerCase()).filter(Boolean);
  if (explicit.length) return explicit;
  const actionId = String(action?.id || "").trim().toLowerCase();
  if (WINDOWS_ONLY_ACTION_IDS.has(actionId)) return ["windows"];
  if (LINUX_ONLY_ACTION_IDS.has(actionId)) return ["linux"];
  const blob = [
    action?.id || "",
    action?.label || "",
    action?.description || "",
    action?.command || "",
  ].join(" ").toLowerCase();
  const looksWindows = /\bwindows\b|\bwinrm\b|\bkb\d+\b|netsh|winget|wuauclt|usoclient/.test(blob);
  const looksLinux = /\blinux\b|\bubuntu\b|\bdebian\b|\bcentos\b|\bdnf\b|\byum\b|\bapt\b|\bpacman\b|\bzypper\b/.test(blob);
  if (looksLinux && !looksWindows) return ["linux"];
  if (looksWindows && !looksLinux) return ["windows"];
  return ["windows", "linux"];
};

const compactArgs = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out = {};
  Object.entries(value).forEach(([key, current]) => {
    if (current === null || current === undefined) return;
    if (typeof current === "string" && !current.trim()) return;
    out[key] = current;
  });
  return out;
};

const defaultInputs = (action) => {
  const out = {};
  const fields = Array.isArray(action?.inputs) ? action.inputs : [];
  fields.forEach((field) => {
    if (!field || typeof field !== "object") return;
    const name = String(field.name || "").trim();
    if (!name) return;
    out[name] = field.default !== undefined && field.default !== null ? String(field.default) : "";
  });
  return out;
};

const inputLabel = (field) => String(field?.label || field?.title || field?.name || "Input").trim();
const inputPlaceholder = (field) => String(field?.placeholder || field?.example || field?.description || "").trim();

export default function ActionsMin({ onExecutionCreated }) {
  const [actions, setActions] = useState([]);
  const [actionsLoading, setActionsLoading] = useState(true);
  const [actionsError, setActionsError] = useState("");
  const [agents, setAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(true);

  const [actionId, setActionId] = useState("");
  const [actionInputs, setActionInputs] = useState({});
  const [justification, setJustification] = useState("");
  const [dispatchStatus, setDispatchStatus] = useState("");
  const [dispatching, setDispatching] = useState(false);

  const [targetMode, setTargetMode] = useState("fleet");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [multiPickAgentId, setMultiPickAgentId] = useState("");
  const [agentSearch, setAgentSearch] = useState("");

  const [catalogSearch, setCatalogSearch] = useState("");
  const [catalogCategory, setCatalogCategory] = useState("");
  const [catalogPlatform, setCatalogPlatform] = useState("all");

  const loadActions = useCallback(async () => {
    setActionsLoading(true);
    setActionsError("");
    try {
      const response = await getActions();
      const rows = Array.isArray(response?.data) ? response.data : [];
      setActions(rows);
    } catch (err) {
      setActions([]);
      setActionsError(formatApiError(err, "Failed to load action catalog."));
    } finally {
      setActionsLoading(false);
    }
  }, []);

  const loadAgents = useCallback(async () => {
    setAgentsLoading(true);
    try {
      const response = await getAgents(undefined, {
        force: true,
        compact: true,
        limit: 5000,
        status: "active,connected,online",
      });
      const rows = normalizeAgents(response?.data)
        .map((agent) => {
          const id = formatAgentId(agent?.id || agent?.agent_id);
          if (!id) return null;
          const groups = toGroups(agent);
          return {
            id,
            name: String(agent?.name || agent?.hostname || id).trim(),
            status: String(agent?.status || "unknown").trim().toLowerCase(),
            groups,
            groupText: groups.join(", "),
            platform: agentPlatform(agent),
          };
        })
        .filter(Boolean);
      setAgents(rows);
    } catch {
      setAgents([]);
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadActions();
    void loadAgents();
  }, [loadActions, loadAgents]);

  const selectedAction = useMemo(
    () => actions.find((item) => String(item?.id || "") === String(actionId)) || null,
    [actions, actionId]
  );

  useEffect(() => {
    if (!actions.length) {
      if (actionId) setActionId("");
      return;
    }
    if (!actionId || !actions.some((item) => String(item?.id || "") === String(actionId))) {
      setActionId(String(actions[0]?.id || ""));
    }
  }, [actions, actionId]);

  useEffect(() => {
    setActionInputs(defaultInputs(selectedAction));
  }, [selectedAction]);

  const connectedAgents = useMemo(
    () => agents.filter((agent) => CONNECTED_STATUSES.has(agent.status)),
    [agents]
  );

  const availableGroups = useMemo(() => {
    const names = new Set();
    connectedAgents.forEach((agent) => {
      (agent.groups || []).forEach((group) => {
        const text = String(group || "").trim();
        if (text) names.add(text);
      });
    });
    return Array.from(names).sort((left, right) => left.localeCompare(right));
  }, [connectedAgents]);

  const selectedAgentSet = useMemo(
    () => new Set(targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)),
    [targetAgentIds]
  );

  const filteredAgents = useMemo(() => {
    const query = String(agentSearch || "").trim().toLowerCase();
    if (!query) return connectedAgents;
    return connectedAgents.filter((agent) => (
      agent.id.toLowerCase().includes(query)
      || String(agent.name || "").toLowerCase().includes(query)
      || String(agent.groupText || "").toLowerCase().includes(query)
    ));
  }, [agentSearch, connectedAgents]);

  const scopedTargets = useMemo(() => {
    const value = String(targetValue || "").trim();
    const normalizedAgentId = formatAgentId(value);
    const normalizedGroup = value.toLowerCase();

    if (targetMode === "agent") {
      if (!normalizedAgentId) return [];
      return connectedAgents.filter((agent) => agent.id === normalizedAgentId);
    }
    if (targetMode === "multi") {
      if (!selectedAgentSet.size) return [];
      return connectedAgents.filter((agent) => selectedAgentSet.has(agent.id));
    }
    if (targetMode === "group") {
      if (!normalizedGroup) return [];
      return connectedAgents.filter((agent) =>
        (agent.groups || []).some((group) => String(group || "").trim().toLowerCase() === normalizedGroup)
      );
    }
    if (targetMode === "os_windows") {
      return connectedAgents.filter((agent) => agent.platform === "windows");
    }
    if (targetMode === "os_linux") {
      return connectedAgents.filter((agent) => agent.platform === "linux");
    }
    return connectedAgents;
  }, [connectedAgents, selectedAgentSet, targetMode, targetValue]);

  const resolvedTargetIds = useMemo(() => scopedTargets.map((agent) => agent.id), [scopedTargets]);

  const categories = useMemo(
    () => Array.from(new Set(actions.map((item) => actionCategory(item)))).sort((left, right) => left.localeCompare(right)),
    [actions]
  );

  const filteredActions = useMemo(() => {
    const query = String(catalogSearch || "").trim().toLowerCase();
    const effectivePlatform =
      catalogPlatform !== "all"
        ? catalogPlatform
        : targetMode === "os_linux"
          ? "linux"
          : targetMode === "os_windows"
            ? "windows"
            : "all";
    return actions.filter((action) => {
      const category = actionCategory(action);
      if (catalogCategory && category !== catalogCategory) return false;
      const platforms = actionSupportedPlatforms(action);
      if (effectivePlatform === "windows" && !platforms.includes("windows")) return false;
      if (effectivePlatform === "linux" && !platforms.includes("linux")) return false;
      if (!query) return true;
      const blob = [actionLabel(action), action?.id || "", action?.description || "", category]
        .join(" ")
        .toLowerCase();
      return blob.includes(query);
    });
  }, [actions, catalogCategory, catalogPlatform, catalogSearch, targetMode]);

  const effectiveCatalogPlatformLabel = useMemo(() => {
    if (catalogPlatform !== "all") return catalogPlatform === "linux" ? "Linux" : "Windows";
    if (targetMode === "os_linux") return "Linux (from target scope)";
    if (targetMode === "os_windows") return "Windows (from target scope)";
    return "All platforms";
  }, [catalogPlatform, targetMode]);

  useEffect(() => {
    if (!filteredActions.length) return;
    if (!actionId || !filteredActions.some((item) => String(item?.id || "") === String(actionId))) {
      setActionId(String(filteredActions[0]?.id || ""));
    }
  }, [actionId, filteredActions]);

  const actionInputsList = useMemo(
    () => Array.isArray(selectedAction?.inputs) ? selectedAction.inputs.filter((field) => field && field.name) : [],
    [selectedAction]
  );

  const missingRequiredInput = useMemo(
    () => actionInputsList.some((field) => field.required && !String(actionInputs?.[field.name] ?? "").trim()),
    [actionInputs, actionInputsList]
  );

  const canRun = Boolean(selectedAction) && resolvedTargetIds.length > 0 && !missingRequiredInput && !dispatching;

  const runSelectedAction = useCallback(async () => {
    if (!selectedAction) {
      setDispatchStatus("Select an action first.");
      return;
    }
    if (!resolvedTargetIds.length) {
      setDispatchStatus("Select target scope with at least one connected agent.");
      return;
    }
    if (missingRequiredInput) {
      setDispatchStatus("Fill all required inputs before dispatch.");
      return;
    }

    setDispatching(true);
    setDispatchStatus("Submitting action...");
    try {
      const response = await runAction({
        agent_ids: resolvedTargetIds,
        action_id: String(selectedAction?.id || actionId),
        args: compactArgs(actionInputs),
        justification: justification.trim() || "Action execution requested from min workbench.",
        async: true,
      });
      const executionId = Number(response?.data?.execution_id || 0) || null;
      if (executionId && typeof onExecutionCreated === "function") {
        onExecutionCreated(executionId);
      }
      setDispatchStatus(executionId ? `Action queued as execution #${executionId}.` : "Action queued.");
    } catch (err) {
      setDispatchStatus(formatApiError(err, "Action dispatch failed."));
    } finally {
      setDispatching(false);
    }
  }, [actionId, actionInputs, justification, missingRequiredInput, onExecutionCreated, resolvedTargetIds, selectedAction]);

  return (
    <div className="card patch-workbench-command-card">
      <div className="card-header">
        <div>
          <h3>4) Action Runner</h3>
          <p className="muted">Select scope, filter catalog, pick action from dropdown, and dispatch.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" type="button" onClick={() => void loadAgents()} disabled={agentsLoading}>
            {agentsLoading ? "Refreshing Targets..." : "Refresh Targets"}
          </button>
          <button className="btn secondary" type="button" onClick={() => void loadActions()} disabled={actionsLoading}>
            {actionsLoading ? "Refreshing Catalog..." : "Refresh Catalog"}
          </button>
        </div>
      </div>

      {actionsError ? <div className="empty-state">{actionsError}</div> : null}

      <div className="list">
        <div className="list-item readable">
          <div className="muted">Target Scope</div>
          <div className="page-actions mt-8">
            <select className="input" value={targetMode} onChange={(event) => setTargetMode(event.target.value)}>
              <option value="fleet">Fleet (all connected agents)</option>
              <option value="group">Group</option>
              <option value="multi">Multiple agents</option>
              <option value="agent">Single agent</option>
              <option value="os_windows">Windows agents</option>
              <option value="os_linux">Linux agents</option>
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
                  <option key={`target-agent-${agent.id}`} value={agent.id}>
                    {agent.id} - {agent.name}{agent.groupText ? ` (${agent.groupText})` : ""}
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
                  placeholder="Search agents"
                />
                <select className="input" value={multiPickAgentId} onChange={(event) => setMultiPickAgentId(event.target.value)}>
                  <option value="">Pick agent</option>
                  {filteredAgents.map((agent) => (
                    <option key={`multi-agent-${agent.id}`} value={agent.id}>
                      {agent.id} - {agent.name}
                    </option>
                  ))}
                </select>
                <button
                  className="btn secondary"
                  type="button"
                  onClick={() => {
                    if (!multiPickAgentId) return;
                    setTargetAgentIds((current) => {
                      const next = new Set(current.map((id) => formatAgentId(id)).filter(Boolean));
                      next.add(multiPickAgentId);
                      return Array.from(next);
                    });
                  }}
                  disabled={!multiPickAgentId}
                >
                  Add
                </button>
                <button className="btn secondary" type="button" onClick={() => setTargetAgentIds(filteredAgents.map((agent) => agent.id))}>
                  Select Visible
                </button>
                <button className="btn secondary" type="button" onClick={() => setTargetAgentIds([])}>
                  Clear
                </button>
              </div>
              <div className="meta-line mt-8">Selected agents: {selectedAgentSet.size}</div>
            </div>
          ) : null}

          <div className="meta-line mt-10">Resolved connected targets: {resolvedTargetIds.length}</div>
        </div>

        <div className="list-item readable">
          <div className="muted">Action Catalog</div>
          <div className="page-actions mt-8">
            <input
              className="input"
              value={catalogSearch}
              onChange={(event) => setCatalogSearch(event.target.value)}
              placeholder="Search by action, id, category"
            />
            <select className="input" value={catalogCategory} onChange={(event) => setCatalogCategory(event.target.value)}>
              <option value="">All categories</option>
              {categories.map((category) => (
                <option key={`action-category-${category}`} value={category}>{category}</option>
              ))}
            </select>
            <select className="input" value={catalogPlatform} onChange={(event) => setCatalogPlatform(event.target.value)}>
              <option value="all">All platforms</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
          </div>
          <div className="page-actions mt-8">
            <select className="input" value={actionId} onChange={(event) => setActionId(event.target.value)}>
              {filteredActions.length === 0 ? (
                <option value="">No actions match current filters</option>
              ) : (
                filteredActions.map((action) => (
                  <option key={`action-option-${action?.id}`} value={String(action?.id || "")}>
                    {actionLabel(action)} ({actionCategory(action)})
                  </option>
                ))
              )}
            </select>
          </div>
          <div className="meta-line mt-8">{filteredActions.length} / {actions.length} actions visible</div>
          <div className="meta-line">Effective platform filter: {effectiveCatalogPlatformLabel}</div>
        </div>

        {selectedAction ? (
          <div className="list-item readable">
            <div className="muted">Action Inputs</div>
            {actionInputsList.length === 0 ? (
              <div className="meta-line mt-8">This action has no additional inputs.</div>
            ) : (
              <div className="grid-2 mt-10">
                {actionInputsList.map((field) => {
                  const name = String(field.name || "").trim();
                  if (!name) return null;
                  const value = String(actionInputs?.[name] ?? "");
                  const isMultiline = MULTILINE_INPUT_FIELDS.has(name.toLowerCase()) || /\n/.test(value);
                  return (
                    <label key={`action-input-${name}`} className="list-item readable">
                      <div className="muted">
                        {inputLabel(field)}{field.required ? " *" : ""}
                      </div>
                      {isMultiline ? (
                        <textarea
                          className="input mt-8 mono"
                          rows={4}
                          value={value}
                          onChange={(event) => setActionInputs((current) => ({ ...current, [name]: event.target.value }))}
                          placeholder={inputPlaceholder(field) || `Enter ${name}`}
                        />
                      ) : (
                        <input
                          className="input mt-8"
                          value={value}
                          onChange={(event) => setActionInputs((current) => ({ ...current, [name]: event.target.value }))}
                          placeholder={inputPlaceholder(field) || `Enter ${name}`}
                        />
                      )}
                    </label>
                  );
                })}
              </div>
            )}
          </div>
        ) : null}

        <div className="list-item readable">
          <div className="muted">Justification (optional)</div>
          <input
            className="input mt-8"
            value={justification}
            onChange={(event) => setJustification(event.target.value)}
            placeholder="Reason for this action"
          />
        </div>

        <div className="page-actions">
          <button className="btn" type="button" onClick={runSelectedAction} disabled={!canRun}>
            {dispatching ? "Queueing..." : "Run Catalog Action"}
          </button>
        </div>
        {dispatchStatus ? <div className="empty-state">{dispatchStatus}</div> : null}
      </div>
    </div>
  );
}

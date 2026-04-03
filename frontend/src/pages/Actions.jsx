import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ExecutionStream from "../components/ExecutionStream";
import { getActions, getAgents, getActionConnectorStatus, runAction } from "../api/wazuh";
import { formatApiError } from "../utils/httpErrors";

const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);
const ACTIONS_SIDEBAR_WIDTH_STORAGE_KEY = "c2f-actions-sidebar-width-v4";
const DEFAULT_ACTIONS_SIDEBAR_WIDTH = 440;
const MIN_ACTIONS_SIDEBAR_WIDTH = 360;
const MAX_ACTIONS_SIDEBAR_WIDTH = 640;
const DEFAULT_ACTION_JUSTIFICATION = "Action execution requested from Actions workspace.";
const TARGET_MODE_LABELS = {
  agent: "Single agent",
  multi: "Multiple agents",
  group: "Specific group",
  fleet: "Fleet",
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
  if (typeof raw === "number") return String(raw).padStart(3, "0");
  const value = String(raw).trim();
  return /^[0-9]+$/.test(value) && value.length < 3 ? value.padStart(3, "0") : value;
};

const toAgentGroups = (agent) => {
  const values = [];
  const append = (value) => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) {
      value.forEach((item) => append(item));
      return;
    }
    const text = String(value).trim();
    if (!text) return;
    if (text.includes(",")) {
      text.split(",").forEach((part) => append(part));
      return;
    }
    values.push(text);
  };
  append(agent?.group);
  append(agent?.groups);
  append(agent?.group_name);
  return Array.from(new Set(values));
};

const toDisplay = (value, fallback = "-") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) {
    const labels = value.map((item) => toDisplay(item, "")).filter(Boolean);
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
  Object.entries(value).forEach(([key, current]) => {
    if (current === null || current === undefined) return;
    if (typeof current === "string" && current.trim() === "") return;
    out[key] = current;
  });
  return out;
};

const buildDefaultActionInputs = (action) => {
  const defaults = {};
  const inputs = Array.isArray(action?.inputs) ? action.inputs : [];
  inputs.forEach((field) => {
    if (!field || typeof field !== "object") return;
    const name = String(field.name || "").trim();
    if (!name) return;
    defaults[name] =
      field.default !== undefined && field.default !== null ? String(field.default) : "";
  });
  return defaults;
};

const actionLabel = (action) => String(action?.label || action?.name || action?.id || "").trim();
const actionCategory = (action) => String(action?.category || action?.type || "Uncategorized").trim() || "Uncategorized";
const actionInputCount = (action) => (Array.isArray(action?.inputs) ? action.inputs.length : 0);
const actionRequiredInputCount = (action) =>
  Array.isArray(action?.inputs) ? action.inputs.filter((field) => field?.required).length : 0;
const actionRiskLabel = (action) => String(action?.risk || "").trim().toLowerCase() || "unspecified";
const actionRiskTone = (action) => {
  const risk = actionRiskLabel(action);
  if (risk.includes("critical") || risk.includes("high")) return "risk-high";
  if (risk.includes("medium")) return "risk-medium";
  if (risk.includes("low")) return "risk-low";
  return "risk-neutral";
};

const isAgentConnected = (status) => {
  const value = String(status || "").trim().toLowerCase();
  return value.includes("active") || value.includes("connected") || value.includes("online");
};

const clampSidebarWidth = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return DEFAULT_ACTIONS_SIDEBAR_WIDTH;
  return Math.min(MAX_ACTIONS_SIDEBAR_WIDTH, Math.max(MIN_ACTIONS_SIDEBAR_WIDTH, Math.round(numeric)));
};

const inputLabel = (field) => String(field?.label || field?.title || field?.name || "Input").trim();
const inputPlaceholder = (field) => String(field?.placeholder || field?.example || field?.description || "").trim();

const statusToneFromText = (value) => {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "neutral";
  if (text.includes("failed") || text.includes("error") || text.includes("degraded") || text.includes("disconnected")) return "failed";
  if (text.includes("submitted") || text.includes("success") || text.includes("connected") || text.includes("available")) return "success";
  return "pending";
};

const connectorSummary = (status, error, loaded) => {
  if (error) return "Degraded";
  if (!loaded) return "Checking";
  const connectors = status?.connectors && typeof status.connectors === "object" ? status.connectors : status;
  if (!connectors || typeof connectors !== "object") return "Unavailable";
  const connectorList = Object.values(connectors).filter(
    (connector) => connector && typeof connector === "object" && "enabled" in connector
  );
  if (!connectorList.length) return "Unavailable";
  const enabledConnectors = connectorList.filter((connector) => connector.enabled !== false);
  if (!enabledConnectors.length) return "Disabled";
  const configuredCount = enabledConnectors.filter((connector) => connector.credentials_configured === true).length;
  if (configuredCount === enabledConnectors.length) return "Connected";
  if (configuredCount > 0) return "Partial";
  return "Needs Setup";
};

const buildActionHints = (action) => {
  const inputs = Array.isArray(action?.inputs)
    ? action.inputs.filter((field) => field && typeof field === "object" && field.name)
    : [];
  const hints = [];
  if (!inputs.length) hints.push("This action does not require additional arguments.");
  inputs.forEach((field) => {
    const parts = [];
    if (field.required) parts.push("required");
    if (inputPlaceholder(field)) parts.push(inputPlaceholder(field));
    if (field.default !== undefined && field.default !== null && String(field.default).trim()) parts.push(`default: ${String(field.default)}`);
    hints.push(`${inputLabel(field)}: ${parts.join(" | ") || "optional input"}`);
  });
  if (inputs.some((field) => /(package|app|software|winget|choco)/i.test(`${field?.name || ""} ${field?.label || ""} ${field?.description || ""}`))) {
    hints.push("Keep package identifiers exact. Do not edit punctuation, backticks, colons, or dollar-prefixed tokens.");
  }
  hints.push("Command text is sent as entered. No auto-formatting is applied before dispatch.");
  return hints;
};

const MaskedAgentId = ({ value }) => {
  const agentId = formatAgentId(value);
  if (!agentId) return <span>-</span>;
  if (agentId.length <= 8) return <span className="agent-id-mask">{agentId}</span>;
  return (
    <span className="agent-id-mask">
      <span>{agentId.slice(0, 4)}</span>
      <span className="agent-id-mask-middle">...</span>
      <span>{agentId.slice(-4)}</span>
    </span>
  );
};

export default function Actions() {
  const resizeRef = useRef(null);
  const executionPlanRef = useRef(null);
  const [actions, setActions] = useState([]);
  const [actionSearch, setActionSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [actionId, setActionId] = useState("");
  const [actionInputs, setActionInputs] = useState({});
  const [actionStatus, setActionStatus] = useState("");
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [justification, setJustification] = useState("");
  const [agents, setAgents] = useState([]);
  const [targetMode, setTargetMode] = useState("fleet");
  const [singleTargetId, setSingleTargetId] = useState("");
  const [groupTarget, setGroupTarget] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [multiPickAgentId, setMultiPickAgentId] = useState("");
  const [connectorStatus, setConnectorStatus] = useState(null);
  const [connectorError, setConnectorError] = useState("");
  const [connectorLoaded, setConnectorLoaded] = useState(false);
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_ACTIONS_SIDEBAR_WIDTH;
    return clampSidebarWidth(window.localStorage.getItem(ACTIONS_SIDEBAR_WIDTH_STORAGE_KEY));
  });

  const selectedAction = useMemo(
    () => actions.find((action) => String(action?.id || "") === String(actionId)) || null,
    [actions, actionId]
  );

  const actionCategories = useMemo(
    () => Array.from(new Set(actions.map((action) => actionCategory(action)))).sort((left, right) => left.localeCompare(right)),
    [actions]
  );

  const filteredActions = useMemo(() => {
    const query = actionSearch.trim().toLowerCase();
    return actions.filter((action) => {
      const category = actionCategory(action);
      if (categoryFilter && category !== categoryFilter) return false;
      if (!query) return true;
      const haystack = [actionLabel(action), category, action?.description || "", action?.id || ""].join(" ").toLowerCase();
      return haystack.includes(query);
    });
  }, [actions, actionSearch, categoryFilter]);

  const selectedCatalogAction = useMemo(
    () => filteredActions.find((action) => String(action?.id || "") === String(actionId)) || selectedAction,
    [filteredActions, selectedAction, actionId]
  );

  const connectedAgents = useMemo(
    () => agents.filter((agent) => isAgentConnected(agent.status)),
    [agents]
  );

  const availableGroups = useMemo(() => {
    const names = new Set();
    connectedAgents.forEach((agent) => {
      (agent.groups || []).forEach((group) => {
        const value = String(group || "").trim();
        if (value) names.add(value);
      });
    });
    return Array.from(names).sort((left, right) => left.localeCompare(right));
  }, [connectedAgents]);

  const selectedMultiAgentSet = useMemo(
    () => new Set(targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)),
    [targetAgentIds]
  );

  const selectedMultiAgents = useMemo(
    () => connectedAgents.filter((agent) => selectedMultiAgentSet.has(agent.id)),
    [connectedAgents, selectedMultiAgentSet]
  );

  const scopedTargets = useMemo(() => {
    if (targetMode === "agent") {
      const match = connectedAgents.find((agent) => agent.id === formatAgentId(singleTargetId));
      return match ? [match] : [];
    }
    if (targetMode === "multi") {
      return connectedAgents.filter((agent) => selectedMultiAgentSet.has(agent.id));
    }
    if (targetMode === "group") {
      const normalizedGroup = String(groupTarget || "").trim().toLowerCase();
      if (!normalizedGroup) return [];
      return connectedAgents.filter((agent) =>
        (agent.groups || []).some((group) => String(group || "").trim().toLowerCase() === normalizedGroup)
      );
    }
    return connectedAgents;
  }, [connectedAgents, targetMode, singleTargetId, selectedMultiAgentSet, groupTarget]);

  const selectedAgents = scopedTargets;
  const resolvedTargetIds = useMemo(() => scopedTargets.map((agent) => agent.id), [scopedTargets]);

  const actionInputsList = useMemo(
    () => Array.isArray(selectedAction?.inputs) ? selectedAction.inputs.filter((field) => field && typeof field === "object" && field.name) : [],
    [selectedAction]
  );

  const actionHints = useMemo(() => buildActionHints(selectedAction), [selectedAction]);
  const connectedAgentCount = connectedAgents.length;
  const effectiveJustification = useMemo(
    () => (justification.trim() ? justification.trim() : DEFAULT_ACTION_JUSTIFICATION),
    [justification]
  );

  const payloadPreview = useMemo(() => {
    if (!selectedAction) return "";
    return JSON.stringify(
      {
        agent_ids: resolvedTargetIds,
        action_id: actionId,
        args: compactArgs(actionInputs),
        justification: effectiveJustification,
        async: true,
      },
      null,
      2
    );
  }, [selectedAction, resolvedTargetIds, actionId, actionInputs, effectiveJustification]);

  const connectorLabel = connectorSummary(connectorStatus, connectorError, connectorLoaded);
  const connectorTone = statusToneFromText(connectorStatus?.status || connectorError || connectorLabel);
  const actionStatusTone = statusToneFromText(actionStatus);
  const missingRequiredInput = actionInputsList.some((field) => field.required && !String(actionInputs?.[field.name] ?? "").trim());
  const canExecute = Boolean(selectedAction) && resolvedTargetIds.length > 0 && !missingRequiredInput && !isActionRunning;

  const loadActions = useCallback(async () => {
    try {
      const response = await getActions();
      setActions(Array.isArray(response?.data) ? response.data : []);
    } catch {
      setActions([]);
    }
  }, []);

  const loadAgents = useCallback(async () => {
    try {
      const response = await getAgents(undefined, { limit: 5000 });
      const list = normalizeAgents(response?.data)
        .map((agent) => {
          const id = formatAgentId(agent?.id || agent?.agent_id || "");
          if (!id) return null;
          const hostname = toDisplay(agent?.name || agent?.hostname || id, id);
          const groups = toAgentGroups(agent);
          return {
            id,
            name: hostname,
            hostname,
            status: toDisplay(agent?.status, "unknown"),
            os: toDisplay(agent?.os?.name || agent?.os || agent?.platform, "-"),
            latency: Number(agent?.latency_ms || agent?.latency || agent?.ping || 0) || 0,
            groups,
            groupText: groups.join(", "),
          };
        })
        .filter(Boolean);
      setAgents(list);
    } catch {
      setAgents([]);
    }
  }, []);

  const loadConnectorStatus = useCallback(async () => {
    try {
      const response = await getActionConnectorStatus();
      setConnectorStatus(response?.data || null);
      setConnectorError("");
    } catch (error) {
      setConnectorStatus(null);
      setConnectorError(error?.response?.data?.detail || error?.message || "Connector status unavailable");
    } finally {
      setConnectorLoaded(true);
    }
  }, []);

  useEffect(() => {
    void loadActions();
    void loadAgents();
    void loadConnectorStatus();
  }, [loadActions, loadAgents, loadConnectorStatus]);

  useEffect(() => {
    if (!actions.length) {
      if (actionId) setActionId("");
      return;
    }
    if (!actionId || !actions.some((action) => String(action?.id || "") === String(actionId))) {
      setActionId(String(actions[0]?.id || ""));
    }
  }, [actions, actionId]);

  useEffect(() => {
    setActionInputs(buildDefaultActionInputs(selectedAction));
  }, [selectedAction]);

  useEffect(() => {
    setTargetAgentIds((current) => current.filter((id) => connectedAgents.some((agent) => agent.id === id)));
  }, [connectedAgents]);

  useEffect(() => {
    if (targetMode !== "multi") setMultiPickAgentId("");
    if (targetMode !== "agent") setSingleTargetId("");
    if (targetMode !== "group") setGroupTarget("");
  }, [targetMode]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(ACTIONS_SIDEBAR_WIDTH_STORAGE_KEY, String(sidebarWidth));
  }, [sidebarWidth]);

  const stopResize = useCallback(() => {
    const current = resizeRef.current;
    if (current) {
      window.removeEventListener("mousemove", current.onMove);
      window.removeEventListener("mouseup", current.onUp);
      resizeRef.current = null;
    }
    if (typeof document !== "undefined") {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    }
  }, []);

  useEffect(() => () => stopResize(), [stopResize]);

  const startResize = useCallback((event) => {
    if (event.button !== 0) return;
    const startX = event.clientX;
    const startWidth = sidebarWidth;
    const onMove = (moveEvent) => setSidebarWidth(clampSidebarWidth(startWidth + (moveEvent.clientX - startX)));
    const onUp = () => stopResize();
    resizeRef.current = { onMove, onUp };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    document.body.style.userSelect = "none";
    document.body.style.cursor = "col-resize";
    event.preventDefault();
  }, [sidebarWidth, stopResize]);

  const handleActionSelect = useCallback((action) => {
    const nextId = String(action?.id || "").trim();
    if (!nextId) return;
    setActionId(nextId);
    setActionStatus("");
    if (typeof window !== "undefined") {
      window.requestAnimationFrame(() => {
        executionPlanRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  }, []);

  const handleToggleAgent = useCallback((agentId) => {
    const formattedId = formatAgentId(agentId);
    if (!formattedId) return;
    setTargetAgentIds((current) =>
      current.includes(formattedId)
        ? current.filter((id) => id !== formattedId)
        : [...current, formattedId]
    );
    setActionStatus("");
  }, []);

  const handleActionInputChange = useCallback((name, value) => {
    const key = String(name || "").trim();
    if (!key) return;
    setActionInputs((current) => ({ ...current, [key]: value }));
  }, []);

  const handleExecuteAction = useCallback(async () => {
    if (!selectedAction || resolvedTargetIds.length === 0) {
      setActionStatus("Select an action and at least one target agent.");
      return;
    }
    if (missingRequiredInput) {
      setActionStatus("Fill every required input before dispatch.");
      return;
    }
    if (isActionRunning) return;

    setIsActionRunning(true);
    setActionStatus("Submitting action...");
    setActiveExecutionId(null);

    try {
      const response = await runAction({
        agent_ids: resolvedTargetIds,
        action_id: actionId,
        args: compactArgs(actionInputs),
        justification: effectiveJustification,
        async: true,
      });
      const executionId = response?.data?.execution_id;
      setActiveExecutionId(executionId || null);
      setActionStatus(executionId ? `Action submitted as execution #${executionId}.` : "Action submitted.");
    } catch (error) {
      setActionStatus(formatApiError(error, "Action execution failed."));
    } finally {
      setIsActionRunning(false);
    }
  }, [selectedAction, resolvedTargetIds, missingRequiredInput, isActionRunning, actionId, actionInputs, effectiveJustification]);

  return (
    <div className="page actions-page page-route-actions">
      <div className="page-header">
        <div>
          <h2>Actions Workspace</h2>
          <p className="muted">Select a response action, target the right agents, and dispatch without leaving the console shell.</p>
        </div>
        <div className="page-actions actions-header-actions">
          <span className={`status-pill ${connectorTone}`}>Connector {connectorLabel}</span>
          <button type="button" className="btn secondary" onClick={() => void loadConnectorStatus()}>
            Refresh Connector
          </button>
          <button type="button" className="btn secondary" onClick={() => void loadActions()}>
            Refresh Catalog
          </button>
          <button type="button" className="btn secondary" onClick={() => void loadAgents()}>
            Refresh Targets
          </button>
        </div>
      </div>

      <div className="mission-grid">
        <div className="mission-card">
          <div className="mission-label">Selected Action</div>
          <div className="mission-value">{selectedAction ? actionLabel(selectedAction) : "-"}</div>
          <div className="mission-meta">{selectedAction ? actionCategory(selectedAction) : "Pick an action from the catalog."}</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Target Scope</div>
          <div className="mission-value">{resolvedTargetIds.length}</div>
          <div className="mission-meta">
            {TARGET_MODE_LABELS[targetMode]}{selectedAgents.length === 1 ? " • 1 agent selected" : ` • ${selectedAgents.length} agents selected`}
          </div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Connected Agents</div>
          <div className="mission-value">{connectedAgentCount}</div>
          <div className="mission-meta">{agents.length} agents loaded from inventory</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Execution Feed</div>
          <div className="mission-value">{activeExecutionId ? `#${activeExecutionId}` : "-"}</div>
          <div className="mission-meta">{activeExecutionId ? "Live output stream attached" : "No active action stream"}</div>
        </div>
      </div>

      <div className="actions-workspace" style={{ "--actions-sidebar-width": `${sidebarWidth}px` }}>
        <div className="actions-sidebar-pane" data-tour-id="action-catalog">
          <div className="card actions-targeting-card">
            <div className="card-header">
              <div>
                <h3>Target Selection</h3>
                <p className="muted">Use fleet, multi, single, or group targeting before choosing and dispatching actions.</p>
              </div>
            </div>

            <div className="actions-field-block">
              <label className="actions-field-label">Target Scope</label>
              <select
                className="input"
                value={targetMode}
                onChange={(event) => setTargetMode(event.target.value)}
              >
                <option value="fleet">Fleet (all connected agents)</option>
                <option value="multi">Multiple agents</option>
                <option value="agent">Single agent</option>
                <option value="group">Specific group</option>
              </select>
            </div>

            {targetMode === "multi" ? (
              <div className="actions-field-block">
                <label className="actions-field-label">Pick Agents</label>
                <div className="page-actions">
                  <select
                    className="input"
                    value={multiPickAgentId}
                    onChange={(event) => setMultiPickAgentId(formatAgentId(event.target.value))}
                  >
                    <option value="">Select connected agent</option>
                    {connectedAgents.map((agent) => (
                      <option key={`multi-target-${agent.id}`} value={agent.id}>
                        {agent.id} - {agent.hostname}{agent.groupText ? ` (${agent.groupText})` : ""}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="btn secondary"
                    onClick={() => {
                      if (!multiPickAgentId) return;
                      setTargetAgentIds((current) => {
                        const ids = new Set(current.map((id) => formatAgentId(id)).filter(Boolean));
                        ids.add(multiPickAgentId);
                        return Array.from(ids);
                      });
                    }}
                    disabled={!multiPickAgentId}
                  >
                    Add
                  </button>
                  <button
                    type="button"
                    className="btn secondary"
                    onClick={() => setTargetAgentIds(connectedAgents.map((agent) => agent.id))}
                    disabled={!connectedAgents.length}
                  >
                    All
                  </button>
                  <button
                    type="button"
                    className="btn secondary"
                    onClick={() => setTargetAgentIds([])}
                    disabled={!targetAgentIds.length}
                  >
                    Clear
                  </button>
                </div>
              </div>
            ) : null}

            {targetMode === "agent" ? (
              <div className="actions-field-block">
                <label className="actions-field-label">Single Agent</label>
                <select className="input" value={singleTargetId} onChange={(event) => setSingleTargetId(event.target.value)}>
                  <option value="">Select agent</option>
                  {connectedAgents.map((agent) => (
                    <option key={`single-target-${agent.id}`} value={agent.id}>
                      {agent.id} - {agent.hostname}{agent.groupText ? ` (${agent.groupText})` : ""}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            {targetMode === "group" ? (
              <div className="actions-field-block">
                <label className="actions-field-label">Target Group</label>
                <select className="input" value={groupTarget} onChange={(event) => setGroupTarget(event.target.value)}>
                  <option value="">Select group</option>
                  {availableGroups.map((group) => (
                    <option key={`group-target-${group}`} value={group}>{group}</option>
                  ))}
                </select>
              </div>
            ) : null}

            {targetMode === "multi" ? (
              <div className="actions-selection-strip">
                {selectedMultiAgents.length ? selectedMultiAgents.map((agent) => (
                  <span key={`selected-multi-${agent.id}`} className="chip">
                    <MaskedAgentId value={agent.id} />
                    <span>{agent.hostname}</span>
                    <button type="button" className="panel-collapse-btn" onClick={() => handleToggleAgent(agent.id)} aria-label={`Remove ${agent.hostname}`}>
                      x
                    </button>
                  </span>
                )) : <div className="meta-line">No agents selected yet.</div>}
              </div>
            ) : (
              <div className="meta-line">{TARGET_MODE_LABELS[targetMode]} resolves to {resolvedTargetIds.length} target(s).</div>
            )}

            <div className="meta-line">
              {scopedTargets.length
                ? `Resolved target preview hidden to keep the workspace focused. ${scopedTargets.length} target(s) will be used for execution.`
                : "No agents match the current target scope."}
            </div>
          </div>

          <div className="card actions-catalog-card">
            <div className="card-header">
              <div>
                <h3>Action Catalog</h3>
                <p className="muted">Browse remediation and containment actions without leaving the workspace.</p>
              </div>
              <span className="chip">{filteredActions.length} / {actions.length} visible</span>
            </div>
            <div className="page-actions actions-catalog-toolbar">
              <input
                className="input"
                value={actionSearch}
                onChange={(event) => setActionSearch(event.target.value)}
                placeholder="Search action name, id, category, or description..."
              />
              <select className="input" value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}>
                <option value="">All categories</option>
                {actionCategories.map((category) => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </select>
              <button
                type="button"
                className="btn secondary"
                onClick={() => {
                  setActionSearch("");
                  setCategoryFilter("");
                }}
                disabled={!actionSearch.trim() && !categoryFilter}
              >
                Clear Filters
              </button>
            </div>
            <div className="actions-catalog-summary">
              <div className="actions-catalog-stat">
                <span>Total</span>
                <strong>{actions.length}</strong>
              </div>
              <div className="actions-catalog-stat">
                <span>Filtered</span>
                <strong>{filteredActions.length}</strong>
              </div>
              <div className="actions-catalog-stat">
                <span>Category</span>
                <strong>{categoryFilter || "All"}</strong>
              </div>
            </div>
            {selectedCatalogAction ? (
              <div className="actions-catalog-selected">
                <div className="actions-catalog-selected-title">{actionLabel(selectedCatalogAction)}</div>
                <div className="actions-catalog-selected-meta">
                  <span>{String(selectedCatalogAction?.id || "-")}</span>
                  <span>{actionRequiredInputCount(selectedCatalogAction)} required input(s)</span>
                  <span className={`actions-catalog-risk ${actionRiskTone(selectedCatalogAction)}`}>
                    {actionRiskLabel(selectedCatalogAction)}
                  </span>
                </div>
              </div>
            ) : null}
            <div className="meta-line">Drag the divider to resize the catalog panel.</div>
            <div className="actions-catalog-scroll">
              {filteredActions.length ? (
                <div className="actions-catalog-list">
                  {filteredActions.map((action) => {
                    const selected = String(action?.id || "") === String(actionId);
                    return (
                      <button
                        key={String(action?.id || actionLabel(action))}
                        type="button"
                        className={`actions-catalog-item${selected ? " selected" : ""}`}
                        onClick={() => handleActionSelect(action)}
                      >
                        <div className="actions-catalog-item-head">
                          <div className="actions-catalog-item-title">{actionLabel(action)}</div>
                          <span className="chip actions-catalog-item-chip">
                            {actionInputCount(action)} input{actionInputCount(action) === 1 ? "" : "s"}
                          </span>
                        </div>
                        <div className="actions-catalog-item-desc">{toDisplay(action?.description, "No description available.")}</div>
                        <div className="actions-catalog-item-meta">
                          <span className="actions-catalog-item-category">{actionCategory(action)}</span>
                          <span className={`actions-catalog-risk ${actionRiskTone(action)}`}>{actionRiskLabel(action)}</span>
                          <code>{String(action?.id || "-")}</code>
                        </div>
                      </button>
                    );
                  })}
                </div>
              ) : (
                <div className="empty-state">No actions match the current filters.</div>
              )}
            </div>
          </div>
        </div>

        <div className="actions-workspace-divider" aria-hidden="true">
          <button type="button" className="actions-workspace-divider-handle" onMouseDown={startResize} onDoubleClick={() => setSidebarWidth(DEFAULT_ACTIONS_SIDEBAR_WIDTH)} title="Drag to resize the action catalog. Double-click to reset." />
        </div>

        <div className="actions-main-pane">
          <div className="actions-console-grid">
            <div ref={executionPlanRef} className="card">
              <div className="card-header">
                <div>
                  <h3>Execution Plan</h3>
                  <p className="muted">Review the selected action, preserve raw input text, and dispatch once the plan is ready.</p>
                </div>
              </div>

              {selectedAction ? (
                <>
                  <div className="actions-detail-grid">
                    <div className="list-item readable">
                      <div className="mission-label">Action</div>
                      <div className="actions-row-name">{actionLabel(selectedAction)}</div>
                      <div className="meta-line">{toDisplay(selectedAction?.description, "No description provided.")}</div>
                    </div>
                    <div className="list-item readable">
                      <div className="mission-label">Category</div>
                      <div className="actions-row-name">{actionCategory(selectedAction)}</div>
                      <div className="meta-line">Action ID: {String(selectedAction?.id || "-")}</div>
                    </div>
                    <div className="list-item readable">
                      <div className="mission-label">Targets</div>
                      <div className="actions-row-name">{resolvedTargetIds.length}</div>
                      <div className="meta-line">{resolvedTargetIds.length ? `${resolvedTargetIds.length} agents queued for dispatch.` : "Select target agents before dispatch."}</div>
                    </div>
                  </div>

                  <div className="actions-field-grid">
                    {actionInputsList.map((field) => {
                      const name = String(field.name || "").trim();
                      const multiline = Boolean(field.multiline) || MULTILINE_INPUT_FIELDS.has(name.toLowerCase());
                      const value = String(actionInputs?.[name] ?? "");
                      return (
                        <div key={name} className="actions-field-block">
                          <label className="actions-field-label">{inputLabel(field)}{field.required ? " *" : ""}</label>
                          {multiline ? (
                            <textarea className="input" placeholder={inputPlaceholder(field)} value={value} onChange={(event) => handleActionInputChange(name, event.target.value)} disabled={isActionRunning} />
                          ) : (
                            <input className="input" type="text" placeholder={inputPlaceholder(field)} value={value} onChange={(event) => handleActionInputChange(name, event.target.value)} disabled={isActionRunning} />
                          )}
                          {inputPlaceholder(field) ? <div className="meta-line">{inputPlaceholder(field)}</div> : null}
                        </div>
                      );
                    })}
                  </div>

                  <div className="actions-field-block">
                    <label className="actions-field-label">Justification</label>
                    <textarea className="input" placeholder="State why this action is being executed." value={justification} onChange={(event) => setJustification(event.target.value)} disabled={isActionRunning} />
                    <div className="meta-line">Optional. If left blank, a default justification is attached automatically. Sidebar and panel resizing do not clear this field.</div>
                  </div>
                </>
              ) : (
                <div className="empty-state">No action selected. Pick an action from the catalog to build the execution plan.</div>
              )}
            </div>
          </div>

          <div className="actions-docs-grid">
            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Command Guardrails</h3>
                  <p className="muted">Keep the payload exact and visible before dispatch.</p>
                </div>
              </div>
              <div className="actions-help-list">
                {actionHints.map((hint, index) => (
                  <div key={`${index}-${hint}`} className="actions-help-item">{hint}</div>
                ))}
              </div>
              <div className="mission-label">Payload Preview</div>
              <details className="ticketing-detail-section" open>
                <summary>View Technical Payload</summary>
                <pre className="code-block">{payloadPreview || "Select an action to generate the request payload preview."}</pre>
              </details>
              <div className="actions-run-footer">
                {actionStatus ? (
                  <div className={`actions-inline-status ${actionStatusTone}`}>{actionStatus}</div>
                ) : (
                  <div className="meta-line">Review the plan and payload, then dispatch.</div>
                )}
                <button type="button" className="btn" onClick={() => void handleExecuteAction()} disabled={!canExecute}>
                  {isActionRunning ? "Running..." : "Run Command"}
                </button>
              </div>
            </div>
          </div>

          {activeExecutionId ? (
            <div className="card actions-execution-card">
              <div className="card-header">
                <div>
                  <h3>Live Execution Stream</h3>
                  <p className="muted">Monitor stdout, stderr, per-target progress, and recovery actions without leaving the workspace.</p>
                </div>
                <span className="status-pill pending">Execution #{activeExecutionId}</span>
              </div>
              <details className="ticketing-detail-section" open>
                <summary>View Execution Logs</summary>
                <ExecutionStream executionId={activeExecutionId} />
              </details>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}


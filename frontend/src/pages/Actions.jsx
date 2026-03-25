import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ExecutionStream from "../components/ExecutionStream";
import { getActions, getAgents, getActionConnectorStatus, runAction } from "../api/wazuh";
import { formatApiError } from "../utils/httpErrors";

const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);
const ACTIONS_SIDEBAR_WIDTH_STORAGE_KEY = "c2f-actions-sidebar-width-v3";
const DEFAULT_ACTIONS_SIDEBAR_WIDTH = 360;
const MIN_ACTIONS_SIDEBAR_WIDTH = 300;
const MAX_ACTIONS_SIDEBAR_WIDTH = 520;

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

const isAgentConnected = (status) => {
  const value = String(status || "").trim().toLowerCase();
  return value.includes("active") || value.includes("connected") || value.includes("online");
};

const formatLatency = (value) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? `${numeric} ms` : "-";
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

const connectorSummary = (status, error) => {
  if (status?.status) {
    const label = String(status.status).replace(/[_-]+/g, " ").trim();
    return label ? label.replace(/\b\w/g, (part) => part.toUpperCase()) : "Connected";
  }
  if (error) return "Degraded";
  return "Checking";
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
  const [actions, setActions] = useState([]);
  const [actionSearch, setActionSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [actionId, setActionId] = useState("");
  const [actionInputs, setActionInputs] = useState({});
  const [actionStatus, setActionStatus] = useState("");
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [justification, setJustification] = useState("");
  const [agents, setAgents] = useState([]);
  const [targetSearch, setTargetSearch] = useState("");
  const [targetStatusFilter, setTargetStatusFilter] = useState("all");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [connectorStatus, setConnectorStatus] = useState(null);
  const [connectorError, setConnectorError] = useState("");
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

  const selectedAgents = useMemo(
    () => targetAgentIds.map((agentId) => agents.find((agent) => agent.id === agentId)).filter(Boolean),
    [agents, targetAgentIds]
  );

  const filteredAgents = useMemo(() => {
    const query = targetSearch.trim().toLowerCase();
    const selectedIds = new Set(targetAgentIds);
    return [...agents]
      .filter((agent) => {
        if (targetStatusFilter === "connected" && !isAgentConnected(agent.status)) return false;
        if (targetStatusFilter === "disconnected" && isAgentConnected(agent.status)) return false;
        if (!query) return true;
        const haystack = [agent.id, agent.hostname, agent.os, agent.status].join(" ").toLowerCase();
        return haystack.includes(query);
      })
      .sort((left, right) => {
        const leftSelected = selectedIds.has(left.id);
        const rightSelected = selectedIds.has(right.id);
        if (leftSelected !== rightSelected) return leftSelected ? -1 : 1;
        const leftConnected = isAgentConnected(left.status);
        const rightConnected = isAgentConnected(right.status);
        if (leftConnected !== rightConnected) return leftConnected ? -1 : 1;
        return `${left.hostname} ${left.id}`.localeCompare(`${right.hostname} ${right.id}`);
      });
  }, [agents, targetAgentIds, targetSearch, targetStatusFilter]);

  const actionInputsList = useMemo(
    () => Array.isArray(selectedAction?.inputs) ? selectedAction.inputs.filter((field) => field && typeof field === "object" && field.name) : [],
    [selectedAction]
  );

  const actionHints = useMemo(() => buildActionHints(selectedAction), [selectedAction]);
  const connectedAgentCount = useMemo(() => agents.filter((agent) => isAgentConnected(agent.status)).length, [agents]);

  const payloadPreview = useMemo(() => {
    if (!selectedAction) return "";
    return JSON.stringify(
      {
        agent_ids: targetAgentIds,
        action_id: actionId,
        args: compactArgs(actionInputs),
        justification: justification.trim(),
      },
      null,
      2
    );
  }, [selectedAction, targetAgentIds, actionId, actionInputs, justification]);

  const connectorLabel = connectorSummary(connectorStatus, connectorError);
  const connectorTone = statusToneFromText(connectorStatus?.status || connectorError || connectorLabel);
  const actionStatusTone = statusToneFromText(actionStatus);
  const missingRequiredInput = actionInputsList.some((field) => field.required && !String(actionInputs?.[field.name] ?? "").trim());
  const canExecute = Boolean(selectedAction) && targetAgentIds.length > 0 && Boolean(justification.trim()) && !missingRequiredInput && !isActionRunning;

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
          return {
            id,
            name: hostname,
            hostname,
            status: toDisplay(agent?.status, "unknown"),
            os: toDisplay(agent?.os?.name || agent?.os || agent?.platform, "-"),
            latency: Number(agent?.latency_ms || agent?.latency || agent?.ping || 0) || 0,
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
    setTargetAgentIds((current) => current.filter((id) => agents.some((agent) => agent.id === id)));
  }, [agents]);

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
    if (!selectedAction || targetAgentIds.length === 0) {
      setActionStatus("Select an action and at least one target agent.");
      return;
    }
    if (!justification.trim()) {
      setActionStatus("Provide justification before running the action.");
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
        agent_ids: targetAgentIds,
        action_id: actionId,
        args: compactArgs(actionInputs),
        justification: justification.trim(),
      });
      const executionId = response?.data?.execution_id;
      setActiveExecutionId(executionId || null);
      setActionStatus(executionId ? `Action submitted as execution #${executionId}.` : "Action submitted.");
    } catch (error) {
      setActionStatus(formatApiError(error, "Action execution failed."));
    } finally {
      setIsActionRunning(false);
    }
  }, [selectedAction, targetAgentIds, justification, missingRequiredInput, isActionRunning, actionId, actionInputs]);

  const selectVisibleAgents = useCallback(() => {
    setTargetAgentIds((current) => {
      const merged = new Set(current);
      filteredAgents.forEach((agent) => merged.add(agent.id));
      return Array.from(merged);
    });
  }, [filteredAgents]);

  const clearSelectedAgents = useCallback(() => {
    setTargetAgentIds([]);
  }, []);

  return (
    <div className="page actions-page page-route-actions">
      <div className="page-header">
        <div>
          <h2>Actions Workspace</h2>
          <p className="muted">Select a response action, target the right agents, and dispatch without leaving the console shell.</p>
        </div>
        <div className="page-actions">
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
          <div className="mission-value">{targetAgentIds.length}</div>
          <div className="mission-meta">{selectedAgents.length === 1 ? "1 agent selected" : `${selectedAgents.length} agents selected`}</div>
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
        <div className="card actions-sidebar-pane" data-tour-id="action-catalog">
          <div className="card-header">
            <div>
              <h3>Action Catalog</h3>
              <p className="muted">Browse remediation and containment actions without leaving the workspace.</p>
            </div>
          </div>
          <div className="page-actions">
            <input className="input" value={actionSearch} onChange={(event) => setActionSearch(event.target.value)} placeholder="Search action name, id, category, or description..." />
            <select className="input" value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}>
              <option value="">All categories</option>
              {actionCategories.map((category) => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
          </div>
          <div className="meta-line">{filteredActions.length} visible actions. Drag the divider to resize the catalog.</div>
          <div className="table-scroll actions-catalog-scroll">
            <table className="table compact readable actions-catalog-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Category</th>
                  <th>ID</th>
                </tr>
              </thead>
              <tbody>
                {filteredActions.length ? filteredActions.map((action) => {
                  const selected = String(action?.id || "") === String(actionId);
                  return (
                    <tr key={action.id} className={`clickable${selected ? " selected" : ""}`} onClick={() => handleActionSelect(action)}>
                      <td>
                        <div className="actions-row-name">{actionLabel(action)}</div>
                        <div className="meta-line">{toDisplay(action?.description, "No description available.")}</div>
                      </td>
                      <td>{actionCategory(action)}</td>
                      <td><code>{String(action?.id || "-")}</code></td>
                    </tr>
                  );
                }) : (
                  <tr>
                    <td colSpan={3}><div className="empty-state">No actions match the current filters.</div></td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="actions-workspace-divider" aria-hidden="true">
          <button type="button" className="actions-workspace-divider-handle" onMouseDown={startResize} onDoubleClick={() => setSidebarWidth(DEFAULT_ACTIONS_SIDEBAR_WIDTH)} title="Drag to resize the action catalog. Double-click to reset." />
        </div>

        <div className="actions-main-pane">
          <div className="actions-console-grid">
            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Target Selection</h3>
                  <p className="muted">Filter agents, select the exact endpoint set, and keep the target list visible while triaging.</p>
                </div>
                <div className="page-actions">
                  <button type="button" className="btn secondary" onClick={selectVisibleAgents}>Select Visible</button>
                  <button type="button" className="btn secondary" onClick={clearSelectedAgents}>Clear Selection</button>
                </div>
              </div>

              <div className="page-actions">
                <input className="input" value={targetSearch} onChange={(event) => setTargetSearch(event.target.value)} placeholder="Search agent id, hostname, OS, or status..." />
                <select className="input" value={targetStatusFilter} onChange={(event) => setTargetStatusFilter(event.target.value)}>
                  <option value="all">All statuses</option>
                  <option value="connected">Connected only</option>
                  <option value="disconnected">Disconnected only</option>
                </select>
              </div>

              <div className="actions-selection-strip">
                {selectedAgents.length ? selectedAgents.map((agent) => (
                  <span key={agent.id} className="selection-chip" data-agent-id={agent.id}>
                    <MaskedAgentId value={agent.id} />
                    <span>{agent.hostname}</span>
                    <button type="button" className="actions-chip-dismiss" onClick={() => handleToggleAgent(agent.id)} aria-label={`Remove agent ${agent.hostname}`}>x</button>
                  </span>
                )) : <div className="meta-line">No target agents selected yet.</div>}
              </div>

              <div className="table-scroll actions-target-scroll">
                <table className="table compact readable actions-target-table">
                  <thead>
                    <tr>
                      <th>Pick</th>
                      <th>Agent ID</th>
                      <th>Host</th>
                      <th>Status</th>
                      <th>OS</th>
                      <th>Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAgents.length ? filteredAgents.map((agent) => {
                      const selected = targetAgentIds.includes(agent.id);
                      const connected = isAgentConnected(agent.status);
                      return (
                        <tr key={agent.id} className={`clickable${selected ? " selected" : ""}`} onClick={() => handleToggleAgent(agent.id)} data-agent-id={agent.id}>
                          <td>
                            <input className="actions-table-checkbox" type="checkbox" checked={selected} onChange={() => handleToggleAgent(agent.id)} onClick={(event) => event.stopPropagation()} aria-label={`Select agent ${agent.hostname}`} />
                          </td>
                          <td><MaskedAgentId value={agent.id} /></td>
                          <td>
                            <div className="actions-row-name">{agent.hostname}</div>
                            <div className="meta-line">{agent.name}</div>
                          </td>
                          <td><span className={`status-pill ${connected ? "success" : "failed"}`}>{connected ? "Connected" : toDisplay(agent.status, "Unknown")}</span></td>
                          <td>{agent.os}</td>
                          <td>{formatLatency(agent.latency)}</td>
                        </tr>
                      );
                    }) : (
                      <tr>
                        <td colSpan={6}><div className="empty-state">No agents match the current target filters.</div></td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Execution Plan</h3>
                  <p className="muted">Review the selected action, preserve raw input text, and dispatch once the plan is ready.</p>
                </div>
                <div className="page-actions">
                  <button type="button" className="btn" onClick={() => void handleExecuteAction()} disabled={!canExecute}>
                    {isActionRunning ? "Running..." : "Run Action"}
                  </button>
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
                      <div className="actions-row-name">{targetAgentIds.length}</div>
                      <div className="meta-line">{targetAgentIds.length ? `${targetAgentIds.length} agents queued for dispatch.` : "Select target agents before dispatch."}</div>
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
                    <label className="actions-field-label">Justification *</label>
                    <textarea className="input" placeholder="State why this action is being executed." value={justification} onChange={(event) => setJustification(event.target.value)} disabled={isActionRunning} />
                    <div className="meta-line">Sidebar and panel resizing do not clear this field. Raw text is preserved until you change the action or refresh the page.</div>
                  </div>

                  {actionStatus ? <div className={`actions-inline-status ${actionStatusTone}`}>{actionStatus}</div> : null}
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
              <pre className="code-block">{payloadPreview || "Select an action to generate the request payload preview."}</pre>
            </div>

            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Connector Health</h3>
                  <p className="muted">The workspace stays operational even when connector status is still being resolved.</p>
                </div>
              </div>
              <div className="actions-help-list">
                <div className="list-item split readable">
                  <div className="stack-col gap-6">
                    <div className="mission-label">Connector State</div>
                    <div className="actions-row-name">{connectorLabel}</div>
                    <div className="meta-line">{connectorError || toDisplay(connectorStatus?.message || connectorStatus?.detail, "Status loaded from the connector health endpoint.")}</div>
                  </div>
                  <span className={`status-pill ${connectorTone}`}>{connectorLabel}</span>
                </div>
                <div className="list-item readable">
                  <div className="mission-label">Workspace Notes</div>
                  <div className="meta-line">All tables expand fluidly with the shell. No fixed-position search bars or page-local shell chrome are used here anymore.</div>
                </div>
                <div className="list-item readable">
                  <div className="mission-label">Execution Routing</div>
                  <div className="meta-line">Dispatch continues to use the existing backend API contract with <code>agent_ids</code>, <code>action_id</code>, <code>args</code>, and <code>justification</code>.</div>
                </div>
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
              <ExecutionStream executionId={activeExecutionId} />
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}


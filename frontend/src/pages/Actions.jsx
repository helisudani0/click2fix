import { useCallback, useEffect, useMemo, useState } from "react";
import ExecutionStream from "../components/ExecutionStream";
import {
  getActions,
  getAgents,
  getAgentGroups,
  getActionConnectorStatus,
  requestApproval,
  runAction,
  testActionCapability,
  validateAction,
} from "../api/wazuh";

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
  const str = String(raw);
  return /^[0-9]+$/.test(str) && str.length < 3 ? str.padStart(3, "0") : str;
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
  Object.entries(value).forEach(([key, v]) => {
    if (v === null || v === undefined) return;
    if (typeof v === "string" && v.trim() === "") return;
    out[key] = v;
  });
  return out;
};

const riskClass = (risk) => {
  const value = String(risk || "").toLowerCase();
  if (value.includes("critical") || value.includes("high")) return "failed";
  if (value.includes("medium")) return "pending";
  if (value.includes("low")) return "success";
  return "neutral";
};

const SPECIFIC_SOFTWARE_ACTION_ID = "software-install-upgrade";
const CUSTOM_OS_COMMAND_ACTION_ID = "custom-os-command";
const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);

export default function Actions() {
  const [actions, setActions] = useState([]);
  const [actionsLoading, setActionsLoading] = useState(true);
  const [actionSearch, setActionSearch] = useState("");
  const [actionId, setActionId] = useState("");
  const [actionInputs, setActionInputs] = useState({});
  const [actionValidation, setActionValidation] = useState(null);
  const [actionStatus, setActionStatus] = useState("");
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [justification, setJustification] = useState("");

  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [targetMode, setTargetMode] = useState("agent");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [targetSearch, setTargetSearch] = useState("");
  const [excludeAgents, setExcludeAgents] = useState("");

  const [connectorStatus, setConnectorStatus] = useState(null);
  const [connectorError, setConnectorError] = useState("");
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [matrixLoading, setMatrixLoading] = useState(false);
  const [matrixRows, setMatrixRows] = useState([]);

  const selectedAction = useMemo(
    () => actions.find((a) => a.id === actionId) || null,
    [actions, actionId]
  );

  const loadActions = useCallback(async () => {
    setActionsLoading(true);
    try {
      const res = await getActions();
      setActions(res.data || []);
    } catch {
      setActions([]);
    } finally {
      setActionsLoading(false);
    }
  }, []);

  const loadAgents = useCallback(async () => {
    try {
      const res = await getAgents(undefined, { limit: 5000 });
      const list = normalizeAgents(res.data).map((a) => {
        const id = formatAgentId(a.id || a.agent_id || "");
        const name = toDisplay(a.name || a.hostname || id || "-");
        const group = toDisplay(a.group || a.group_name || (Array.isArray(a.groups) ? a.groups.join(", ") : ""), "-");
        const status = toDisplay(a.status, "unknown");
        return { id, name, group, status };
      });
      setAgents(list.filter((a) => a.id));
    } catch {
      setAgents([]);
    }
  }, []);

  const loadGroups = useCallback(async () => {
    try {
      const res = await getAgentGroups();
      setGroups(res.data || []);
    } catch {
      setGroups([]);
    }
  }, []);

  const loadConnectorStatus = useCallback(async () => {
    try {
      const res = await getActionConnectorStatus();
      setConnectorStatus(res.data);
      setConnectorError("");
    } catch (err) {
      setConnectorStatus(null);
      setConnectorError(err.response?.data?.detail || err.message || "Connector status unavailable");
    }
  }, []);

  useEffect(() => {
    loadActions();
    loadAgents();
    loadGroups();
    loadConnectorStatus();
  }, [loadActions, loadAgents, loadGroups, loadConnectorStatus]);

  const filteredActions = useMemo(() => {
    const q = actionSearch.trim().toLowerCase();
    if (!q) return actions;
    return actions.filter((a) => {
      const label = String(a.label || a.id || "").toLowerCase();
      const id = String(a.id || "").toLowerCase();
      const cat = String(a.category || "").toLowerCase();
      return label.includes(q) || id.includes(q) || cat.includes(q);
    });
  }, [actions, actionSearch]);

  const targetPickList = useMemo(() => {
    const q = targetSearch.trim().toLowerCase();
    const base = agents;
    if (!q) return base.slice(0, 60);
    return base
      .filter((a) => a.id.includes(q) || a.name.toLowerCase().includes(q) || a.group.toLowerCase().includes(q))
      .slice(0, 60);
  }, [agents, targetSearch]);

  const resolveTarget = () => {
    if (targetMode === "fleet") return { agent_id: "all" };
    if (targetMode === "group") return { group: (targetValue || "").trim() };
    if (targetMode === "multi") return { agent_ids: targetAgentIds };
    return { agent_id: (targetValue || "").trim() };
  };

  const buildSampleArgs = (action) => {
    const args = {};
    const inputs = Array.isArray(action?.inputs) ? action.inputs : [];
    inputs.forEach((field) => {
      if (!field || typeof field !== "object") return;
      const name = String(field.name || "").trim();
      if (!name) return;
      if (field.default !== undefined && field.default !== null && String(field.default) !== "") {
        args[name] = String(field.default);
        return;
      }
      const lname = name.toLowerCase();
      if (lname.includes("ip")) args[name] = "1.2.3.4";
      else if (lname.includes("pid")) args[name] = "1234";
      else if (lname.includes("path")) args[name] = "C:\\\\Temp\\\\suspect.exe";
      else if (lname.includes("service")) args[name] = "WazuhSvc";
      else if (lname.includes("user") || lname.includes("account")) args[name] = "test-user";
      else if (lname.includes("kb")) args[name] = "5001716";
      else if (lname.includes("package")) args[name] = "Git.Git";
      else if (lname.includes("command")) args[name] = "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion";
      else if (lname.includes("sha") || lname.includes("hash")) args[name] = "0123456789abcdef";
      else args[name] = "test";
    });
    return args;
  };

  const validateAllActionsForTarget = async () => {
    const target = resolveTarget();
    const hasTarget =
      Boolean(target.agent_id) ||
      Boolean(target.group) ||
      (Array.isArray(target.agent_ids) && target.agent_ids.length > 0);
    if (!hasTarget) {
      setActionStatus("Select a target before running matrix validation.");
      return;
    }
    if (!actions.length) {
      setActionStatus("No actions loaded.");
      return;
    }
    setMatrixLoading(true);
    setMatrixRows([]);
    setActionStatus("Validating action matrix...");
    const rows = [];
    for (const action of actions) {
      const aid = action?.id;
      if (!aid) continue;
      try {
        const res = await validateAction({
          ...target,
          action_id: aid,
          args: buildSampleArgs(action),
        });
        rows.push({
          id: aid,
          label: action?.label || aid,
          ok: Boolean(res?.data?.is_valid),
          channel: res?.data?.preferred_channel || res?.data?.preferred || "-",
          os: res?.data?.agent_os || "-",
          errors: Array.isArray(res?.data?.errors) ? res.data.errors.join(", ") : "",
        });
      } catch (err) {
        rows.push({
          id: aid,
          label: action?.label || aid,
          ok: false,
          channel: "-",
          os: "-",
          errors: err.response?.data?.detail || err.message || "Validation failed",
        });
      }
    }
    setMatrixRows(rows);
    setActionStatus(`Matrix validation complete: ${rows.filter((r) => r.ok).length}/${rows.length} valid.`);
    setMatrixLoading(false);
  };

  const validateConnector = async () => {
    try {
      const target = resolveTarget();
      const res = await testActionCapability({ ...target, action_id: "endpoint-healthcheck" });
      const mode = res?.data?.execution_mode || res?.data?.preferred_channel || "endpoint";
      const total = res?.data?.execution_result?.total || (Array.isArray(target.agent_ids) ? target.agent_ids.length : 1);
      setActionStatus(`Connector test passed in ${mode} mode for ${total || 1} target(s).`);
    } catch (err) {
      setActionStatus(err.response?.data?.detail || err.message || "Connector validation failed.");
    }
  };

  const testActionWorkflow = async () => {
    if (!actionId) {
      setActionStatus("Select an action.");
      return;
    }
    try {
      const target = resolveTarget();
      const res = await testActionCapability({
        ...target,
        action_id: actionId,
        args: compactArgs(actionInputs),
      });
      setActionStatus(res?.data?.message || "Action test completed.");
    } catch (err) {
      setActionStatus(err.response?.data?.detail || err.message || "Action test failed.");
    }
  };

  const requestActionApproval = async () => {
    if (!actionId) {
      setActionStatus("Select an action.");
      return;
    }
    const target = resolveTarget();
    const hasTarget =
      Boolean(target.agent_id) ||
      Boolean(target.group) ||
      (Array.isArray(target.agent_ids) && target.agent_ids.length > 0);
    if (!hasTarget) {
      setActionStatus("Select a target.");
      return;
    }
    try {
      await requestApproval({
        ...target,
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
        justification: justification || undefined,
      });
      setActionStatus("Approval request submitted.");
    } catch (err) {
      setActionStatus(err.response?.data?.detail || err.message || "Approval request failed.");
    }
  };

  const runSelectedAction = async () => {
    if (!actionId) {
      setActionStatus("Select an action.");
      return;
    }
    if (isActionRunning) {
      setActionStatus("Action is already running. Please wait for completion.");
      return;
    }
    const target = resolveTarget();
    const hasTarget =
      Boolean(target.agent_id) ||
      Boolean(target.group) ||
      (Array.isArray(target.agent_ids) && target.agent_ids.length > 0);
    if (!hasTarget) {
      setActionStatus("Select a target.");
      return;
    }

    try {
      const validationResponse = await validateAction({
        ...target,
        action_id: actionId,
        args: compactArgs(actionInputs),
      });
      setActionValidation(validationResponse.data);
      if (!validationResponse.data.is_valid) {
        setActionStatus(`Validation failed: ${validationResponse.data.errors.join(", ")}`);
        return;
      }
    } catch (err) {
      setActionStatus(`Validation error: ${err.response?.data?.detail || err.message}`);
      return;
    }

    setIsActionRunning(true);
    setActionStatus("Action execution in progress...");
    setActiveExecutionId(null);
    try {
      const res = await runAction({
        ...target,
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
        justification: justification || undefined,
      });
      const executionId = res?.data?.execution_id;
      setActiveExecutionId(executionId || null);
      setActionStatus(
        executionId
          ? `Action submitted (run #${executionId}).`
          : "Action submitted."
      );
    } catch (err) {
      setActionStatus(err.response?.data?.detail || err.message || "Action execution failed.");
    } finally {
      setIsActionRunning(false);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Actions</h2>
          <p className="muted">
            Run and monitor response actions across single endpoints, groups, or the entire fleet.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={() => {
            loadActions();
            loadConnectorStatus();
          }}>
            Refresh Catalog
          </button>
          <button className="btn secondary" onClick={() => {
            loadAgents();
            loadGroups();
          }}>
            Refresh Targets
          </button>
        </div>
      </div>

      {actionStatus ? <div className="empty-state">{actionStatus}</div> : null}

      <div className="split-view">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Action Catalog</h3>
              <p className="muted">Search and select an action to execute.</p>
            </div>
          </div>
          <div className="page-actions">
            <input
              className="input"
              value={actionSearch}
              onChange={(e) => setActionSearch(e.target.value)}
              placeholder="Search actions"
            />
          </div>
          {actionsLoading ? (
            <div className="empty-state">Loading actions...</div>
          ) : filteredActions.length === 0 ? (
            <div className="empty-state">No actions found.</div>
          ) : (
            <div className="list-scroll tall">
              <div className="list">
                {filteredActions.map((a) => (
	                  <button
	                    key={a.id}
	                    type="button"
	                    className={`list-item clickable readable text-left ${a.id === actionId ? "selected" : ""}`}
	                    onClick={() => setActionId(a.id)}
	                  >
	                    <div className="flex-between">
	                      <strong>{toDisplay(a.label || a.id)}</strong>
	                      <div className="page-actions gap-6">
	                        <span className="chip">{toDisplay(a.category || "response")}</span>
	                        {String(a.id || "").trim().toLowerCase() === SPECIFIC_SOFTWARE_ACTION_ID ? (
	                          <span className="status-pill success">Recommended</span>
	                        ) : null}
	                      </div>
	                    </div>
	                    <div className="meta-line ws-normal">{a.id}</div>
	                    {a.description ? (
	                      <div className="meta-line ws-normal">{a.description}</div>
	                    ) : null}
	                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

	        <div className="stack-col gap-18">
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Execute Action</h3>
                <p className="muted">Targets, justification, and live execution details.</p>
              </div>
            </div>

            <div className="page-actions">
              <span className="chip">
                Mode: {toDisplay(connectorStatus?.orchestration_mode || "n/a")}
              </span>
              <span className="chip">
                WinRM: {connectorStatus?.connectors?.windows?.credentials_configured ? "configured" : "missing"}
              </span>
              <span className="chip">
                Linux: {connectorStatus?.connectors?.linux?.credentials_configured ? "configured" : "missing"}
              </span>
            </div>
	            {connectorError ? (
	              <div className="meta-line ws-normal">
	                Connector status error: {connectorError}
	              </div>
	            ) : null}

            <div className="list">
              <div className="list-item readable">
                <div className="muted">Targets</div>
	                <div className="page-actions mt-8">
	                  <select className="input" value={targetMode} onChange={(e) => setTargetMode(e.target.value)}>
                    <option value="agent">Single agent</option>
                    <option value="multi">Multiple agents</option>
                    <option value="group">Agent group</option>
                    <option value="fleet">Fleet (all)</option>
                  </select>
                </div>

                {targetMode === "multi" ? (
	                  <div className="mt-10">
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
	                    <div className="list-scroll mt-10 h-240">
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
                                      if (next) return prev.includes(agent.id) ? prev : [...prev, agent.id];
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
                ) : targetMode === "group" ? (
	                  <div className="page-actions mt-10">
                    <select className="input" value={targetValue} onChange={(e) => setTargetValue(e.target.value)}>
                      <option value="">Select group</option>
                      {groups.map((g) => (
                        <option key={g} value={g}>{g}</option>
                      ))}
                    </select>
                    <input
                      className="input"
                      value={excludeAgents}
                      onChange={(e) => setExcludeAgents(e.target.value)}
                      placeholder="Exclude agent IDs (comma separated)"
                    />
                  </div>
                ) : targetMode === "fleet" ? (
	                  <div className="page-actions mt-10">
                    <input
                      className="input"
                      value={excludeAgents}
                      onChange={(e) => setExcludeAgents(e.target.value)}
                      placeholder="Exclude agent IDs (comma separated)"
                    />
                  </div>
                ) : (
	                  <div className="page-actions mt-10">
                    <input
                      className="input"
                      value={targetValue}
                      onChange={(e) => setTargetValue(e.target.value)}
                      placeholder="Agent ID (example: 004)"
                      list="agentIds"
                    />
                    <datalist id="agentIds">
                      {agents.slice(0, 80).map((a) => (
                        <option key={`agent-${a.id}`} value={a.id}>
                          {a.name}
                        </option>
                      ))}
                    </datalist>
                  </div>
                )}
              </div>

              <div className="list-item readable">
                <div className="muted">Selected Action</div>
                {selectedAction ? (
                  <>
	                    <div className="mt-6">
	                      <strong>{toDisplay(selectedAction.label || selectedAction.id)}</strong>
	                    </div>
	                    <div className="meta-line ws-normal">{selectedAction.id}</div>
	                    {selectedAction.description ? (
	                      <div className="meta-line ws-normal">{selectedAction.description}</div>
	                    ) : null}
	                    {String(selectedAction.id || "").trim().toLowerCase() === SPECIFIC_SOFTWARE_ACTION_ID ? (
	                      <div className="empty-state mt-8">
	                        Recommended for software-specific vulnerability remediation on selected endpoints.
	                      </div>
	                    ) : null}
	                    {String(selectedAction.id || "").trim().toLowerCase() === CUSTOM_OS_COMMAND_ACTION_ID ? (
	                      <div className="empty-state mt-8">
	                        Emergency fallback. This runs exactly what you type on endpoints; validate command safety before execution.
	                      </div>
	                    ) : null}
	                    <div className="page-actions mt-8">
	                      <span className="chip">{toDisplay(selectedAction.category || "response")}</span>
                      <span className={`status-pill ${riskClass(selectedAction.risk)}`}>
                        {toDisplay(selectedAction.risk || "n/a")}
                      </span>
                      <span className="chip">
                        {selectedAction.custom ? "custom command" : "built-in command"}
                      </span>
                    </div>
                    {selectedAction.docs && typeof selectedAction.docs === "object" ? (
	                      <div className="mt-10">
	                        <div className="muted">Action Guide</div>
	                        {selectedAction.docs.what_it_does ? (
	                          <div className="mt-6">
	                            <strong>What it does:</strong> {String(selectedAction.docs.what_it_does)}
	                          </div>
	                        ) : null}
	                        {selectedAction.docs.when_to_use ? (
	                          <div className="mt-6">
	                            <strong>When to use:</strong> {String(selectedAction.docs.when_to_use)}
	                          </div>
	                        ) : null}
	                        {selectedAction.docs.impact ? (
	                          <div className="mt-6">
	                            <strong>Impact:</strong> {String(selectedAction.docs.impact)}
	                          </div>
	                        ) : null}
	                        {selectedAction.docs.rollback ? (
	                          <div className="mt-6">
	                            <strong>Rollback:</strong> {String(selectedAction.docs.rollback)}
	                          </div>
	                        ) : null}
	                        {selectedAction.docs.requirements ? (
	                          <div className="mt-6">
	                            <strong>Requirements:</strong> {String(selectedAction.docs.requirements)}
	                          </div>
	                        ) : null}
	                        {selectedAction.docs.examples ? (
	                          <div className="mt-6">
	                            <strong>Examples:</strong> {String(selectedAction.docs.examples)}
	                          </div>
	                        ) : null}
                      </div>
                    ) : null}
                  </>
                ) : (
	                  <div className="meta-line mt-6">
	                    Pick an action from the catalog.
	                  </div>
                )}
              </div>

              {(selectedAction?.inputs || []).map((field) => (
                <div key={field.name} className="list-item readable">
                  <div className="muted">{toDisplay(field.label || field.name)}</div>
                  {MULTILINE_INPUT_FIELDS.has(String(field.name || "").trim().toLowerCase()) ? (
                    <textarea
	                      className="input mt-8 mono"
	                      value={actionInputs[field.name] || ""}
                      onChange={(e) =>
                        setActionInputs((prev) => ({
                          ...prev,
                          [field.name]: e.target.value,
                        }))
                      }
                      placeholder={field.placeholder || ""}
	                      rows={4}
	                    />
	                  ) : (
	                    <input
	                      className="input mt-8"
	                      value={actionInputs[field.name] || ""}
                      onChange={(e) =>
                        setActionInputs((prev) => ({
                          ...prev,
                          [field.name]: e.target.value,
                        }))
                      }
	                      placeholder={field.placeholder || ""}
	                    />
	                  )}
                </div>
              ))}

              <div className="list-item readable">
                <div className="muted">Justification (if required)</div>
                <input
	                  className="input mt-8"
	                  value={justification}
	                  onChange={(e) => setJustification(e.target.value)}
	                  placeholder="Why is this response needed?"
	                />
              </div>

              {actionValidation ? (
                <div className="list-item readable">
                  <div className="muted">Validation Results</div>
	                  <div className="page-actions mt-8">
	                    <span className={`status-pill ${actionValidation.is_valid ? "success" : "failed"}`}>
                      {actionValidation.is_valid ? "Valid" : "Invalid"}
                    </span>
                    <span className="chip">OS: {actionValidation.agent_os}</span>
                    <span className="chip">Channel: {actionValidation.preferred_channel}</span>
                    <span className="chip">Timeout: {actionValidation.timeout_seconds}s</span>
                  </div>
                  {!actionValidation.is_valid ? (
	                    <div className="meta-line ws-normal mt-6">
	                      Errors: {(actionValidation.errors || []).join(", ")}
	                    </div>
	                  ) : null}
                </div>
              ) : null}

              <div className="page-actions">
                <button className="btn secondary" onClick={validateConnector}>
                  Validate Connector
                </button>
                <button className="btn secondary" onClick={validateAllActionsForTarget} disabled={matrixLoading}>
                  {matrixLoading ? "Validating..." : "Validate All"}
                </button>
                <button className="btn secondary" onClick={testActionWorkflow}>
                  Test Action
                </button>
                <button className="btn secondary" onClick={requestActionApproval}>
                  Request Approval
                </button>
                <button className="btn" onClick={runSelectedAction} disabled={isActionRunning}>
                  {isActionRunning ? "Running..." : "Run Action"}
                </button>
              </div>
            </div>
          </div>

          {activeExecutionId ? <ExecutionStream executionId={activeExecutionId} /> : null}

          {matrixRows.length ? (
            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Action Matrix</h3>
                  <p className="muted">Validation results for the selected target.</p>
                </div>
              </div>
	              <div className="table-scroll h-56vh">
                <table className="table compact readable">
                  <thead>
                    <tr>
                      <th>Action</th>
                      <th>Status</th>
                      <th>OS</th>
                      <th>Channel</th>
                      <th>Errors</th>
                    </tr>
                  </thead>
                  <tbody>
                    {matrixRows.map((row) => (
                      <tr key={`matrix-${row.id}`}>
                        <td>{row.label} ({row.id})</td>
                        <td>
                          <span className={`status-pill ${row.ok ? "success" : "failed"}`}>
                            {row.ok ? "VALID" : "INVALID"}
                          </span>
                        </td>
                        <td>{row.os}</td>
                        <td>{row.channel}</td>
                        <td>{row.errors || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

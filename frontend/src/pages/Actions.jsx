import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

const agentStatusClass = (status) => {
  const value = String(status || "").toLowerCase();
  if (value.includes("active") || value.includes("connected") || value.includes("online")) return "success";
  if (value.includes("pending") || value.includes("queue")) return "pending";
  return "failed";
};

const PACKAGE_UPDATE_ACTION_ID = "package-update";
const SPECIFIC_SOFTWARE_ACTION_ID = "software-install-upgrade";
const CUSTOM_OS_COMMAND_ACTION_ID = "custom-os-command";
const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);
const WINGET_BACKED_ACTION_IDS = new Set([PACKAGE_UPDATE_ACTION_ID, SPECIFIC_SOFTWARE_ACTION_ID]);
const ACTIONS_SIDEBAR_WIDTH_STORAGE_KEY = "c2f-actions-sidebar-width-v2";
const DEFAULT_ACTIONS_SIDEBAR_WIDTH = 380;
const MIN_ACTIONS_SIDEBAR_WIDTH = 300;
const MAX_ACTIONS_SIDEBAR_WIDTH = 620;
const PACKAGE_ID_EXAMPLES = [
  { id: "Microsoft.Edge", label: "Microsoft Edge" },
  { id: "Google.Chrome", label: "Google Chrome" },
  { id: "Mozilla.Firefox", label: "Mozilla Firefox" },
  { id: "Notepad++.Notepad++", label: "Notepad++" },
  { id: "7zip.7zip", label: "7-Zip" },
  { id: "Git.Git", label: "Git" },
];
const ACTION_SEARCH_PRIORITY = [
  PACKAGE_UPDATE_ACTION_ID,
  SPECIFIC_SOFTWARE_ACTION_ID,
  "endpoint-healthcheck",
  CUSTOM_OS_COMMAND_ACTION_ID,
];

const RAW_INPUT_PROPS = {
  spellCheck: false,
  autoCorrect: "off",
  autoCapitalize: "off",
  autoComplete: "off",
};

const clampActionsSidebarWidth = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return DEFAULT_ACTIONS_SIDEBAR_WIDTH;
  return Math.min(MAX_ACTIONS_SIDEBAR_WIDTH, Math.max(MIN_ACTIONS_SIDEBAR_WIDTH, Math.round(numeric)));
};

const compactAgentId = (raw) => {
  const id = formatAgentId(raw);
  if (!id || id.length <= 10) return id;
  return `${id.slice(0, 4)}...${id.slice(-4)}`;
};

const agentIdMaskParts = (raw) => {
  const id = formatAgentId(raw);
  if (!id) return null;
  if (id.length <= 8) {
    return { prefix: id, middle: "", suffix: "" };
  }
  return {
    prefix: id.slice(0, 4),
    middle: "...",
    suffix: id.slice(-4),
  };
};

const renderMaskedAgentId = (raw) => {
  const parts = agentIdMaskParts(raw);
  if (!parts) return "-";
  return (
    <span className="agent-id-mask" title={formatAgentId(raw)}>
      <span>{parts.prefix}</span>
      {parts.middle ? <span className="agent-id-mask-middle">{parts.middle}</span> : null}
      {parts.suffix ? <span>{parts.suffix}</span> : null}
    </span>
  );
};

export default function Actions() {
  const workspaceRef = useRef(null);
  const resizeRef = useRef(null);
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
  const [nativePanelExpanded, setNativePanelExpanded] = useState(true);
  const [guideExpanded, setGuideExpanded] = useState(true);
  const [catalogWidth, setCatalogWidth] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_ACTIONS_SIDEBAR_WIDTH;
    return clampActionsSidebarWidth(window.localStorage.getItem(ACTIONS_SIDEBAR_WIDTH_STORAGE_KEY));
  });

  const selectedAction = useMemo(
    () => actions.find((a) => a.id === actionId) || null,
    [actions, actionId]
  );
  const selectedActionIdLower = String(selectedAction?.id || "").trim().toLowerCase();
  const showNativePackagePanel = Boolean(selectedActionIdLower) && WINGET_BACKED_ACTION_IDS.has(selectedActionIdLower);

  useEffect(() => {
    if (showNativePackagePanel) {
      setNativePanelExpanded(true);
    }
  }, [showNativePackagePanel]);

  useEffect(() => {
    if (selectedAction?.docs) {
      setGuideExpanded(true);
    }
  }, [selectedAction]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(ACTIONS_SIDEBAR_WIDTH_STORAGE_KEY, String(catalogWidth));
  }, [catalogWidth]);

  const stopCatalogResize = useCallback(() => {
    if (typeof window !== "undefined" && resizeRef.current) {
      window.removeEventListener("mousemove", resizeRef.current.onMove);
      window.removeEventListener("mouseup", resizeRef.current.onUp);
      resizeRef.current = null;
    }
    if (typeof document !== "undefined") {
      document.body.style.removeProperty("cursor");
      document.body.style.removeProperty("user-select");
    }
  }, []);

  useEffect(() => () => stopCatalogResize(), [stopCatalogResize]);

  const startCatalogResize = useCallback((event) => {
    if (typeof window === "undefined" || window.innerWidth <= 1024) return;
    event.preventDefault();
    stopCatalogResize();
    const startX = event.clientX;
    const startWidth = catalogWidth;
    const onMove = (moveEvent) => {
      const delta = moveEvent.clientX - startX;
      setCatalogWidth(clampActionsSidebarWidth(startWidth + delta));
    };
    const onUp = () => stopCatalogResize();
    resizeRef.current = { onMove, onUp };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    if (typeof document !== "undefined") {
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }
  }, [catalogWidth, stopCatalogResize]);

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

  const actionSearchSuggestions = useMemo(() => {
    const q = actionSearch.trim().toLowerCase();
    const preferred = ACTION_SEARCH_PRIORITY
      .map((id) => actions.find((action) => action?.id === id))
      .filter(Boolean);
    const pool = q ? filteredActions : preferred.length ? preferred : filteredActions;
    return pool.slice(0, 5);
  }, [actions, actionSearch, filteredActions]);

  const packageInputValue = useMemo(
    () => String(actionInputs.package || actionInputs.package_id || "").trim(),
    [actionInputs]
  );

  const packageSuggestions = useMemo(() => {
    const query = packageInputValue.toLowerCase();
    const matches = PACKAGE_ID_EXAMPLES.filter((item) =>
      !query || item.id.toLowerCase().includes(query) || item.label.toLowerCase().includes(query)
    );
    return matches.slice(0, 5);
  }, [packageInputValue]);

  const targetPickList = useMemo(() => {
    const q = targetSearch.trim().toLowerCase();
    const base = agents;
    if (!q) return base.slice(0, 60);
    return base
      .filter((a) => a.id.includes(q) || a.name.toLowerCase().includes(q) || a.group.toLowerCase().includes(q))
      .slice(0, 60);
  }, [agents, targetSearch]);

  const targetSelectionSummary = useMemo(() => {
    if (targetMode === "fleet") {
      const excluded = excludeAgents
        .split(",")
        .map((id) => formatAgentId(id.trim()))
        .filter(Boolean);
      return excluded.length ? `Fleet minus ${excluded.length} excluded agent(s)` : "Entire managed fleet";
    }
    if (targetMode === "group") {
      const excluded = excludeAgents
        .split(",")
        .map((id) => formatAgentId(id.trim()))
        .filter(Boolean);
      return `${targetValue || "No group selected"}${excluded.length ? ` | ${excluded.length} excluded` : ""}`;
    }
    if (targetMode === "multi") {
      return targetAgentIds.length
        ? `${targetAgentIds.length} selected agent(s)`
        : "No agents selected";
    }
    return targetValue ? `Agent ${compactAgentId(targetValue)}` : "No agent selected";
  }, [excludeAgents, targetAgentIds, targetMode, targetValue]);

  const selectedAgentRows = useMemo(
    () => agents.filter((agent) => targetAgentIds.includes(agent.id)),
    [agents, targetAgentIds]
  );

  const actionDocEntries = useMemo(() => {
    const docs = selectedAction?.docs;
    if (!docs || typeof docs !== "object") return [];
    return [
      ["What it does", docs.what_it_does],
      ["When to use", docs.when_to_use],
      ["Impact", docs.impact],
      ["Rollback", docs.rollback],
      ["Requirements", docs.requirements],
      ["Examples", docs.examples],
    ].filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== "");
  }, [selectedAction]);

  const applyCatalogSelection = (action) => {
    const nextId = String(action?.id || "").trim();
    if (!nextId) return;
    if (WINGET_BACKED_ACTION_IDS.has(nextId.toLowerCase())) {
      selectWingetQuickAction(nextId);
    } else {
      setActionId(nextId);
      setActionValidation(null);
    }
    setActionSearch(String(action?.label || nextId));
  };

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

  const selectWingetQuickAction = (nextActionId) => {
    setActionId(nextActionId);
    setActionValidation(null);
    setActionInputs((prev) => {
      const next = { ...prev };
      if (nextActionId === PACKAGE_UPDATE_ACTION_ID && !String(next.package || "").trim()) {
        next.package = "all";
      }
      if (nextActionId === SPECIFIC_SOFTWARE_ACTION_ID && next.package === undefined) {
        next.package = "";
      }
      if (next.version === undefined) {
        next.version = "";
      }
      return next;
    });
    setActionStatus(
      "Selected native package action. Windows endpoints use winget-backed remediation and the backend bootstraps winget when it is missing."
    );
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

  const buildExecutionPayload = (target) => ({
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
      await requestApproval(buildExecutionPayload(target));
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
      const res = await runAction(buildExecutionPayload(target));
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
          <h2>Actions Workspace</h2>
          <p className="muted">
            High-density execution planning for endpoint actions, package remediation, and live response runs.
          </p>
        </div>
        <div className="page-actions">
          <button
            className="btn secondary"
            onClick={() => {
              loadActions();
              loadConnectorStatus();
            }}
          >
            Refresh Catalog
          </button>
          <button
            className="btn secondary"
            onClick={() => {
              loadAgents();
              loadGroups();
            }}
          >
            Refresh Targets
          </button>
        </div>
      </div>

      {actionStatus ? <div className="empty-state">{actionStatus}</div> : null}

      <div className="mission-grid">
        <div className="mission-card">
          <div className="mission-label">Selected Action</div>
          <div className="mission-value">{selectedAction ? "1" : "0"}</div>
          <div className="mission-meta">
            {selectedAction ? `${toDisplay(selectedAction.label || selectedAction.id)} (${selectedAction.id})` : "Pick an action from the catalog."}
          </div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Target Scope</div>
          <div className="mission-value">
            {targetMode === "multi" ? targetAgentIds.length : targetMode === "group" ? (targetValue || "-") : targetMode === "fleet" ? "ALL" : (compactAgentId(targetValue) || "-")}
          </div>
          <div className="mission-meta">{targetSelectionSummary}</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Windows Connector</div>
          <div className="mission-value">
            {connectorStatus?.connectors?.windows?.credentials_configured ? "READY" : "CHECK"}
          </div>
          <div className="mission-meta">
            Orchestration mode: {toDisplay(connectorStatus?.orchestration_mode || "n/a")}
          </div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Linux Connector</div>
          <div className="mission-value">
            {connectorStatus?.connectors?.linux?.credentials_configured ? "READY" : "CHECK"}
          </div>
          <div className="mission-meta">
            {connectorError || "Credentials and connector health are shown live from the backend."}
          </div>
        </div>
      </div>

      <div
        ref={workspaceRef}
        className="actions-workspace"
        style={{ "--actions-sidebar-width": `${catalogWidth}px` }}
      >
        <aside className="actions-sidebar-pane card">
          <div className="card-header">
            <div>
              <h3>Action Catalog</h3>
              <p className="muted">Search, shortlist, and lock in the exact backend action ID.</p>
            </div>
            <span className="chip">{filteredActions.length} visible</span>
          </div>
          <div className="page-actions actions-command-bar">
            <input
              className="input"
              value={actionSearch}
              onChange={(e) => setActionSearch(e.target.value)}
              placeholder="Search actions, categories, or exact IDs"
              {...RAW_INPUT_PROPS}
            />
          </div>
          {actionSearchSuggestions.length ? (
            <div className="actions-suggestion-row mt-8">
              {actionSearchSuggestions.map((action) => (
                <button
                  key={`suggest-${action.id}`}
                  type="button"
                  className="btn secondary"
                  onClick={() => applyCatalogSelection(action)}
                >
                  {toDisplay(action.label || action.id)}
                </button>
              ))}
            </div>
          ) : null}
          <div className="meta-line mt-6">
            Search suggestions surface exact action IDs and common remediation paths to reduce operator guesswork.
          </div>
          {actionsLoading ? (
            <div className="empty-state">Loading actions...</div>
          ) : filteredActions.length === 0 ? (
            <div className="empty-state">No actions found.</div>
          ) : (
            <div className="list-scroll tall actions-catalog-scroll">
              <div className="list">
                {filteredActions.map((a) => (
                  <button
                    key={a.id}
                    type="button"
                    className={`list-item clickable readable text-left ${a.id === actionId ? "selected" : ""}`}
                    onClick={() => applyCatalogSelection(a)}
                  >
                    <div className="flex-between">
                      <strong>{toDisplay(a.label || a.id)}</strong>
                      <div className="page-actions gap-6">
                        <span className="chip">{toDisplay(a.category || "response")}</span>
                        {WINGET_BACKED_ACTION_IDS.has(String(a.id || "").trim().toLowerCase()) ? (
                          <span className="status-pill success">Recommended</span>
                        ) : null}
                      </div>
                    </div>
                    <div className="meta-line ws-normal mono">{a.id}</div>
                    {a.description ? (
                      <div className="meta-line ws-normal">{a.description}</div>
                    ) : null}
                  </button>
                ))}
              </div>
            </div>
          )}
        </aside>

        <div className="actions-workspace-divider" aria-hidden="true">
          <button
            type="button"
            className="actions-workspace-divider-handle"
            onMouseDown={startCatalogResize}
            onDoubleClick={() => setCatalogWidth(DEFAULT_ACTIONS_SIDEBAR_WIDTH)}
            title="Drag to resize action catalog. Double-click to reset."
          />
        </div>

        <div className="actions-main-pane">
          <div className="actions-console-grid">
            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Targeting & Connectors</h3>
                  <p className="muted">Define the blast radius, exclusions, and connector readiness without leaving the workspace.</p>
                </div>
                <button className="btn secondary" onClick={validateConnector}>
                  Validate Connector
                </button>
              </div>

              <div className="list">
                <div className="list-item readable">
                  <div className="muted">Scope Builder</div>
                  <div className="page-actions mt-8">
                    <select className="input" value={targetMode} onChange={(e) => setTargetMode(e.target.value)}>
                      <option value="agent">Single agent</option>
                      <option value="multi">Multiple agents</option>
                      <option value="group">Agent group</option>
                      <option value="fleet">Fleet (all)</option>
                    </select>
                    <span className="chip">Current scope: {targetSelectionSummary}</span>
                    {targetMode === "multi" ? <span className="chip">Selected: {targetAgentIds.length}</span> : null}
                  </div>

                  {targetMode === "multi" ? (
                    <>
                      <div className="page-actions mt-10">
                        <input
                          className="input"
                          value={targetSearch}
                          onChange={(e) => setTargetSearch(e.target.value)}
                          placeholder="Search agents by ID, hostname, or group"
                          {...RAW_INPUT_PROPS}
                        />
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() => setTargetAgentIds(targetPickList.map((a) => a.id))}
                        >
                          Select Visible
                        </button>
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() => setTargetAgentIds([])}
                        >
                          Clear
                        </button>
                      </div>
                      <div className="table-scroll h-44vh">
                        <table className="table compact readable">
                          <thead>
                            <tr>
                              <th>Pick</th>
                              <th>Agent</th>
                              <th>Name</th>
                              <th>Group</th>
                              <th>Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {targetPickList.length === 0 ? (
                              <tr>
                                <td colSpan={5}>No agents match your search.</td>
                              </tr>
                            ) : (
                              targetPickList.map((agent) => {
                                const checked = targetAgentIds.includes(agent.id);
                                return (
                                  <tr key={`target-${agent.id}`} data-agent-id={agent.id}>
                                    <td>
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
                                      />
                                    </td>
                                    <td>{renderMaskedAgentId(agent.id)}</td>
                                    <td>{agent.name || "-"}</td>
                                    <td>{agent.group || "-"}</td>
                                    <td>
                                      <span className={`status-pill ${agentStatusClass(agent.status)}`}>
                                        {agent.status || "unknown"}
                                      </span>
                                    </td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    </>
                  ) : null}

                  {targetMode === "group" ? (
                    <div className="actions-form-grid mt-10">
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
                        {...RAW_INPUT_PROPS}
                      />
                      <div className="meta-line">
                        Group actions keep the raw exclusion list intact and only normalize IDs when building the request payload.
                      </div>
                    </div>
                  ) : null}

                  {targetMode === "fleet" ? (
                    <div className="actions-form-grid mt-10">
                      <div className="empty-state">
                        Fleet mode targets every managed endpoint unless exclusions are provided.
                      </div>
                      <input
                        className="input"
                        value={excludeAgents}
                        onChange={(e) => setExcludeAgents(e.target.value)}
                        placeholder="Exclude agent IDs (comma separated)"
                        {...RAW_INPUT_PROPS}
                      />
                    </div>
                  ) : null}

                  {targetMode === "agent" ? (
                    <div className="actions-form-grid mt-10">
                      <input
                        className="input"
                        value={targetValue}
                        onChange={(e) => setTargetValue(e.target.value)}
                        placeholder="Agent ID (example: 004)"
                        list="agentIds"
                        {...RAW_INPUT_PROPS}
                      />
                      <datalist id="agentIds">
                        {agents.slice(0, 120).map((a) => (
                          <option key={`agent-${a.id}`} value={a.id}>
                            {a.name}
                          </option>
                        ))}
                      </datalist>
                      <div className="meta-line">
                        Agent IDs are preserved as entered and normalized only for dispatch.
                      </div>
                    </div>
                  ) : null}
                </div>

                <div className="list-item readable">
                  <div className="muted">Connector Readiness</div>
                  <div className="page-actions mt-8">
                    <span className="chip">Mode: {toDisplay(connectorStatus?.orchestration_mode || "n/a")}</span>
                    <span className={`status-pill ${connectorStatus?.connectors?.windows?.credentials_configured ? "success" : "failed"}`}>
                      WinRM {connectorStatus?.connectors?.windows?.credentials_configured ? "Ready" : "Missing"}
                    </span>
                    <span className={`status-pill ${connectorStatus?.connectors?.linux?.credentials_configured ? "success" : "pending"}`}>
                      Linux {connectorStatus?.connectors?.linux?.credentials_configured ? "Ready" : "Check"}
                    </span>
                  </div>
                  {connectorError ? (
                    <div className="meta-line ws-normal mt-6">
                      Connector status error: {connectorError}
                    </div>
                  ) : (
                    <div className="meta-line mt-6">
                      Backend connector probes remain independent from action form state, so refreshing status will not wipe your in-progress justification or inputs.
                    </div>
                  )}
                </div>

                {selectedAgentRows.length ? (
                  <div className="list-item readable">
                    <div className="muted">Selected Agents</div>
                    <div className="actions-selection-strip mt-8">
                      {selectedAgentRows.slice(0, 16).map((agent) => (
                        <div key={`selected-${agent.id}`} className="selection-chip" data-agent-id={agent.id}>
                          {renderMaskedAgentId(agent.id)}
                          <span>{agent.name || "-"}</span>
                        </div>
                      ))}
                      {selectedAgentRows.length > 16 ? (
                        <div className="selection-chip">+{selectedAgentRows.length - 16} more</div>
                      ) : null}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Action Builder</h3>
                  <p className="muted">Keep the payload raw, review the execution contract, and launch without leaving the console.</p>
                </div>
                {selectedAction ? <span className="chip mono">{selectedAction.id}</span> : null}
              </div>

              <div className="list">
                <div className="list-item readable">
                  <div className="muted">Selected Action</div>
                  {selectedAction ? (
                    <>
                      <div className="mt-6">
                        <strong>{toDisplay(selectedAction.label || selectedAction.id)}</strong>
                      </div>
                      <div className="meta-line ws-normal mono">{selectedAction.id}</div>
                      {selectedAction.description ? (
                        <div className="meta-line ws-normal">{selectedAction.description}</div>
                      ) : null}
                      <div className="page-actions mt-8">
                        <span className="chip">{toDisplay(selectedAction.category || "response")}</span>
                        <span className={`status-pill ${riskClass(selectedAction.risk)}`}>
                          {toDisplay(selectedAction.risk || "n/a")}
                        </span>
                        <span className="chip">
                          {selectedAction.custom ? "custom command" : "built-in action"}
                        </span>
                      </div>
                      {selectedActionIdLower === CUSTOM_OS_COMMAND_ACTION_ID ? (
                        <div className="empty-state mt-8">
                          Raw command text is preserved exactly as typed. Backticks, dollar signs, colons, and slashes are not reformatted before backend Base64 encoding.
                        </div>
                      ) : null}
                    </>
                  ) : (
                    <div className="meta-line mt-6">Pick an action from the catalog to start building the request.</div>
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
                        {...RAW_INPUT_PROPS}
                      />
                    ) : (
                      <input
                        className="input mt-8"
                        value={actionInputs[field.name] || ""}
                        list={
                          WINGET_BACKED_ACTION_IDS.has(selectedActionIdLower) && String(field.name || "").trim().toLowerCase() === "package"
                            ? "wingetPackageSuggestions"
                            : undefined
                        }
                        onChange={(e) =>
                          setActionInputs((prev) => ({
                            ...prev,
                            [field.name]: e.target.value,
                          }))
                        }
                        placeholder={field.placeholder || ""}
                        {...RAW_INPUT_PROPS}
                      />
                    )}
                    {WINGET_BACKED_ACTION_IDS.has(selectedActionIdLower) && String(field.name || "").trim().toLowerCase() === "package" ? (
                      <>
                        <datalist id="wingetPackageSuggestions">
                          {PACKAGE_ID_EXAMPLES.map((item) => (
                            <option key={item.id} value={item.id}>
                              {item.label}
                            </option>
                          ))}
                        </datalist>
                        <div className="meta-line ws-normal mt-6">
                          Package syntax hint: use the exact winget ID such as `Notepad++.Notepad++`. Use `all` only with the bulk package-update action.
                        </div>
                        {packageSuggestions.length ? (
                          <div className="actions-suggestion-row mt-8">
                            {packageSuggestions.map((item) => (
                              <button
                                key={`pkg-${item.id}`}
                                type="button"
                                className="btn secondary"
                                onClick={() =>
                                  setActionInputs((prev) => ({
                                    ...prev,
                                    [field.name]: item.id,
                                  }))
                                }
                              >
                                {item.id}
                              </button>
                            ))}
                          </div>
                        ) : null}
                      </>
                    ) : null}
                  </div>
                ))}

                <div className="list-item readable">
                  <div className="muted">Justification</div>
                  <textarea
                    className="input mt-8"
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    placeholder="Why is this response needed?"
                    rows={3}
                    {...RAW_INPUT_PROPS}
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
              </div>

              <div className="actions-command-bar">
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

          {(showNativePackagePanel || actionDocEntries.length) ? (
            <div className="actions-docs-grid">
              {showNativePackagePanel ? (
                <div className="card">
                  <div className="card-header">
                    <div>
                      <h3>Native Package Path</h3>
                      <p className="muted">Winget-backed software install and upgrade flows tuned for Windows endpoints.</p>
                    </div>
                    <button
                      className="btn secondary"
                      type="button"
                      onClick={() => setNativePanelExpanded((prev) => !prev)}
                    >
                      {nativePanelExpanded ? "Collapse" : "Expand"}
                    </button>
                  </div>
                  {nativePanelExpanded ? (
                    <>
                      <div className="empty-state">
                        Windows package actions stay on the native remediation path. If winget is missing, the backend attempts bootstrap and then retries the install or upgrade automatically.
                      </div>
                      <div className="actions-suggestion-row mt-10">
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() => selectWingetQuickAction(PACKAGE_UPDATE_ACTION_ID)}
                        >
                          Upgrade Installed Packages
                        </button>
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() => selectWingetQuickAction(SPECIFIC_SOFTWARE_ACTION_ID)}
                        >
                          Install / Upgrade Specific Package
                        </button>
                      </div>
                      <div className="meta-line mt-8">
                        Preferred syntax: use exact package IDs such as `Publisher.Product`. Existing installs that are already at target state now resolve to success instead of hanging as unresolved work.
                      </div>
                    </>
                  ) : null}
                </div>
              ) : null}

              {actionDocEntries.length ? (
                <div className="card">
                  <div className="card-header">
                    <div>
                      <h3>Action Guide</h3>
                      <p className="muted">Operator-facing notes and guardrails for the currently selected action.</p>
                    </div>
                    <button
                      className="btn secondary"
                      type="button"
                      onClick={() => setGuideExpanded((prev) => !prev)}
                    >
                      {guideExpanded ? "Collapse" : "Expand"}
                    </button>
                  </div>
                  {guideExpanded ? (
                    <div className="list">
                      {actionDocEntries.map(([label, value]) => (
                        <div key={label} className="list-item readable">
                          <div className="muted">{label}</div>
                          <div className="mt-6 ws-pre-wrap">{String(value)}</div>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
          ) : null}

          {activeExecutionId ? <ExecutionStream executionId={activeExecutionId} /> : null}

          {matrixRows.length ? (
            <div className="card">
              <div className="card-header">
                <div>
                  <h3>Action Matrix</h3>
                  <p className="muted">Targeted validation results for the current scope.</p>
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
                        <td>
                          <div className="execution-cell-text">
                            <strong>{row.label}</strong>
                            <div className="meta-line mono">{row.id}</div>
                          </div>
                        </td>
                        <td>
                          <span className={`status-pill ${row.ok ? "success" : "failed"}`}>
                            {row.ok ? "Valid" : "Invalid"}
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

import { useCallback, useEffect, useMemo, useState } from "react";
import ExecutionStream from "../components/ExecutionStream";
import StatusBar from "../components/StatusBar";
import GlobalSearchBar from "../components/GlobalSearchBar";
import ActionArsenal from "../components/ActionArsenal";
import TacticalMap from "../components/TacticalMap";
import ExecutionChamber from "../components/ExecutionChamber";
import {
  getActions,
  getAgents,
  getActionConnectorStatus,
  runAction,
} from "../api/wazuh";

const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);

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
    const fallback =
      field.default !== undefined && field.default !== null ? String(field.default) : "";
    defaults[name] = fallback;
  });
  return defaults;
};

const actionLabel = (action) =>
  String(action?.label || action?.name || action?.id || "").trim();

const isActionConnected = (connectorStatus, connectorError) =>
  connectorStatus?.status === "connected" || !connectorError;

export default function Actions() {
  const [actions, setActions] = useState([]);
  const [actionSearch, setActionSearch] = useState("");
  const [actionId, setActionId] = useState("");
  const [actionInputs, setActionInputs] = useState({});
  const [actionStatus, setActionStatus] = useState("");
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [justification, setJustification] = useState("");
  const [agents, setAgents] = useState([]);
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [connectorStatus, setConnectorStatus] = useState(null);
  const [connectorError, setConnectorError] = useState("");
  const [isActionRunning, setIsActionRunning] = useState(false);

  const selectedAction = useMemo(
    () => actions.find((action) => String(action?.id || "") === String(actionId)) || null,
    [actions, actionId]
  );

  const filteredActions = useMemo(() => {
    const query = actionSearch.trim().toLowerCase();
    if (!query) return actions;
    return actions.filter((action) => {
      const label = actionLabel(action).toLowerCase();
      const category = String(action?.category || action?.type || "").toLowerCase();
      const description = String(action?.description || "").toLowerCase();
      return label.includes(query) || category.includes(query) || description.includes(query);
    });
  }, [actions, actionSearch]);

  const selectedAgents = useMemo(
    () => agents.filter((agent) => targetAgentIds.includes(agent.id)),
    [agents, targetAgentIds]
  );

  const loadActions = useCallback(async () => {
    try {
      const response = await getActions();
      const nextActions = Array.isArray(response?.data) ? response.data : [];
      setActions(nextActions);
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
          const status = toDisplay(agent?.status, "unknown");
          const os = toDisplay(agent?.os?.name || agent?.os || agent?.platform, "-");
          const latency = Number(agent?.latency_ms || agent?.latency || agent?.ping || 0) || 0;
          return {
            id,
            name: hostname,
            hostname,
            status,
            os,
            latency,
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
      setConnectorError(
        error?.response?.data?.detail || error?.message || "Connector status unavailable"
      );
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
    setActionInputs((current) => ({
      ...current,
      [key]: value,
    }));
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
      setActionStatus(
        executionId ? `Action submitted as execution #${executionId}.` : "Action submitted."
      );
    } catch (error) {
      setActionStatus(
        error?.response?.data?.detail || error?.message || "Action execution failed."
      );
    } finally {
      setIsActionRunning(false);
    }
  }, [selectedAction, targetAgentIds, justification, isActionRunning, actionId, actionInputs]);

  return (
    <>
      <style>{`
.actions-workspace-titan {
  display: grid;
  grid-template-rows: 1px 1fr;
  height: 100vh;
  background: var(--bg-0);
  overflow: hidden;
}

.actions-3col-layout {
  display: grid;
  grid-template-columns: 20% 1px 55% 1px 25%;
  height: 100%;
  gap: 0;
  background: var(--border);
}

.actions-arsenal-panel {
  background: var(--panel);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.actions-tactical-panel {
  background: var(--bg-1);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.actions-execution-panel {
  background: var(--panel);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 0;
  right: 0;
}

.actions-gutter {
  background: var(--border);
  width: 1px;
}

.execution-stream-container {
  position: fixed;
  bottom: 0;
  right: 0;
  width: 25%;
  max-height: 400px;
  background: var(--panel);
  border-top: 1px solid var(--border);
  border-left: 1px solid var(--border);
  z-index: 50;
  overflow-y: auto;
}

@media (max-width: 1280px) {
  .actions-3col-layout {
    grid-template-columns: 25% 1px 50% 1px 25%;
  }
}

@media (max-width: 1024px) {
  .actions-3col-layout {
    grid-template-columns: 30% 1px 70%;
  }

  .actions-execution-panel {
    position: static;
  }

  .execution-stream-container {
    position: static;
    width: 100%;
    max-height: none;
    border: none;
    border-top: 1px solid var(--border);
  }
}
      `}</style>
      <div className="actions-workspace-titan">
        <StatusBar isConnected={isActionConnected(connectorStatus, connectorError)} />
        <GlobalSearchBar
          onSearch={setActionSearch}
          placeholder="Search actions by name or category..."
        />

        <div className="actions-3col-layout">
          <div className="actions-arsenal-panel">
            <ActionArsenal
              actions={filteredActions}
              selectedActionId={actionId}
              onActionSelect={handleActionSelect}
              searchQuery={actionSearch}
            />
          </div>

          <div className="actions-gutter" />

          <div className="actions-tactical-panel">
            <TacticalMap
              agents={agents}
              selectedAgents={targetAgentIds}
              onToggleAgent={handleToggleAgent}
            />
          </div>

          <div className="actions-gutter" />

          <div className="actions-execution-panel">
            <ExecutionChamber
              selectedAction={selectedAction}
              selectedAgents={selectedAgents}
              actionInputs={actionInputs}
              onActionInputChange={handleActionInputChange}
              multilineFields={MULTILINE_INPUT_FIELDS}
              onExecute={handleExecuteAction}
              isExecuting={isActionRunning}
              justification={justification}
              onJustificationChange={setJustification}
              statusMessage={actionStatus}
            />
          </div>
        </div>

        {activeExecutionId ? (
          <div className="execution-stream-container">
            <ExecutionStream executionId={activeExecutionId} />
          </div>
        ) : null}
      </div>
    </>
  );
}

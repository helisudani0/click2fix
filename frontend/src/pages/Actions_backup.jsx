import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ExecutionStream from "../components/ExecutionStream";
import StatusBar from "../components/StatusBar";
import GlobalSearchBar from "../components/GlobalSearchBar";
import ActionArsenal from "../components/ActionArsenal";
import TacticalMap from "../components/TacticalMap";
import ExecutionChamber from "../components/ExecutionChamber";
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

const riskClass = (risk) => {
  const value = String(risk || "").toLowerCase();
  if (value.includes("critical") || value.includes("high")) return "failed";
  if (value.includes("medium")) return "pending";
  if (value.includes("low")) return "success";
  return "neutral";
};

const PACKAGE_UPDATE_ACTION_ID = "package-update";
const SPECIFIC_SOFTWARE_ACTION_ID = "software-install-upgrade";
const CUSTOM_OS_COMMAND_ACTION_ID = "custom-os-command";
const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);
const WINGET_BACKED_ACTION_IDS = new Set([PACKAGE_UPDATE_ACTION_ID, SPECIFIC_SOFTWARE_ACTION_ID]);
const PACKAGE_ID_EXAMPLES = [
  { id: "Microsoft.Edge", label: "Microsoft Edge" },
  { id: "Google.Chrome", label: "Google Chrome" },
  { id: "Mozilla.Firefox", label: "Mozilla Firefox" },
  { id: "Notepad++.Notepad++", label: "Notepad++" },
  { id: "7zip.7zip", label: "7-Zip" },
  { id: "Git.Git", label: "Git" },
];

const RAW_INPUT_PROPS = {
  spellCheck: false,
  autoCorrect: "off",
  autoCapitalize: "off",
  autoComplete: "off",
};

const styles = `
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
`;

export default function Actions() {
  const [actions, setActions] = useState([]);
  const [actionsLoading, setActionsLoading] = useState(true);
  const [actionSearch, setActionSearch] = useState("");
  const [actionId, setActionId] = useState("");
  const [actionInputs, setActionInputs] = useState({});
  const [actionValidation, setActionValidation] = useState(null);
  const [activeExecutionId, setActiveExecutionId] = useState(null);
  const [justification, setJustification] = useState("");

  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [targetSearch, setTargetSearch] = useState("");

  const [connectorStatus, setConnectorStatus] = useState(null);
  const [connectorError, setConnectorError] = useState("");
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [matrixRows, setMatrixRows] = useState([]);

  const selectedAction = useMemo(
    () => actions.find((a) => a.id === actionId) || null,
    [actions, actionId]
  );

  // Load actions, agents, groups, and connector status
  const loadActions = useCallback(async () => {
    setActionsLoading(true);
    try {
      const res = await getActions();
      const actionList = (res.data || []).map((a) => ({
        id: a.id,
        name: a.label || a.id,
        label: a.label || a.id,
        category: a.category || "Remediation",
        description: a.description || "",
        icon: a.category === "Containment" ? "🛡️" : 
              a.category === "Investigation" ? "🔍" : "⚙️",
        ...a,
      }));
      setActions(actionList);
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
        const hostname = toDisplay(a.name || a.hostname || id || "-");
        const status = toDisplay(a.status, "offline");
        const os = toDisplay(a.os || a.os_name || "");
        const latency = a.latency || null;
        return { id, hostname, status, os, latency };
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

  // Filter actions by search
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

  // Handle action execution
  const handleExecuteAction = useCallback(async () => {
    if (!selectedAction || targetAgentIds.length === 0 || !justification.trim()) {
      return;
    }

    setIsActionRunning(true);
    try {
      const payload = {
        action_id: selectedAction.id,
        agent_ids: targetAgentIds,
        inputs: actionInputs,
        justification: justification.trim(),
      };

      const res = await runAction(payload);
      setActiveExecutionId(res.data?.execution_id);
      
      // Reset form after execution
      setTimeout(() => {
        setJustification("");
        setActionInputs({});
        setTargetAgentIds([]);
      }, 1000);
    } catch (err) {
      console.error("Action execution failed:", err);
    } finally {
      setIsActionRunning(false);
    }
  }, [selectedAction, targetAgentIds, justification, actionInputs]);

  const isConnected = connectorStatus?.status === "connected" || !connectorError;

  return (
    <>
      <style>{styles}</style>
      <div className="actions-workspace-titan page-route-actions-backup">
        {/* Status Bar - 1px height, pulsing green/red */}
        <StatusBar isConnected={isConnected} />

        {/* Global Search Bar - Floating at top center with glassmorphism */}
        <GlobalSearchBar
          onSearch={(query) => setActionSearch(query)}
          placeholder="Search actions by name or category..."
        />

        {/* 3-Column Layout */}
        <div className="actions-3col-layout">
          {/* Left Panel: Action Arsenal (20%) */}
          <div className="actions-arsenal-panel">
            <ActionArsenal
              actions={filteredActions}
              selectedActionId={actionId}
              onActionSelect={(action) => {
                setActionId(action.id);
                setActionValidation(null);
              }}
              searchQuery={actionSearch}
            />
          </div>

          {/* Gutter */}
          <div className="actions-gutter" />

          {/* Center Panel: Tactical Map (55%) */}
          <div className="actions-tactical-panel">
            <TacticalMap agents={agents} selectedAgents={targetAgentIds} />
          </div>

          {/* Gutter */}
          <div className="actions-gutter" />

          {/* Right Panel: Execution Chamber (25%) */}
          <div className="actions-execution-panel">
            <ExecutionChamber
              selectedAction={selectedAction}
              selectedAgents={targetAgentIds}
              onExecute={handleExecuteAction}
              isExecuting={isActionRunning}
              justification={justification}
              onJustificationChange={setJustification}
            />
          </div>
        </div>

        {/* Execution Stream (appears at bottom right when active) */}
        {activeExecutionId && (
          <div className="execution-stream-container">
            <ExecutionStream executionId={activeExecutionId} />
          </div>
        )}
      </div>
    </>
  );
}

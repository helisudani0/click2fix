import { useEffect, useState } from "react";
import api from "../api/client";
import {
  getPlaybooks,
  getPlaybook,
  generatePlaybook,
  savePlaybook,
  executePlaybook,
  seedDefaultPlaybooks,
} from "../api/wazuh";
import ExecutionStream from "../components/ExecutionStream";

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
      args: { path: String(task.path || "C:\\\\Temp\\\\suspect.exe") },
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
    steps: steps.map((step, idx) => ({
      id: step.id || `step_${idx + 1}`,
      action: step.action || "ioc-scan",
      args: step.args && typeof step.args === "object" ? step.args : {},
      reason: step.reason || "Playbook step",
    })),
  };
}

export default function Playbooks() {

  const [playbooks, setPlaybooks] = useState([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [generated, setGenerated] = useState(null);
  const [alertId, setAlertId] = useState("");
  const [caseId, setCaseId] = useState("");
  const [playbookName, setPlaybookName] = useState("");
  const [targetType, setTargetType] = useState("agent");
  const [targetValue, setTargetValue] = useState("");
  const [excludeAgents, setExcludeAgents] = useState("");
  const [justification, setJustification] = useState("");
  const [dryRun, setDryRun] = useState(false);
  const [status, setStatus] = useState("");
  const [playbookSearch, setPlaybookSearch] = useState("");
  const [activeExecutionId, setActiveExecutionId] = useState(null);

  const refresh = async () => {
    await seedDefaultPlaybooks({ force: false }).catch(() => null);
    getPlaybooks().then((r) => setPlaybooks(r.data || []));
  };

  useEffect(() => {
    refresh();
  }, []);

  const loadPlaybook = (name) => {
    setStatus("");
    getPlaybook(name)
      .then((r) => {
        const normalized = normalizePlaybook(r.data);
        setSelectedPlaybook(normalized);
        setGenerated(normalized);
        setPlaybookName(normalized?.name || name.replace(/\.json$/i, ""));
        setActiveExecutionId(null);
        setStatus("Template loaded. Review args and request approvals.");
      })
      .catch(() => setSelectedPlaybook(null));
  };

  const handleGenerate = () => {
    setStatus("");
    setSelectedPlaybook(null);
    setActiveExecutionId(null);
    const parsedCaseId = Number(caseId);
    generatePlaybook({
      alert_id: alertId || undefined,
      case_id: caseId && Number.isFinite(parsedCaseId) ? parsedCaseId : undefined
    })
      .then(r => {
        const normalized = normalizePlaybook(r.data);
        setGenerated(normalized);
        setPlaybookName(normalized?.name || "generated-playbook");
        const agent = normalized?.source?.agent_id || "";
        if (agent) {
          setTargetType("agent");
          setTargetValue(agent);
        }
      })
      .catch(err => {
        setStatus(err.response?.data?.detail || "Failed to generate playbook.");
      });
  };

  const handleSave = () => {
    if (!generated) return;
    savePlaybook({ name: playbookName, payload: generated })
      .then(() => {
        setStatus("Playbook saved.");
        return getPlaybooks();
      })
      .then(r => setPlaybooks(r.data || []))
      .catch(err => {
        setStatus(err.response?.data?.detail || "Failed to save playbook.");
      });
  };

  const buildTargetPayload = () => {
    const raw = (targetValue || "").trim();
    if (targetType === "group") return { group: raw };
    if (targetType === "fleet") return { agent_id: "all" };
    if (targetType === "multi") {
      const ids = raw
        .split(",")
        .map((id) => id.trim())
        .filter(Boolean);
      return { agent_ids: ids };
    }
    return { agent_id: raw };
  };

  const updateStepArg = (stepIndex, key, value) => {
    setGenerated((current) => {
      if (!current?.steps) return current;
      const nextSteps = current.steps.map((step, idx) => {
        if (idx !== stepIndex) return step;
        return {
          ...step,
          args: {
            ...(step.args || {}),
            [key]: value,
          },
        };
      });
      return { ...current, steps: nextSteps };
    });
  };

  const handleRequestApprovals = async () => {
    if (!generated || !generated.steps?.length) return;
    const target = buildTargetPayload();
    const hasTarget =
      Boolean(target.agent_id) ||
      (Array.isArray(target.agent_ids) && target.agent_ids.length > 0) ||
      Boolean(target.group);
    if (!hasTarget) {
      setStatus("Target agent/group/multi/fleet is required.");
      return;
    }
    setStatus("Submitting approvals...");
    const basePayload = {
      alert_id: generated.source?.alert_id || alertId || undefined,
      case_id: generated.source?.case_id || (caseId ? Number(caseId) : undefined),
      justification: justification || undefined
    };
    Object.assign(basePayload, target);
    if ((targetType === "fleet" || targetType === "group") && excludeAgents.trim()) {
      basePayload.exclude_agent_ids = excludeAgents
        .split(",")
        .map((id) => id.trim())
        .filter(Boolean);
    }
    try {
      for (const step of generated.steps) {
        await api.post("/approvals/request", {
          ...basePayload,
          action_id: step.action,
          args: step.args || {}
        });
      }
      setStatus("Approvals requested.");
    } catch (err) {
      setStatus(err.response?.data?.detail || "Failed to request approvals.");
    }
  };

  const handleExecutePlaybook = async () => {
    if (!generated || !generated.steps?.length) return;
    const target = buildTargetPayload();
    const hasTarget =
      Boolean(target.agent_id) ||
      (Array.isArray(target.agent_ids) && target.agent_ids.length > 0) ||
      Boolean(target.group);
    if (!hasTarget) {
      setStatus("Target agent/group/multi/fleet is required.");
      return;
    }
    setStatus("Executing playbook...");
    try {
      const payload = {
        name: playbookName || generated?.name || undefined,
        payload: generated,
        ...target,
        dry_run: dryRun,
        ...(excludeAgents.trim()
          ? {
              exclude_agent_ids: excludeAgents
                  .split(",")
                .map((id) => id.trim())
                .filter(Boolean),
            }
          : {}),
        alert_id: generated.source?.alert_id || alertId || undefined,
        case_id: generated.source?.case_id || (caseId ? Number(caseId) : undefined),
        justification: justification || undefined,
      };
      const res = await executePlaybook(payload);
      if (res?.data?.dry_run || res?.data?.status === "SIMULATED") {
        setActiveExecutionId(null);
        setStatus("Playbook simulation completed. Review the resolved plan before executing.");
        return;
      }
      const executionId = res?.data?.execution_id;
      setActiveExecutionId(executionId || null);
      setStatus(
        executionId
          ? `Playbook execution submitted (run #${executionId}).`
          : "Playbook execution submitted."
      );
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message || "Failed to execute playbook.");
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Playbooks</h2>
          <p className="muted">Generate, save, and approve multi-step response playbooks.</p>
        </div>
        <div className="page-actions">
            <button className="btn secondary" onClick={refresh}>Refresh</button>
          </div>
        </div>

      {status && <div className="empty-state">{status}</div>}

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Generate Playbook</h3>
              <p className="muted">Create a response plan from alert or case context.</p>
            </div>
          </div>
          <div className="page-actions">
            <input
              className="input"
              placeholder="Alert ID"
              value={alertId}
              onChange={(e) => setAlertId(e.target.value)}
            />
            <input
              className="input"
              placeholder="Case ID"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
            />
            <button className="btn" onClick={handleGenerate}>Generate</button>
          </div>

          {generated ? (
            <div className="list">
              <div className="list-item">
                <strong>{generated.name}</strong>
                <div className="muted">{generated.description}</div>
                <div className="muted">
                  Source alert: {generated.source?.alert_id || "n/a"}
                </div>
              </div>
              {generated.steps?.length ? (
                <div className="list-scroll">
                  <div className="list">
                    {generated.steps.map((step, idx) => (
                      <div className="list-item" key={`${step.id}-${idx}`}>
                        <strong>{step.action || `step_${idx + 1}`}</strong>
                        <div className="muted">{step.reason || "Generated step"}</div>
                        {Object.keys(step.args || {}).length ? (
                          <div className="page-actions mt-8">
                            {Object.entries(step.args || {}).map(([key, value]) => (
                              <input
                                key={`${step.id}-${key}`}
                                className="input"
                                placeholder={key}
                                value={value == null ? "" : String(value)}
                                onChange={(e) => updateStepArg(idx, key, e.target.value)}
                              />
                            ))}
                          </div>
                        ) : (
                          <div className="muted">No arguments required.</div>
                        )}
                        <pre className="code-block">{JSON.stringify(step.args || {}, null, 2)}</pre>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="empty-state">No steps generated.</div>
              )}
              <div className="list-item">
                <div className="muted">Save & Approve</div>
                <div className="page-actions mt-8">
                  <input
                    className="input"
                    placeholder="Playbook name"
                    value={playbookName}
                    onChange={(e) => setPlaybookName(e.target.value)}
                  />
                  <button className="btn secondary" onClick={handleSave}>Save</button>
                </div>
                <div className="page-actions mt-8">
                  <select
                    className="input"
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                  >
                    <option value="agent">Agent</option>
                    <option value="group">Group</option>
                    <option value="multi">Multiple agents</option>
                    <option value="fleet">Fleet (all)</option>
                  </select>
                  <input
                    className="input"
                    placeholder={
                      targetType === "group"
                        ? "Group name"
                        : targetType === "multi"
                          ? "Agent IDs (comma separated)"
                          : targetType === "fleet"
                            ? "all"
                            : "Agent ID"
                    }
                    value={targetValue}
                    onChange={(e) => setTargetValue(e.target.value)}
                    disabled={targetType === "fleet"}
                  />
                  {(targetType === "fleet" || targetType === "group") ? (
                    <input
                      className="input"
                      placeholder="Exclude agent IDs (comma separated)"
                      value={excludeAgents}
                      onChange={(e) => setExcludeAgents(e.target.value)}
                    />
                  ) : null}
                  <input
                    className="input"
                    placeholder="Justification (if required)"
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                  />
                  <label className="muted inline-check">
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                    />
                    Dry run (simulate only)
                  </label>
                  <button className="btn" onClick={handleRequestApprovals}>
                    Request Approvals
                  </button>
                  <button className="btn secondary" onClick={handleExecutePlaybook}>
                    Execute Playbook
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-state">Generate a playbook to see steps.</div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Saved Playbooks</h3>
              <p className="muted">Review stored playbook templates.</p>
            </div>
          </div>
          <div className="page-actions">
            <input
              className="input"
              placeholder="Search playbooks"
              value={playbookSearch}
              onChange={(e) => setPlaybookSearch(e.target.value)}
            />
          </div>
          {playbooks.length === 0 ? (
            <div className="empty-state">No playbooks saved yet.</div>
          ) : (
            <div className="list-scroll">
              <ul className="list">
                {playbooks
                  .filter((p) => p.toLowerCase().includes(playbookSearch.trim().toLowerCase()))
                  .map((p) => (
                    <li key={p} className="list-item split">
                      <div>{p}</div>
                      <button className="btn secondary" onClick={() => loadPlaybook(p)}>
                        Load
                      </button>
                    </li>
                  ))}
              </ul>
            </div>
          )}
          {selectedPlaybook && (
            <div className="mt-12">
              <pre className="code-block">{JSON.stringify(selectedPlaybook, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>

      {activeExecutionId ? <ExecutionStream executionId={activeExecutionId} /> : null}
    </div>
  );
}

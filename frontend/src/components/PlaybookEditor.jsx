import { useEffect, useMemo, useState } from "react";

const MULTILINE_INPUT_FIELDS = new Set(["command", "custom_command", "script"]);

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

const formatArgs = (value) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "{}";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
};

const parseArgs = (value) => {
  try {
    const parsed = JSON.parse(String(value || "{}"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "Args JSON must be an object." };
    }
    return { ok: true, value: parsed };
  } catch (err) {
    return { ok: false, error: err.message || "Invalid JSON." };
  }
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
    const lowered = name.toLowerCase();
    if (lowered.includes("ip")) args[name] = "1.2.3.4";
    else if (lowered.includes("pid")) args[name] = "1234";
    else if (lowered.includes("path")) args[name] = "C:\\Temp\\suspect.exe";
    else if (lowered.includes("service")) args[name] = "WazuhSvc";
    else if (lowered.includes("user") || lowered.includes("account")) args[name] = "test-user";
    else if (lowered.includes("kb")) args[name] = "KB5030219";
    else if (lowered.includes("package")) args[name] = "Git.Git";
    else if (lowered.includes("command")) args[name] = "Get-Service WazuhSvc";
    else if (lowered.includes("hash") || lowered.includes("sha")) {
      args[name] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    } else {
      args[name] = "test";
    }
  });
  return args;
};

const normalizeStep = (step = {}, index = 0) => ({
  id: step.id || `step_${index + 1}`,
  action: step.action || step.command || "endpoint-healthcheck",
  args: step.args && typeof step.args === "object" && !Array.isArray(step.args) ? step.args : {},
  reason: step.reason || "Playbook step",
});

function PlaybookStepEditor({
  step,
  index,
  total,
  actions,
  onChange,
  onMove,
  onRemove,
}) {
  const selectedAction = useMemo(
    () => actions.find((item) => item.id === step.action) || null,
    [actions, step.action]
  );
  const [argsText, setArgsText] = useState(formatArgs(step.args));
  const [argsError, setArgsError] = useState("");

  useEffect(() => {
    setArgsText(formatArgs(step.args));
    setArgsError("");
  }, [step.args]);

  const updateArgsField = (name, value) => {
    const nextArgs = { ...(step.args || {}) };
    if (value === "") delete nextArgs[name];
    else nextArgs[name] = value;
    onChange(index, { ...step, args: nextArgs });
  };

  const applyArgsJson = () => {
    const parsed = parseArgs(argsText);
    if (!parsed.ok) {
      setArgsError(parsed.error || "Invalid JSON.");
      return;
    }
    setArgsError("");
    onChange(index, { ...step, args: parsed.value });
  };

  const resetArgsFromAction = () => {
    onChange(index, { ...step, args: buildSampleArgs(selectedAction) });
  };

  return (
    <div className="list-item readable">
      <div className="flex-between">
        <div>
          <strong>Step {index + 1}</strong>
          <div className="meta-line">{toDisplay(selectedAction?.label || step.action)}</div>
        </div>
        <div className="page-actions gap-6">
          <button
            type="button"
            className="btn secondary"
            onClick={() => onMove(index, -1)}
            disabled={index === 0}
          >
            Up
          </button>
          <button
            type="button"
            className="btn secondary"
            onClick={() => onMove(index, 1)}
            disabled={index >= total - 1}
          >
            Down
          </button>
          <button type="button" className="btn danger" onClick={() => onRemove(index)}>
            Remove
          </button>
        </div>
      </div>

      <div className="grid-3 mt-10">
        <div>
          <div className="muted">Step ID</div>
          <input
            className="input mt-8"
            value={step.id}
            onChange={(event) => onChange(index, { ...step, id: event.target.value })}
            placeholder={`step_${index + 1}`}
          />
        </div>
        <div>
          <div className="muted">Action</div>
          <select
            className="input mt-8"
            value={step.action}
            onChange={(event) => {
              const nextAction = event.target.value;
              const actionMeta = actions.find((item) => item.id === nextAction) || null;
              const hasArgs = Object.keys(step.args || {}).length > 0;
              onChange(index, {
                ...step,
                action: nextAction,
                args: hasArgs ? step.args : buildSampleArgs(actionMeta),
              });
            }}
          >
            <option value="">Select action</option>
            {actions.map((action) => (
              <option key={action.id} value={action.id}>
                {toDisplay(action.label || action.id)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <div className="muted">Reason</div>
          <input
            className="input mt-8"
            value={step.reason}
            onChange={(event) => onChange(index, { ...step, reason: event.target.value })}
            placeholder="Why this step exists"
          />
        </div>
      </div>

      {selectedAction?.description ? (
        <div className="empty-state mt-10">{String(selectedAction.description)}</div>
      ) : null}

      {Array.isArray(selectedAction?.inputs) && selectedAction.inputs.length ? (
        <div className="grid-2 mt-10">
          {selectedAction.inputs.map((field) => {
            const fieldName = String(field?.name || "").trim();
            if (!fieldName) return null;
            const isTextarea = MULTILINE_INPUT_FIELDS.has(fieldName.toLowerCase());
            return (
              <div key={`${step.id}-${fieldName}`}>
                <div className="muted">{toDisplay(field.label || fieldName)}</div>
                {isTextarea ? (
                  <textarea
                    className="input mt-8 mono"
                    rows={4}
                    value={step.args?.[fieldName] ?? ""}
                    placeholder={field.placeholder || ""}
                    onChange={(event) => updateArgsField(fieldName, event.target.value)}
                  />
                ) : (
                  <input
                    className="input mt-8"
                    value={step.args?.[fieldName] ?? ""}
                    placeholder={field.placeholder || ""}
                    onChange={(event) => updateArgsField(fieldName, event.target.value)}
                  />
                )}
              </div>
            );
          })}
        </div>
      ) : null}

      <div className="page-actions mt-10">
        <button type="button" className="btn secondary" onClick={resetArgsFromAction}>
          Load Action Defaults
        </button>
        <span className="muted">Use JSON below for advanced or unsupported args.</span>
      </div>

      <div className="mt-10">
        <div className="muted">Args JSON</div>
        <textarea
          className="input mt-8 mono"
          rows={6}
          value={argsText}
          onChange={(event) => {
            setArgsText(event.target.value);
            if (argsError) setArgsError("");
          }}
          spellCheck={false}
        />
        <div className="page-actions mt-8">
          <button type="button" className="btn secondary" onClick={applyArgsJson}>
            Apply Args JSON
          </button>
          {argsError ? <span className="text-danger">{argsError}</span> : null}
        </div>
      </div>
    </div>
  );
}

export default function PlaybookEditor({ playbook, onChange, actions = [] }) {
  const current = playbook && typeof playbook === "object"
    ? playbook
    : { name: "", description: "", steps: [] };
  const steps = Array.isArray(current.steps)
    ? current.steps.map((step, index) => normalizeStep(step, index))
    : [];

  const updatePlaybook = (patch) => {
    onChange({
      ...current,
      ...patch,
      steps: Array.isArray(patch.steps) ? patch.steps.map((step, index) => normalizeStep(step, index)) : steps,
    });
  };

  const updateStep = (index, nextStep) => {
    const nextSteps = steps.map((step, cursor) => (
      cursor === index ? normalizeStep(nextStep, cursor) : normalizeStep(step, cursor)
    ));
    updatePlaybook({ steps: nextSteps });
  };

  const moveStep = (index, direction) => {
    const target = index + direction;
    if (target < 0 || target >= steps.length) return;
    const nextSteps = [...steps];
    const [currentStep] = nextSteps.splice(index, 1);
    nextSteps.splice(target, 0, currentStep);
    updatePlaybook({ steps: nextSteps });
  };

  const removeStep = (index) => {
    const nextSteps = steps.filter((_, cursor) => cursor !== index);
    updatePlaybook({ steps: nextSteps });
  };

  const addStep = () => {
    const fallbackAction = actions[0] || null;
    const nextSteps = [
      ...steps,
      normalizeStep(
        {
          id: `step_${steps.length + 1}`,
          action: fallbackAction?.id || "endpoint-healthcheck",
          args: buildSampleArgs(fallbackAction),
          reason: "Custom playbook step",
        },
        steps.length
      ),
    ];
    updatePlaybook({ steps: nextSteps });
  };

  return (
    <div className="list">
      <div className="list-item readable">
        <div className="grid-2">
          <div>
            <div className="muted">Playbook Name</div>
            <input
              className="input mt-8"
              value={current.name || ""}
              onChange={(event) => updatePlaybook({ name: event.target.value })}
              placeholder="manual-playbook"
            />
          </div>
          <div>
            <div className="muted">Description</div>
            <input
              className="input mt-8"
              value={current.description || ""}
              onChange={(event) => updatePlaybook({ description: event.target.value })}
              placeholder="Describe the response workflow"
            />
          </div>
        </div>
        {(current.source?.alert_id || current.source?.case_id) ? (
          <div className="meta-line mt-10">
            Source context:
            {current.source?.alert_id ? ` alert ${current.source.alert_id}` : ""}
            {current.source?.alert_id && current.source?.case_id ? " |" : ""}
            {current.source?.case_id ? ` case ${current.source.case_id}` : ""}
          </div>
        ) : (
          <div className="meta-line mt-10">Manual playbook builder. Add any action sequence you need.</div>
        )}
      </div>

      <div className="page-actions">
        <button type="button" className="btn secondary" onClick={addStep}>
          Add Step
        </button>
        <span className="muted">{steps.length} step(s)</span>
      </div>

      {steps.length === 0 ? (
        <div className="empty-state">No steps yet. Add the first step to start building the playbook.</div>
      ) : (
        steps.map((step, index) => (
          <PlaybookStepEditor
            key={`${step.id}-${index}`}
            step={step}
            index={index}
            total={steps.length}
            actions={actions}
            onChange={updateStep}
            onMove={moveStep}
            onRemove={removeStep}
          />
        ))
      )}
    </div>
  );
}

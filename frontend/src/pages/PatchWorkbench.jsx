import { useMemo, useState } from "react";
import Actions from "./Actions";
import Playbooks from "./Playbooks";
import Scheduler from "./Scheduler";
import PatchWorkbenchShell from "./PatchWorkbenchShell";

const WORKBENCH_MODES = [
  { value: "shell", label: "Shell" },
  { value: "actions", label: "Actions" },
  { value: "playbooks", label: "Playbooks" },
  { value: "scheduler", label: "Scheduler" },
];

const MODE_SUMMARY = {
  shell: "Global shell patching flow with vulnerability context and live execution proof.",
  actions: "Action catalog with Linux/Windows-focused filtering and guarded dispatch.",
  playbooks: "Manual + AI goal playbook workflows (alert/case generation removed in min mode).",
  scheduler: "Schedule shell, action, or playbook jobs with hourly/daily/weekly/monthly/custom timing.",
};

export default function PatchWorkbench({ minMode = false }) {
  const [mode, setMode] = useState("shell");

  const activePane = useMemo(() => {
    if (!minMode) return <PatchWorkbenchShell />;
    if (mode === "actions") return <Actions />;
    if (mode === "playbooks") return <Playbooks minWorkbench />;
    if (mode === "scheduler") return <Scheduler embedded />;
    return <PatchWorkbenchShell />;
  }, [mode, minMode]);

  if (!minMode) {
    return activePane;
  }

  return (
    <div className="patch-workbench-min-router">
      <div className="card patch-workbench-switcher-card mb-18">
        <div className="card-header">
          <div>
            <h3>Min Workbench</h3>
            <p className="muted">Use a single workspace switcher for shell, actions, playbooks, and scheduling.</p>
          </div>
        </div>
        <div className="page-actions">
          <select className="input" value={mode} onChange={(event) => setMode(event.target.value)}>
            {WORKBENCH_MODES.map((item) => (
              <option key={item.value} value={item.value}>{item.label}</option>
            ))}
          </select>
        </div>
        <div className="meta-line mt-8">{MODE_SUMMARY[mode] || MODE_SUMMARY.shell}</div>
      </div>

      {activePane}
    </div>
  );
}

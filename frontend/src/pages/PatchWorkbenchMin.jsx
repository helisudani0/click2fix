import { useCallback, useState } from "react";
import ActionsMin from "./ActionsMin";
import PlaybooksMin from "./PlaybooksMin";
import SchedulerMin from "./SchedulerMin";
import PatchWorkbenchShellMin from "./PatchWorkbenchShellMin";

const WORKBENCH_MODES = [
  { value: "shell", label: "Shell" },
  { value: "actions", label: "Actions" },
  { value: "playbooks", label: "Playbooks" },
  { value: "scheduler", label: "Scheduler" },
];

const MODE_SUMMARY = {
  shell: "Run global shell with vulnerability context and live execution proof.",
  actions: "Use action catalog dispatch for Linux and Windows endpoints.",
  playbooks: "Build/load playbooks and run them without AI helpers.",
  scheduler: "Schedule shell, action, or playbook jobs with cron patterns.",
};

export default function PatchWorkbenchMin() {
  const [mode, setMode] = useState("shell");

  const renderModePane = useCallback((props = {}) => {
    if (mode === "actions") return <ActionsMin {...props} />;
    if (mode === "playbooks") return <PlaybooksMin {...props} />;
    if (mode === "scheduler") return <SchedulerMin {...props} />;
    return null;
  }, [mode]);

  return (
    <PatchWorkbenchShellMin
      mode={mode}
      modeOptions={WORKBENCH_MODES}
      modeSummary={MODE_SUMMARY}
      onModeChange={setMode}
      renderModePane={renderModePane}
    />
  );
}

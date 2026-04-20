import { useMemo, useState } from "react";
import Actions from "./Actions";
import PlaybooksMin from "./PlaybooksMin";
import Scheduler from "./Scheduler";
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

  const modePane = useMemo(() => {
    if (mode === "actions") return <Actions />;
    if (mode === "playbooks") return <PlaybooksMin />;
    if (mode === "scheduler") return <Scheduler embedded />;
    return null;
  }, [mode]);

  return (
    <PatchWorkbenchShellMin
      mode={mode}
      modeOptions={WORKBENCH_MODES}
      modeSummary={MODE_SUMMARY}
      onModeChange={setMode}
      modePane={modePane}
    />
  );
}

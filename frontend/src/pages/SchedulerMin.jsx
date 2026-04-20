import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createSchedulerJob,
  getActions,
  getAgentGroups,
  getAgents,
  getPlaybook,
  getPlaybooks,
  getSchedulerJobs,
  runSchedulerJobNow,
  updateSchedulerJob,
} from "../api/wazuh";
import RelativeTimestamp from "../components/RelativeTimestamp";
import { formatApiError } from "../utils/httpErrors";

const CONNECTED_STATUSES = new Set(["active", "connected", "online"]);
const JOB_KINDS = {
  action: "Action",
  shell: "Shell",
  playbook: "Playbook",
};
const SCHEDULE_MODES = {
  hourly: "Hourly",
  daily: "Daily",
  weekly: "Weekly",
  monthly: "Monthly",
  custom: "Custom Cron",
};
const WEEKDAY_OPTIONS = [
  { value: "0", label: "Sunday" },
  { value: "1", label: "Monday" },
  { value: "2", label: "Tuesday" },
  { value: "3", label: "Wednesday" },
  { value: "4", label: "Thursday" },
  { value: "5", label: "Friday" },
  { value: "6", label: "Saturday" },
];

const normalizeAgents = (data) => {
  if (Array.isArray(data)) return data;
  if (data?.data?.affected_items) return data.data.affected_items;
  if (data?.affected_items) return data.affected_items;
  if (data?.items) return data.items;
  return [];
};

const formatAgentId = (raw) => {
  if (raw === null || raw === undefined) return "";
  const text = String(raw).trim();
  if (!text) return "";
  return /^[0-9]+$/.test(text) && text.length < 3 ? text.padStart(3, "0") : text;
};

const toGroups = (agent) => {
  const out = [];
  const append = (value) => {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) {
      value.forEach((item) => append(item));
      return;
    }
    const text = String(value).trim();
    if (!text) return;
    if (text.includes(",")) {
      text.split(",").forEach((item) => append(item));
      return;
    }
    out.push(text);
  };
  append(agent?.group);
  append(agent?.groups);
  append(agent?.group_name);
  return Array.from(new Set(out));
};

const agentPlatform = (agent) => {
  const node = agent?.os;
  const osName = typeof node === "object" && node
    ? String(node.name || node.platform || node.full || "")
    : String(agent?.os_name || agent?.os || agent?.platform || "");
  const lowered = osName.toLowerCase();
  if (lowered.includes("windows")) return "windows";
  if (
    lowered.includes("linux")
    || lowered.includes("ubuntu")
    || lowered.includes("debian")
    || lowered.includes("centos")
    || lowered.includes("fedora")
    || lowered.includes("suse")
  ) {
    return "linux";
  }
  return "unknown";
};

const parseMaybeJsonObject = (value, fallback = {}) => {
  const text = String(value || "").trim();
  if (!text) return fallback;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
};

const clampInt = (value, min, max, fallback) => {
  const parsed = Number.parseInt(String(value || "").trim(), 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
};

const parseClockTime = (value) => {
  const text = String(value || "").trim();
  if (!text) return null;
  const twelveHourMatch = text.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (twelveHourMatch) {
    let hour = Number.parseInt(twelveHourMatch[1], 10);
    const minute = Number.parseInt(twelveHourMatch[2], 10);
    const meridiem = String(twelveHourMatch[3] || "").toUpperCase();
    if (!Number.isFinite(hour) || hour < 1 || hour > 12 || !Number.isFinite(minute) || minute < 0 || minute > 59) {
      return null;
    }
    if (meridiem === "AM") {
      if (hour === 12) hour = 0;
    } else if (hour !== 12) {
      hour += 12;
    }
    return { hour, minute };
  }
  const twentyFourMatch = text.match(/^(\d{1,2}):(\d{2})$/);
  if (twentyFourMatch) {
    const hour = Number.parseInt(twentyFourMatch[1], 10);
    const minute = Number.parseInt(twentyFourMatch[2], 10);
    if (!Number.isFinite(hour) || hour < 0 || hour > 23 || !Number.isFinite(minute) || minute < 0 || minute > 59) {
      return null;
    }
    return { hour, minute };
  }
  return null;
};

const buildCron = ({
  scheduleMode,
  hourlyEvery,
  hourlyMinute,
  timeOfDay,
  weekDay,
  monthDay,
  customCron,
}) => {
  if (scheduleMode === "hourly") {
    const every = clampInt(hourlyEvery, 1, 24, 6);
    const minute = clampInt(hourlyMinute, 0, 59, 0);
    return `${minute} */${every} * * *`;
  }
  if (scheduleMode === "custom") {
    return String(customCron || "").trim();
  }

  const parsedClock = parseClockTime(timeOfDay);
  if (!parsedClock) return "";

  if (scheduleMode === "daily") {
    return `${parsedClock.minute} ${parsedClock.hour} * * *`;
  }
  if (scheduleMode === "weekly") {
    const weekday = clampInt(weekDay, 0, 6, 1);
    return `${parsedClock.minute} ${parsedClock.hour} * * ${weekday}`;
  }
  if (scheduleMode === "monthly") {
    const day = clampInt(monthDay, 1, 28, 1);
    return `${parsedClock.minute} ${parsedClock.hour} ${day} * *`;
  }
  return "";
};

const toJob = (row) => {
  if (Array.isArray(row)) {
    const hasExtendedShape = row.length >= 11;
    return {
      id: row[0],
      name: row[1],
      playbook: row[2],
      jobKind: String(hasExtendedShape ? row?.[3] : "action").toLowerCase(),
      payload: hasExtendedShape && row?.[4] && typeof row[4] === "object" ? row[4] : {},
      target: hasExtendedShape ? row[5] : row[3],
      cron: hasExtendedShape ? row[6] : row[4],
      enabled: Boolean(hasExtendedShape ? row[7] : row[5]),
      requireApproval: Boolean(hasExtendedShape ? row[8] : row[6]),
      lastRun: hasExtendedShape ? row[9] : row[7],
      orgId: hasExtendedShape ? row[10] : row[8],
    };
  }
  return {
    id: row?.id,
    name: row?.name,
    playbook: row?.playbook,
    jobKind: String(row?.job_kind || "action").toLowerCase(),
    payload: row?.payload && typeof row.payload === "object" ? row.payload : {},
    target: row?.target,
    cron: row?.cron,
    enabled: Boolean(row?.enabled),
    requireApproval: Boolean(row?.require_approval),
    lastRun: row?.last_run,
    orgId: row?.org_id,
  };
};

const summarizePayload = (job) => {
  if (!job || typeof job !== "object") return "-";
  if (job.jobKind === "shell") {
    const command = String(job?.payload?.command || "").trim();
    return command ? command.slice(0, 86) : "Shell payload";
  }
  if (job.jobKind === "playbook") {
    const steps = Array.isArray(job?.payload?.steps) ? job.payload.steps.length : 0;
    return steps > 0 ? `${steps} step(s)` : "Playbook payload";
  }
  const args = job?.payload?.args;
  if (args && typeof args === "object") {
    const keys = Object.keys(args);
    return keys.length ? `args: ${keys.join(", ")}` : "No args";
  }
  return "No payload";
};

export default function SchedulerMin({ onExecutionCreated }) {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [schedulerRunning, setSchedulerRunning] = useState(false);

  const [actions, setActions] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);

  const [name, setName] = useState("Scheduled Job");
  const [jobKind, setJobKind] = useState("action");
  const [selectedAction, setSelectedAction] = useState("endpoint-healthcheck");
  const [actionArgsJson, setActionArgsJson] = useState("{}");

  const [shellType, setShellType] = useState("powershell");
  const [shellCommand, setShellCommand] = useState("");
  const [shellRunAsSystem, setShellRunAsSystem] = useState(false);
  const [verifyKb, setVerifyKb] = useState("");
  const [verifyMinBuild, setVerifyMinBuild] = useState("");
  const [verifyStdoutContains, setVerifyStdoutContains] = useState("");

  const [playbookMode, setPlaybookMode] = useState("saved");
  const [selectedPlaybook, setSelectedPlaybook] = useState("");
  const [customPlaybookJson, setCustomPlaybookJson] = useState(
    JSON.stringify({
      name: "scheduled-custom-playbook",
      steps: [
        {
          id: "step_1",
          action: "endpoint-healthcheck",
          args: {},
          reason: "Scheduled baseline check",
        },
      ],
    }, null, 2)
  );

  const [targetMode, setTargetMode] = useState("fleet");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [multiPickAgentId, setMultiPickAgentId] = useState("");
  const [targetSearch, setTargetSearch] = useState("");

  const [enabled, setEnabled] = useState(true);
  const [requireApproval, setRequireApproval] = useState(false);

  const [scheduleMode, setScheduleMode] = useState("hourly");
  const [hourlyEvery, setHourlyEvery] = useState("6");
  const [hourlyMinute, setHourlyMinute] = useState("0");
  const [timeOfDay, setTimeOfDay] = useState("02:00 AM");
  const [weekDay, setWeekDay] = useState("1");
  const [monthDay, setMonthDay] = useState("1");
  const [customCron, setCustomCron] = useState("0 */6 * * *");

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [jobsResponse, actionsResponse, playbooksResponse, agentsResponse, groupsResponse] = await Promise.all([
        getSchedulerJobs(),
        getActions().catch(() => ({ data: [] })),
        getPlaybooks().catch(() => ({ data: [] })),
        getAgents(undefined, { limit: 5000, compact: true, status: "active,connected,online" }).catch(() => ({ data: [] })),
        getAgentGroups().catch(() => ({ data: [] })),
      ]);
      const payload = jobsResponse?.data || {};
      setJobs(Array.isArray(payload?.jobs) ? payload.jobs.map(toJob) : []);
      setSchedulerRunning(Boolean(payload?.running));
      setActions(Array.isArray(actionsResponse?.data) ? actionsResponse.data : []);
      const playbookList = Array.isArray(playbooksResponse?.data) ? playbooksResponse.data : [];
      setPlaybooks(playbookList);
      if (!selectedPlaybook && playbookList.length) setSelectedPlaybook(String(playbookList[0] || ""));

      const normalizedAgents = normalizeAgents(agentsResponse?.data)
        .map((agent) => {
          const id = formatAgentId(agent?.id || agent?.agent_id);
          if (!id) return null;
          const resolvedGroups = toGroups(agent);
          return {
            id,
            name: String(agent?.name || agent?.hostname || id).trim(),
            status: String(agent?.status || "unknown").trim().toLowerCase(),
            groups: resolvedGroups,
            groupText: resolvedGroups.join(", "),
            platform: agentPlatform(agent),
          };
        })
        .filter(Boolean);
      setAgents(normalizedAgents);
      const groupNames = (Array.isArray(groupsResponse?.data) ? groupsResponse.data : [])
        .map((group) => String(group?.name || group?.id || group || "").trim())
        .filter(Boolean);
      setGroups(groupNames);

      setStatus("");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to load scheduler jobs."));
    } finally {
      setLoading(false);
    }
  }, [selectedPlaybook]);

  useEffect(() => {
    void load();
  }, [load]);

  const connectedAgents = useMemo(
    () => agents.filter((agent) => CONNECTED_STATUSES.has(agent.status)),
    [agents]
  );
  const selectedAgentSet = useMemo(
    () => new Set(targetAgentIds.map((id) => formatAgentId(id)).filter(Boolean)),
    [targetAgentIds]
  );
  const availableGroups = useMemo(() => {
    const names = new Set();
    groups.forEach((group) => {
      const text = String(group || "").trim();
      if (text) names.add(text);
    });
    connectedAgents.forEach((agent) => {
      (agent.groups || []).forEach((group) => {
        const text = String(group || "").trim();
        if (text) names.add(text);
      });
    });
    return Array.from(names).sort((left, right) => left.localeCompare(right));
  }, [connectedAgents, groups]);
  const filteredAgents = useMemo(() => {
    const query = String(targetSearch || "").trim().toLowerCase();
    if (!query) return connectedAgents;
    return connectedAgents.filter((agent) =>
      agent.id.toLowerCase().includes(query)
      || String(agent.name || "").toLowerCase().includes(query)
      || String(agent.groupText || "").toLowerCase().includes(query)
    );
  }, [connectedAgents, targetSearch]);
  const scopedTargets = useMemo(() => {
    const normalizedAgentId = formatAgentId(targetValue);
    const normalizedGroup = String(targetValue || "").trim().toLowerCase();
    if (targetMode === "agent") {
      if (!normalizedAgentId) return [];
      return connectedAgents.filter((agent) => agent.id === normalizedAgentId);
    }
    if (targetMode === "multi") {
      if (!selectedAgentSet.size) return [];
      return connectedAgents.filter((agent) => selectedAgentSet.has(agent.id));
    }
    if (targetMode === "group") {
      if (!normalizedGroup) return [];
      return connectedAgents.filter((agent) =>
        (agent.groups || []).some((group) => String(group || "").trim().toLowerCase() === normalizedGroup)
      );
    }
    if (targetMode === "os_windows") return connectedAgents.filter((agent) => agent.platform === "windows");
    if (targetMode === "os_linux") return connectedAgents.filter((agent) => agent.platform === "linux");
    return connectedAgents;
  }, [connectedAgents, selectedAgentSet, targetMode, targetValue]);

  const resolvedTargetExpression = useMemo(() => {
    if (targetMode === "agent") {
      const id = formatAgentId(targetValue);
      return id || "";
    }
    if (targetMode === "group") {
      const group = String(targetValue || "").trim();
      return group ? `group:${group}` : "";
    }
    if (targetMode === "multi") {
      const ids = Array.from(selectedAgentSet);
      return ids.length ? `multi:${ids.join(",")}` : "";
    }
    if (targetMode === "os_windows" || targetMode === "os_linux") {
      const ids = scopedTargets.map((agent) => agent.id);
      return ids.length ? `multi:${ids.join(",")}` : "";
    }
    return "all";
  }, [scopedTargets, selectedAgentSet, targetMode, targetValue]);

  const cronPreview = useMemo(
    () => buildCron({ scheduleMode, hourlyEvery, hourlyMinute, timeOfDay, weekDay, monthDay, customCron }),
    [customCron, hourlyEvery, hourlyMinute, monthDay, scheduleMode, timeOfDay, weekDay]
  );
  const enabledJobCount = useMemo(() => jobs.filter((job) => Boolean(job.enabled)).length, [jobs]);
  const sortedJobs = useMemo(() => [...jobs].sort((left, right) => Number(left.id || 0) - Number(right.id || 0)), [jobs]);
  const timeInputValid = useMemo(() => {
    if (scheduleMode === "hourly" || scheduleMode === "custom") return true;
    return Boolean(parseClockTime(timeOfDay));
  }, [scheduleMode, timeOfDay]);

  const submitCreate = async () => {
    try {
      if (!resolvedTargetExpression) {
        setStatus("Choose a valid scheduler target scope.");
        return;
      }
      const cron = String(cronPreview || "").trim();
      if (!cron) {
        setStatus("Provide a valid schedule first.");
        return;
      }
      if (!timeInputValid) {
        setStatus("Time format is invalid. Use hh:mm AM/PM or HH:mm.");
        return;
      }

      let playbook = "endpoint-healthcheck";
      let payload = {};

      if (jobKind === "shell") {
        if (!String(shellCommand || "").trim()) {
          setStatus("Shell jobs require a command.");
          return;
        }
        playbook = "global-shell";
        payload = {
          command: shellCommand,
          shell: shellType,
          run_as_system: Boolean(shellRunAsSystem),
          verify_kb: verifyKb,
          verify_min_build: verifyMinBuild,
          verify_stdout_contains: verifyStdoutContains,
        };
      } else if (jobKind === "playbook") {
        if (playbookMode === "saved") {
          if (!selectedPlaybook) {
            setStatus("Choose a saved playbook first.");
            return;
          }
          const playbookResponse = await getPlaybook(selectedPlaybook);
          const playbookPayload = playbookResponse?.data;
          if (!playbookPayload || typeof playbookPayload !== "object") {
            setStatus("Selected playbook payload is invalid.");
            return;
          }
          playbook = String(playbookPayload?.name || selectedPlaybook || "scheduled-playbook").trim() || "scheduled-playbook";
          payload = playbookPayload;
        } else {
          const parsedPayload = parseMaybeJsonObject(customPlaybookJson, {});
          const steps = Array.isArray(parsedPayload?.steps) ? parsedPayload.steps : [];
          if (!steps.length) {
            setStatus("Custom playbook JSON must include a non-empty steps array.");
            return;
          }
          playbook = String(parsedPayload?.name || "scheduled-custom-playbook").trim() || "scheduled-custom-playbook";
          payload = parsedPayload;
        }
      } else {
        playbook = String(selectedAction || "endpoint-healthcheck").trim() || "endpoint-healthcheck";
        payload = { args: parseMaybeJsonObject(actionArgsJson, {}) };
      }

      setStatus("Creating scheduler job...");
      await createSchedulerJob({
        name,
        job_kind: jobKind,
        playbook,
        payload,
        target: resolvedTargetExpression,
        cron,
        enabled,
        require_approval: requireApproval,
      });
      setStatus("Scheduler job created.");
      await load();
    } catch (err) {
      setStatus(formatApiError(err, "Failed to create scheduler job."));
    }
  };

  const toggleJob = async (job) => {
    try {
      const nextEnabled = !job?.enabled;
      await updateSchedulerJob(job.id, { enabled: nextEnabled });
      setStatus(`Job ${job.id} ${nextEnabled ? "enabled" : "disabled"}.`);
      await load();
    } catch (err) {
      setStatus(formatApiError(err, "Failed to toggle scheduler job."));
    }
  };

  const triggerRunNow = async (jobId) => {
    try {
      setStatus(`Running job ${jobId} now...`);
      const response = await runSchedulerJobNow(jobId);
      const executionId = Number(response?.data?.result?.execution_id || 0) || null;
      if (executionId && typeof onExecutionCreated === "function") onExecutionCreated(executionId);
      setStatus(executionId ? `Run-now triggered for job ${jobId} (execution #${executionId}).` : `Run-now triggered for job ${jobId}.`);
      await load();
    } catch (err) {
      setStatus(formatApiError(err, "Failed to run scheduler job."));
    }
  };

  const editCron = async (job) => {
    const currentCron = String(job?.cron || "").trim();
    const nextCron = window.prompt("Enter new cron expression", currentCron);
    if (!nextCron || nextCron.trim() === currentCron) return;
    try {
      await updateSchedulerJob(job.id, { cron: nextCron.trim() });
      setStatus(`Updated cron for job ${job.id}.`);
      await load();
    } catch (err) {
      setStatus(formatApiError(err, "Failed to update scheduler cron."));
    }
  };

  return (
    <div className="card patch-workbench-command-card">
      <div className="card-header">
        <div>
          <h3>4) Scheduler</h3>
          <p className="muted">Schedule shell, action, or playbook runs with reusable recurrence.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" type="button" onClick={() => void load()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Jobs</div>
          <div className="stat-value">{sortedJobs.length}</div>
          <div className="stat-sub">Configured entries</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Enabled</div>
          <div className="stat-value">{enabledJobCount}</div>
          <div className="stat-sub">Active recurring jobs</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Targets</div>
          <div className="stat-value">{scopedTargets.length}</div>
          <div className="stat-sub">Resolved in current scope</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Cron Preview</div>
          <div className="stat-value ws-normal">{cronPreview || "-"}</div>
          <div className="stat-sub">Resolved schedule expression</div>
        </div>
      </div>

      <div className="list mt-10">
        <div className="list-item readable">
          <div className="muted">Name</div>
          <input className="input mt-8" value={name} onChange={(event) => setName(event.target.value)} />
        </div>

        <div className="grid-3">
          <label className="list-item readable">
            <div className="muted">Job Type</div>
            <select className="input mt-8" value={jobKind} onChange={(event) => setJobKind(event.target.value)}>
              {Object.entries(JOB_KINDS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>
          <label className="list-item readable">
            <div className="muted">Target Scope</div>
            <select className="input mt-8" value={targetMode} onChange={(event) => setTargetMode(event.target.value)}>
              <option value="fleet">Fleet (all connected agents)</option>
              <option value="group">Group</option>
              <option value="multi">Multiple agents</option>
              <option value="agent">Single agent</option>
              <option value="os_windows">Windows agents</option>
              <option value="os_linux">Linux agents</option>
            </select>
          </label>
          <div className="list-item readable">
            <div className="muted">Resolved Target</div>
            <div className="meta-line mt-8">{resolvedTargetExpression || "-"}</div>
          </div>
        </div>

        {targetMode === "group" ? (
          <div className="list-item readable">
            <div className="muted">Group</div>
            <select className="input mt-8" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
              <option value="">Select group</option>
              {availableGroups.map((group) => (
                <option key={group} value={group}>{group}</option>
              ))}
            </select>
          </div>
        ) : null}

        {targetMode === "agent" ? (
          <div className="list-item readable">
            <div className="muted">Agent</div>
            <select className="input mt-8" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
              <option value="">Select agent</option>
              {connectedAgents.map((agent) => (
                <option key={`scheduler-agent-${agent.id}`} value={agent.id}>
                  {agent.id} - {agent.name}{agent.groupText ? ` (${agent.groupText})` : ""}
                </option>
              ))}
            </select>
          </div>
        ) : null}

        {targetMode === "multi" ? (
          <div className="list-item readable">
            <div className="muted">Multiple Agents</div>
            <div className="page-actions mt-8">
              <input
                className="input"
                value={targetSearch}
                onChange={(event) => setTargetSearch(event.target.value)}
                placeholder="Search by ID, name, group"
              />
              <select
                className="input"
                value={multiPickAgentId}
                onChange={(event) => setMultiPickAgentId(formatAgentId(event.target.value))}
              >
                <option value="">Pick connected agent</option>
                {filteredAgents.map((agent) => (
                  <option key={`scheduler-multi-${agent.id}`} value={agent.id}>
                    {agent.id} - {agent.name}
                  </option>
                ))}
              </select>
              <button
                className="btn secondary"
                type="button"
                onClick={() => {
                  if (!multiPickAgentId) return;
                  setTargetAgentIds((current) => (
                    current.includes(multiPickAgentId) ? current : [...current, multiPickAgentId]
                  ));
                  setMultiPickAgentId("");
                }}
              >
                Add
              </button>
              <button className="btn secondary" type="button" onClick={() => setTargetAgentIds(filteredAgents.map((agent) => agent.id))}>
                Select Visible
              </button>
              <button className="btn secondary" type="button" onClick={() => setTargetAgentIds([])}>
                Clear
              </button>
            </div>
            <div className="meta-line mt-8">Selected: {selectedAgentSet.size}</div>
          </div>
        ) : null}

        {jobKind === "action" ? (
          <div className="grid-2">
            <label className="list-item readable">
              <div className="muted">Action</div>
              <select className="input mt-8" value={selectedAction} onChange={(event) => setSelectedAction(event.target.value)}>
                {actions.map((action) => (
                  <option key={String(action?.id || "")} value={String(action?.id || "")}>
                    {String(action?.label || action?.id || "-")}
                  </option>
                ))}
              </select>
            </label>
            <label className="list-item readable">
              <div className="muted">Action Args JSON (optional)</div>
              <textarea className="input mono mt-8" rows={4} value={actionArgsJson} onChange={(event) => setActionArgsJson(event.target.value)} />
            </label>
          </div>
        ) : null}

        {jobKind === "shell" ? (
          <div className="grid-2">
            <label className="list-item readable">
              <div className="muted">Shell</div>
              <select className="input mt-8" value={shellType} onChange={(event) => setShellType(event.target.value)}>
                <option value="powershell">PowerShell</option>
                <option value="cmd">CMD</option>
                <option value="bash">Bash</option>
                <option value="sh">SH</option>
              </select>
              <label className="inline-check mt-8">
                <input type="checkbox" checked={shellRunAsSystem} onChange={(event) => setShellRunAsSystem(Boolean(event.target.checked))} />
                <span>Run as admin/root</span>
              </label>
            </label>
            <label className="list-item readable">
              <div className="muted">Command</div>
              <textarea className="input mono mt-8" rows={5} value={shellCommand} onChange={(event) => setShellCommand(event.target.value)} />
            </label>
            <label className="list-item readable">
              <div className="muted">Verify KB (optional)</div>
              <input className="input mt-8" value={verifyKb} onChange={(event) => setVerifyKb(event.target.value)} />
            </label>
            <label className="list-item readable">
              <div className="muted">Verify Min Build (optional)</div>
              <input className="input mt-8" value={verifyMinBuild} onChange={(event) => setVerifyMinBuild(event.target.value)} />
            </label>
            <label className="list-item readable">
              <div className="muted">Verify Output Contains (optional)</div>
              <input className="input mt-8" value={verifyStdoutContains} onChange={(event) => setVerifyStdoutContains(event.target.value)} />
            </label>
          </div>
        ) : null}

        {jobKind === "playbook" ? (
          <div className="list">
            <div className="list-item readable">
              <div className="muted">Playbook Source</div>
              <select className="input mt-8" value={playbookMode} onChange={(event) => setPlaybookMode(event.target.value)}>
                <option value="saved">Saved Playbook</option>
                <option value="custom">Custom JSON</option>
              </select>
            </div>
            {playbookMode === "saved" ? (
              <div className="list-item readable">
                <div className="muted">Saved Playbook</div>
                <select className="input mt-8" value={selectedPlaybook} onChange={(event) => setSelectedPlaybook(event.target.value)}>
                  <option value="">Select playbook</option>
                  {playbooks.map((item) => (
                    <option key={String(item)} value={String(item)}>{String(item)}</option>
                  ))}
                </select>
              </div>
            ) : (
              <div className="list-item readable">
                <div className="muted">Custom Playbook JSON</div>
                <textarea className="input mono mt-8" rows={10} value={customPlaybookJson} onChange={(event) => setCustomPlaybookJson(event.target.value)} />
              </div>
            )}
          </div>
        ) : null}

        <div className="grid-3">
          <label className="list-item readable">
            <div className="muted">Schedule Type</div>
            <select className="input mt-8" value={scheduleMode} onChange={(event) => setScheduleMode(event.target.value)}>
              {Object.entries(SCHEDULE_MODES).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>
          {scheduleMode === "hourly" ? (
            <>
              <label className="list-item readable">
                <div className="muted">Every N Hours</div>
                <input className="input mt-8" value={hourlyEvery} onChange={(event) => setHourlyEvery(event.target.value)} placeholder="6" />
              </label>
              <label className="list-item readable">
                <div className="muted">Minute Offset (0-59)</div>
                <input className="input mt-8" value={hourlyMinute} onChange={(event) => setHourlyMinute(event.target.value)} placeholder="0" />
              </label>
            </>
          ) : scheduleMode === "custom" ? (
            <label className="list-item readable">
              <div className="muted">Cron</div>
              <input className="input mt-8 mono" value={customCron} onChange={(event) => setCustomCron(event.target.value)} placeholder="0 */6 * * *" />
            </label>
          ) : (
            <>
              <label className="list-item readable">
                <div className="muted">Time</div>
                <input className="input mt-8" value={timeOfDay} onChange={(event) => setTimeOfDay(event.target.value)} placeholder="02:00 AM or 14:00" />
                {!timeInputValid ? <div className="meta-line mt-8 text-danger">Invalid format. Use hh:mm AM/PM or HH:mm.</div> : null}
              </label>
              {scheduleMode === "weekly" ? (
                <label className="list-item readable">
                  <div className="muted">Weekday</div>
                  <select className="input mt-8" value={weekDay} onChange={(event) => setWeekDay(event.target.value)}>
                    {WEEKDAY_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
              ) : null}
              {scheduleMode === "monthly" ? (
                <label className="list-item readable">
                  <div className="muted">Day of Month (1-28)</div>
                  <input className="input mt-8" value={monthDay} onChange={(event) => setMonthDay(event.target.value)} placeholder="1" />
                </label>
              ) : null}
            </>
          )}
        </div>

        <label className="list-item inline-check">
          <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(Boolean(event.target.checked))} />
          <span>Enabled</span>
        </label>
        <label className="list-item inline-check">
          <input type="checkbox" checked={requireApproval} onChange={(event) => setRequireApproval(Boolean(event.target.checked))} />
          <span>Require approval before execution</span>
        </label>

        <div className="page-actions">
          <button className="btn" type="button" onClick={() => void submitCreate()}>
            Create Job
          </button>
        </div>
      </div>

      <div className="table-scroll mt-12">
        <table className="table compact readable">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Kind</th>
              <th>Action/Playbook</th>
              <th>Payload</th>
              <th>Target</th>
              <th>Cron</th>
              <th>Enabled</th>
              <th>Last Run</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {sortedJobs.length === 0 ? (
              <tr>
                <td colSpan="10" className="text-center">No scheduled jobs found.</td>
              </tr>
            ) : (
              sortedJobs.map((job) => (
                <tr key={job.id}>
                  <td>{job.id}</td>
                  <td>{job.name || "-"}</td>
                  <td>{JOB_KINDS[job.jobKind] || job.jobKind || "-"}</td>
                  <td>{job.playbook || "-"}</td>
                  <td className="ws-normal" title={JSON.stringify(job.payload || {})}>{summarizePayload(job)}</td>
                  <td>{job.target || "-"}</td>
                  <td>{job.cron || "-"}</td>
                  <td>
                    <span className={`status-pill ${job.enabled ? "success" : "neutral"}`}>
                      {job.enabled ? "enabled" : "disabled"}
                    </span>
                  </td>
                  <td><RelativeTimestamp value={job.lastRun} /></td>
                  <td>
                    <div className="page-actions">
                      <button className="btn secondary" type="button" onClick={() => void toggleJob(job)}>
                        {job.enabled ? "Disable" : "Enable"}
                      </button>
                      <button className="btn secondary" type="button" onClick={() => void editCron(job)}>
                        Edit Cron
                      </button>
                      <button className="btn secondary" type="button" onClick={() => void triggerRunNow(job.id)}>
                        Run Now
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

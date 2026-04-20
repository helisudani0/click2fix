import { useEffect, useMemo, useState } from "react";
import {
  createSchedulerJob,
  getActions,
  getPlaybook,
  getPlaybooks,
  getSchedulerJobs,
  runSchedulerJobNow,
  updateSchedulerJob,
} from "../api/wazuh";
import RelativeTimestamp from "../components/RelativeTimestamp";
import { formatApiError } from "../utils/httpErrors";

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

const clampInt = (value, min, max, fallback) => {
  const parsed = Number.parseInt(String(value || ""), 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
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

const buildCron = ({
  scheduleMode,
  hourlyEvery,
  hourlyMinute,
  atHour,
  atMinute,
  weekDay,
  monthDay,
  customCron,
}) => {
  const minute = clampInt(atMinute, 0, 59, 0);
  const hour = clampInt(atHour, 0, 23, 0);
  if (scheduleMode === "hourly") {
    const every = clampInt(hourlyEvery, 1, 24, 1);
    const offsetMinute = clampInt(hourlyMinute, 0, 59, 0);
    return `${offsetMinute} */${every} * * *`;
  }
  if (scheduleMode === "daily") {
    return `${minute} ${hour} * * *`;
  }
  if (scheduleMode === "weekly") {
    const weekday = clampInt(weekDay, 0, 6, 1);
    return `${minute} ${hour} * * ${weekday}`;
  }
  if (scheduleMode === "monthly") {
    const day = clampInt(monthDay, 1, 28, 1);
    return `${minute} ${hour} ${day} * *`;
  }
  return String(customCron || "").trim();
};

const summarizePayload = (job) => {
  if (!job || typeof job !== "object") return "-";
  if (job.jobKind === "shell") {
    const command = String(job?.payload?.command || "").trim();
    return command ? command.slice(0, 80) : "Shell payload";
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

export default function Scheduler({ embedded = false }) {
  const [jobs, setJobs] = useState([]);
  const [schedulerRunning, setSchedulerRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [actions, setActions] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);

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
    JSON.stringify(
      {
        name: "scheduled-custom-playbook",
        steps: [
          {
            id: "step_1",
            action: "endpoint-healthcheck",
            args: {},
            reason: "Scheduled baseline check",
          },
        ],
      },
      null,
      2
    )
  );

  const [target, setTarget] = useState("all");
  const [enabled, setEnabled] = useState(true);
  const [requireApproval, setRequireApproval] = useState(false);

  const [scheduleMode, setScheduleMode] = useState("hourly");
  const [hourlyEvery, setHourlyEvery] = useState("6");
  const [hourlyMinute, setHourlyMinute] = useState("0");
  const [atHour, setAtHour] = useState("2");
  const [atMinute, setAtMinute] = useState("0");
  const [weekDay, setWeekDay] = useState("1");
  const [monthDay, setMonthDay] = useState("1");
  const [customCron, setCustomCron] = useState("0 */6 * * *");

  const load = async () => {
    try {
      setLoading(true);
      const [jobsResponse, actionsResponse, playbooksResponse] = await Promise.all([
        getSchedulerJobs(),
        getActions().catch(() => ({ data: [] })),
        getPlaybooks().catch(() => ({ data: [] })),
      ]);
      const payload = jobsResponse?.data || {};
      setJobs(Array.isArray(payload?.jobs) ? payload.jobs.map(toJob) : []);
      setSchedulerRunning(Boolean(payload?.running));
      setActions(Array.isArray(actionsResponse?.data) ? actionsResponse.data : []);
      const playbookList = Array.isArray(playbooksResponse?.data) ? playbooksResponse.data : [];
      setPlaybooks(playbookList);
      if (!selectedPlaybook && playbookList.length) {
        setSelectedPlaybook(String(playbookList[0] || ""));
      }
      setStatus("");
    } catch (err) {
      setStatus(formatApiError(err, "Failed to load scheduler jobs."));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const sortedJobs = useMemo(() => {
    const copy = [...jobs];
    copy.sort((left, right) => Number(left.id || 0) - Number(right.id || 0));
    return copy;
  }, [jobs]);

  const cronPreview = useMemo(
    () => buildCron({ scheduleMode, hourlyEvery, hourlyMinute, atHour, atMinute, weekDay, monthDay, customCron }),
    [scheduleMode, hourlyEvery, hourlyMinute, atHour, atMinute, weekDay, monthDay, customCron]
  );

  const enabledJobCount = useMemo(
    () => sortedJobs.filter((job) => Boolean(job.enabled)).length,
    [sortedJobs]
  );

  const submitCreate = async () => {
    try {
      const cron = String(cronPreview || "").trim();
      if (!cron) {
        setStatus("Provide a valid schedule first.");
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
        const parsedArgs = parseMaybeJsonObject(actionArgsJson, {});
        payload = { args: parsedArgs };
      }

      setStatus("Creating scheduler job...");
      await createSchedulerJob({
        name,
        job_kind: jobKind,
        playbook,
        payload,
        target,
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
      await runSchedulerJobNow(jobId);
      setStatus(`Run-now triggered for job ${jobId}.`);
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

  if (loading) {
    return (
      <div className={embedded ? "" : "page page-route-scheduler"}>
        <div className="empty-state">Loading scheduler jobs...</div>
      </div>
    );
  }

  return (
    <div className={embedded ? "" : "page page-route-scheduler"}>
      {!embedded ? (
        <div className="page-header">
          <div>
            <h2>Automation Jobs</h2>
            <p className="muted">Scheduler status: {schedulerRunning ? "running" : "stopped"}.</p>
          </div>
          <div className="page-actions">
            <button className="btn secondary" onClick={() => void load()}>Refresh</button>
          </div>
        </div>
      ) : (
        <div className="card-header">
          <div>
            <h3>Scheduler</h3>
            <p className="muted">Status: {schedulerRunning ? "running" : "stopped"}.</p>
          </div>
          <div className="page-actions">
            <button className="btn secondary" onClick={() => void load()}>Refresh</button>
          </div>
        </div>
      )}

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
          <div className="stat-label">Kinds</div>
          <div className="stat-value">{Object.keys(JOB_KINDS).length}</div>
          <div className="stat-sub">Action / Shell / Playbook</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Cron Preview</div>
          <div className="stat-value ws-normal">{cronPreview || "-"}</div>
          <div className="stat-sub">Resolved schedule expression</div>
        </div>
      </div>

      <div className="card mb-18">
        <div className="card-header">
          <div>
            <h3>Create Job</h3>
            <p className="muted">Schedule shell, action, or playbook runs with reusable recurrence.</p>
          </div>
        </div>

        <div className="grid-3">
          <label className="list-item">
            <div className="muted">Name</div>
            <input className="input" value={name} onChange={(event) => setName(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Job Type</div>
            <select className="input" value={jobKind} onChange={(event) => setJobKind(event.target.value)}>
              {Object.entries(JOB_KINDS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Target</div>
            <input
              className="input"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="all | 001 | group:linux | multi:001,004"
            />
          </label>
        </div>

        {jobKind === "action" ? (
          <div className="grid-2 mt-10">
            <label className="list-item">
              <div className="muted">Action</div>
              <select className="input" value={selectedAction} onChange={(event) => setSelectedAction(event.target.value)}>
                {actions.map((action) => (
                  <option key={String(action?.id || "")} value={String(action?.id || "")}>
                    {String(action?.label || action?.id || "-")}
                  </option>
                ))}
              </select>
            </label>
            <label className="list-item">
              <div className="muted">Action Args JSON (optional)</div>
              <textarea
                className="input mono"
                rows={4}
                value={actionArgsJson}
                onChange={(event) => setActionArgsJson(event.target.value)}
                placeholder='{"package":"all"}'
              />
            </label>
          </div>
        ) : null}

        {jobKind === "shell" ? (
          <div className="grid-2 mt-10">
            <label className="list-item">
              <div className="muted">Shell</div>
              <select className="input" value={shellType} onChange={(event) => setShellType(event.target.value)}>
                <option value="powershell">PowerShell</option>
                <option value="cmd">CMD</option>
                <option value="bash">Bash</option>
                <option value="sh">SH</option>
              </select>
              <label className="inline-check mt-8">
                <input
                  type="checkbox"
                  checked={shellRunAsSystem}
                  onChange={(event) => setShellRunAsSystem(Boolean(event.target.checked))}
                />
                <span>Run as admin/root</span>
              </label>
            </label>
            <label className="list-item">
              <div className="muted">Command</div>
              <textarea
                className="input mono"
                rows={5}
                value={shellCommand}
                onChange={(event) => setShellCommand(event.target.value)}
                placeholder="Example: apt-get update && apt-get upgrade -y"
              />
            </label>
            <label className="list-item">
              <div className="muted">Verify KB (optional)</div>
              <input className="input" value={verifyKb} onChange={(event) => setVerifyKb(event.target.value)} />
            </label>
            <label className="list-item">
              <div className="muted">Verify Min Build (optional)</div>
              <input className="input" value={verifyMinBuild} onChange={(event) => setVerifyMinBuild(event.target.value)} />
            </label>
            <label className="list-item">
              <div className="muted">Verify Output Contains (optional)</div>
              <input className="input" value={verifyStdoutContains} onChange={(event) => setVerifyStdoutContains(event.target.value)} />
            </label>
          </div>
        ) : null}

        {jobKind === "playbook" ? (
          <div className="list mt-10">
            <div className="list-item readable">
              <div className="muted">Playbook Source</div>
              <div className="page-actions mt-8">
                <select className="input" value={playbookMode} onChange={(event) => setPlaybookMode(event.target.value)}>
                  <option value="saved">Saved Playbook</option>
                  <option value="custom">Custom JSON</option>
                </select>
              </div>
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
                <textarea
                  className="input mono mt-8"
                  rows={10}
                  value={customPlaybookJson}
                  onChange={(event) => setCustomPlaybookJson(event.target.value)}
                />
              </div>
            )}
          </div>
        ) : null}

        <div className="grid-3 mt-10">
          <label className="list-item">
            <div className="muted">Schedule Type</div>
            <select className="input" value={scheduleMode} onChange={(event) => setScheduleMode(event.target.value)}>
              {Object.entries(SCHEDULE_MODES).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </label>

          {scheduleMode === "hourly" ? (
            <>
              <label className="list-item">
                <div className="muted">Every N Hours</div>
                <input
                  className="input"
                  type="number"
                  min="1"
                  max="24"
                  value={hourlyEvery}
                  onChange={(event) => setHourlyEvery(event.target.value)}
                />
              </label>
              <label className="list-item">
                <div className="muted">Minute Offset</div>
                <input
                  className="input"
                  type="number"
                  min="0"
                  max="59"
                  value={hourlyMinute}
                  onChange={(event) => setHourlyMinute(event.target.value)}
                />
              </label>
            </>
          ) : null}

          {scheduleMode === "daily" ? (
            <>
              <label className="list-item">
                <div className="muted">Hour (0-23)</div>
                <input className="input" type="number" min="0" max="23" value={atHour} onChange={(event) => setAtHour(event.target.value)} />
              </label>
              <label className="list-item">
                <div className="muted">Minute (0-59)</div>
                <input className="input" type="number" min="0" max="59" value={atMinute} onChange={(event) => setAtMinute(event.target.value)} />
              </label>
            </>
          ) : null}

          {scheduleMode === "weekly" ? (
            <>
              <label className="list-item">
                <div className="muted">Weekday</div>
                <select className="input" value={weekDay} onChange={(event) => setWeekDay(event.target.value)}>
                  {WEEKDAY_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label className="list-item">
                <div className="muted">Hour (0-23)</div>
                <input className="input" type="number" min="0" max="23" value={atHour} onChange={(event) => setAtHour(event.target.value)} />
              </label>
              <label className="list-item">
                <div className="muted">Minute (0-59)</div>
                <input className="input" type="number" min="0" max="59" value={atMinute} onChange={(event) => setAtMinute(event.target.value)} />
              </label>
            </>
          ) : null}

          {scheduleMode === "monthly" ? (
            <>
              <label className="list-item">
                <div className="muted">Day of Month (1-28)</div>
                <input className="input" type="number" min="1" max="28" value={monthDay} onChange={(event) => setMonthDay(event.target.value)} />
              </label>
              <label className="list-item">
                <div className="muted">Hour (0-23)</div>
                <input className="input" type="number" min="0" max="23" value={atHour} onChange={(event) => setAtHour(event.target.value)} />
              </label>
              <label className="list-item">
                <div className="muted">Minute (0-59)</div>
                <input className="input" type="number" min="0" max="59" value={atMinute} onChange={(event) => setAtMinute(event.target.value)} />
              </label>
            </>
          ) : null}

          {scheduleMode === "custom" ? (
            <label className="list-item">
              <div className="muted">Cron</div>
              <input className="input" value={customCron} onChange={(event) => setCustomCron(event.target.value)} placeholder="0 */6 * * *" />
            </label>
          ) : null}
        </div>

        <div className="list mt-10">
          <label className="list-item inline-check">
            <input type="checkbox" checked={enabled} onChange={(event) => setEnabled(Boolean(event.target.checked))} />
            <span>Enabled</span>
          </label>
          <label className="list-item inline-check">
            <input type="checkbox" checked={requireApproval} onChange={(event) => setRequireApproval(Boolean(event.target.checked))} />
            <span>Require approval before execution</span>
          </label>
          <div className="list-item readable">
            <div className="muted">Resolved Cron</div>
            <div className="meta-line mt-8">{cronPreview || "-"}</div>
          </div>
        </div>

        <div className="page-actions mt-8">
          <button className="btn" onClick={() => void submitCreate()}>Create Job</button>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Scheduled Jobs</h3>
            <p className="muted">Run now, enable/disable, or adjust cron.</p>
          </div>
        </div>
        <div className="table-scroll">
          <table className="table compact">
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
                <th>Approval</th>
                <th>Last Run</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedJobs.length === 0 ? (
                <tr>
                  <td colSpan="11" className="text-center">No scheduled jobs found.</td>
                </tr>
              ) : (
                sortedJobs.map((job) => (
                  <tr key={job.id}>
                    <td>{job.id}</td>
                    <td>{job.name || "-"}</td>
                    <td>{JOB_KINDS[job.jobKind] || job.jobKind || "-"}</td>
                    <td>{job.playbook || "-"}</td>
                    <td className="ws-normal" title={JSON.stringify(job.payload || {})}>
                      {summarizePayload(job)}
                    </td>
                    <td>{job.target || "-"}</td>
                    <td>{job.cron || "-"}</td>
                    <td>
                      <span className={`status-pill ${job.enabled ? "active" : "inactive"}`}>
                        {job.enabled ? "enabled" : "disabled"}
                      </span>
                    </td>
                    <td>{job.requireApproval ? "yes" : "no"}</td>
                    <td><RelativeTimestamp value={job.lastRun} /></td>
                    <td>
                      <div className="page-actions">
                        <button className="btn secondary" onClick={() => void toggleJob(job)}>
                          {job.enabled ? "Disable" : "Enable"}
                        </button>
                        <button className="btn secondary" onClick={() => void editCron(job)}>
                          Edit Cron
                        </button>
                        <button className="btn success" onClick={() => void triggerRunNow(job.id)}>
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
    </div>
  );
}

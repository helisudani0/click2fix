import { useEffect, useMemo, useState } from "react";
import {
  createSchedulerJob,
  getSchedulerJobs,
  runSchedulerJobNow,
  updateSchedulerJob,
} from "../api/wazuh";
import { formatWazuhTimestamp } from "../utils/time";

const toJob = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      name: row[1],
      playbook: row[2],
      target: row[3],
      cron: row[4],
      enabled: Boolean(row[5]),
      requireApproval: Boolean(row[6]),
      lastRun: row[7],
      orgId: row[8],
    };
  }
  return {
    id: row?.id,
    name: row?.name,
    playbook: row?.playbook,
    target: row?.target,
    cron: row?.cron,
    enabled: Boolean(row?.enabled),
    requireApproval: Boolean(row?.require_approval),
    lastRun: row?.last_run,
    orgId: row?.org_id,
  };
};

export default function Scheduler() {
  const [jobs, setJobs] = useState([]);
  const [schedulerRunning, setSchedulerRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");

  const [name, setName] = useState("Endpoint Health Check");
  const [playbook, setPlaybook] = useState("endpoint-healthcheck");
  const [target, setTarget] = useState("all");
  const [intervalHours, setIntervalHours] = useState("6");
  const [enabled, setEnabled] = useState(true);
  const [requireApproval, setRequireApproval] = useState(false);

  const sortedJobs = useMemo(() => {
    const copy = [...jobs];
    copy.sort((left, right) => Number(left.id || 0) - Number(right.id || 0));
    return copy;
  }, [jobs]);

  const load = async () => {
    try {
      setLoading(true);
      const response = await getSchedulerJobs();
      const payload = response?.data || {};
      const normalized = Array.isArray(payload?.jobs)
        ? payload.jobs.map(toJob)
        : [];
      setJobs(normalized);
      setSchedulerRunning(Boolean(payload?.running));
      setStatus("");
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const submitCreate = async () => {
    try {
      setStatus("Creating scheduler job...");
      const interval = Number(intervalHours || 0);
      await createSchedulerJob({
        name,
        playbook,
        target,
        interval_hours: Number.isFinite(interval) && interval > 0 ? interval : 6,
        enabled,
        require_approval: requireApproval,
      });
      setStatus("Scheduler job created.");
      await load();
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  const toggleJob = async (job) => {
    try {
      const nextEnabled = !job?.enabled;
      await updateSchedulerJob(job.id, { enabled: nextEnabled });
      setStatus(`Job ${job.id} ${nextEnabled ? "enabled" : "disabled"}.`);
      await load();
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  const triggerRunNow = async (jobId) => {
    try {
      setStatus(`Running job ${jobId} now...`);
      await runSchedulerJobNow(jobId);
      setStatus(`Run-now triggered for job ${jobId}.`);
      await load();
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
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
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  if (loading) return <div className="page">Loading scheduler jobs...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Automation Jobs</h2>
          <p className="muted">
            Scheduler status: {schedulerRunning ? "running" : "stopped"}.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={load}>Refresh</button>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}

      <div className="card mb-18">
        <div className="card-header">
          <div>
            <h3>Create Job</h3>
            <p className="muted">Uses `POST /scheduler/jobs` with interval-to-cron conversion.</p>
          </div>
        </div>
        <div className="grid-3">
          <label className="list-item">
            <div className="muted">Name</div>
            <input className="input" value={name} onChange={(event) => setName(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Playbook/Action</div>
            <input className="input" value={playbook} onChange={(event) => setPlaybook(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Target</div>
            <input className="input" value={target} onChange={(event) => setTarget(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Interval Hours</div>
            <input
              className="input"
              type="number"
              min="1"
              value={intervalHours}
              onChange={(event) => setIntervalHours(event.target.value)}
            />
          </label>
          <label className="list-item">
            <div className="muted">Enabled</div>
            <select
              className="input"
              value={enabled ? "true" : "false"}
              onChange={(event) => setEnabled(event.target.value === "true")}
            >
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Require Approval</div>
            <select
              className="input"
              value={requireApproval ? "true" : "false"}
              onChange={(event) => setRequireApproval(event.target.value === "true")}
            >
              <option value="false">false</option>
              <option value="true">true</option>
            </select>
          </label>
        </div>
        <div className="page-actions mt-8">
          <button className="btn" onClick={submitCreate}>Create Job</button>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Scheduled Jobs</h3>
            <p className="muted">Lifecycle actions use `/scheduler/jobs` + `/run-now`.</p>
          </div>
        </div>
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Playbook</th>
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
                  <td colSpan="9" className="text-center">No scheduled jobs found.</td>
                </tr>
              ) : (
                sortedJobs.map((job) => (
                  <tr key={job.id}>
                    <td>{job.id}</td>
                    <td>{job.name || "-"}</td>
                    <td>{job.playbook || "-"}</td>
                    <td>{job.target || "-"}</td>
                    <td>{job.cron || "-"}</td>
                    <td>
                      <span className={`pill ${job.enabled ? "active" : "inactive"}`}>
                        {job.enabled ? "enabled" : "disabled"}
                      </span>
                    </td>
                    <td>{job.requireApproval ? "yes" : "no"}</td>
                    <td>{formatWazuhTimestamp(job.lastRun)}</td>
                    <td>
                      <div className="page-actions">
                        <button className="btn secondary" onClick={() => toggleJob(job)}>
                          {job.enabled ? "Disable" : "Enable"}
                        </button>
                        <button className="btn secondary" onClick={() => editCron(job)}>
                          Edit Cron
                        </button>
                        <button className="btn success" onClick={() => triggerRunNow(job.id)}>
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

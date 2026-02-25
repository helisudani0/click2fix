import { useEffect, useState } from "react";
import api from "../api/client";

export default function Scheduler() {
  const [jobs, setJobs] = useState([]);
  const [schedulerRunning, setSchedulerRunning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      setLoading(true);
      const response = await api.get("/scheduler");
      const payload = response?.data;
      if (Array.isArray(payload)) {
        setJobs(payload);
        setSchedulerRunning(true);
      } else {
        setJobs(Array.isArray(payload?.jobs) ? payload.jobs : []);
        setSchedulerRunning(Boolean(payload?.running));
      }
      setError(null);
    } catch (err) {
      console.error("Failed to load scheduler jobs:", err);
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const toggleJob = async (jobId) => {
    try {
      await api.post(`/scheduler/${jobId}/toggle`, {});
      await load();
    } catch (err) {
      console.error("Failed to toggle job:", err);
      alert("Failed to toggle job: " + (err.response?.data?.detail || err.message));
    }
  };

  if (loading) return <div>Loading scheduler jobs...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Automation Jobs</h2>
          <p className="muted">
            Scheduled playbooks and their execution cadence.
            {" "}
            {schedulerRunning ? "Scheduler running." : "Scheduler stopped."}
          </p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={load}>Refresh</button>
        </div>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Playbook</th>
            <th>Target</th>
            <th>Cron</th>
            <th>Enabled</th>
          </tr>
        </thead>

          <tbody>
            {jobs.length === 0 ? (
              <tr>
                <td colSpan="5" className="text-center">
                No scheduled jobs found
              </td>
              </tr>
            ) : (
            jobs.map((j) => {
              const id = j?.id ?? j?.[0];
              const name = j?.name ?? j?.[1];
              const playbook = j?.playbook ?? j?.[2];
              const target = j?.target ?? j?.[3];
              const cron = j?.cron ?? j?.[4];
              const enabled = typeof j?.enabled === "boolean" ? j.enabled : Boolean(j?.[5]);
              return (
              <tr key={id}>
                <td>{name}</td>
                <td>{playbook}</td>
                <td>{target}</td>
                <td>{cron}</td>
                <td>
                  <button className="btn secondary" onClick={() => toggleJob(id)}>
                    {enabled ? "Disable" : "Enable"}
                  </button>
                </td>
              </tr>
            )})
          )}
        </tbody>
      </table>
    </div>
  );
}

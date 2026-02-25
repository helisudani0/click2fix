import { useCallback, useEffect, useMemo, useState } from "react";
import { getExecutions } from "../api/wazuh";
import ExecutionStream from "../components/ExecutionStream";
import Pager from "../components/Pager";
import { formatWazuhTimestamp, parseWazuhTimestamp } from "../utils/time";

const executionRow = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      agent: row[1],
      action: row[2],
      status: row[3],
      approvedBy: row[4],
      startedAt: row[5],
      finishedAt: row[6],
    };
  }
  return {
    id: row?.id,
    agent: row?.agent,
    action: row?.action || row?.playbook || row?.coalesce || row?.coalesce_1,
    status: row?.status,
    approvedBy: row?.approved_by,
    startedAt: row?.started_at,
    finishedAt: row?.finished_at,
  };
};

const statusTone = (status) => {
  const value = String(status || "").toUpperCase();
  if (value === "SUCCESS") return "success";
  if (["FAILED", "ERROR", "KILLED"].includes(value)) return "failed";
  if (["RUNNING", "PAUSED", "PENDING", "QUEUED", "CANCELLED"].includes(value)) return "pending";
  return "neutral";
};

const formatDuration = (start, end) => {
  const started = parseWazuhTimestamp(start);
  if (!started) return "-";
  const finished = parseWazuhTimestamp(end) || new Date();
  const ms = Math.max(0, finished.getTime() - started.getTime());
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  const hours = Math.floor(sec / 3600);
  const minutes = Math.floor((sec % 3600) / 60);
  return `${hours}h ${minutes}m`;
};

export default function Executions() {
  const [runs, setRuns] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [executionSearch, setExecutionSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [queuePage, setQueuePage] = useState(1);
  const [queuePageSize, setQueuePageSize] = useState(50);

  const load = useCallback((force = false) => {
    setLoading(true);
    getExecutions({ limit: 400 }, { force })
      .then((r) => {
        const data = Array.isArray(r.data) ? r.data : [];
        setRuns(data);
        setSelected((prev) => {
          if (prev && data.some((row) => Number(executionRow(row).id) === Number(prev))) {
            return prev;
          }
          const first = data.length ? executionRow(data[0]) : null;
          return first?.id || null;
        });
        setLoading(false);
      })
      .catch((err) => {
        setError(err.response?.data?.detail || err.message || "Failed to load execution history");
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const parsedRuns = useMemo(() => runs.map((row) => executionRow(row)), [runs]);

  const filteredRuns = useMemo(() => {
    const query = executionSearch.trim().toLowerCase();
    return parsedRuns.filter((run) => {
      const matchesQuery =
        !query ||
        String(run.id).toLowerCase().includes(query) ||
        String(run.agent || "").toLowerCase().includes(query) ||
        String(run.action || "").toLowerCase().includes(query) ||
        String(run.approvedBy || "").toLowerCase().includes(query);
      const matchesStatus = !statusFilter || String(run.status || "").toUpperCase() === statusFilter;
      return matchesQuery && matchesStatus;
    });
  }, [parsedRuns, executionSearch, statusFilter]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredRuns.length / queuePageSize));
    if (queuePage > totalPages) {
      setQueuePage(totalPages);
    }
  }, [filteredRuns.length, queuePage, queuePageSize]);

  const pagedRuns = useMemo(() => {
    const start = (queuePage - 1) * queuePageSize;
    return filteredRuns.slice(start, start + queuePageSize);
  }, [filteredRuns, queuePage, queuePageSize]);

  const selectedRun = useMemo(
    () => filteredRuns.find((run) => Number(run.id) === Number(selected)) || parsedRuns.find((run) => Number(run.id) === Number(selected)) || null,
    [filteredRuns, parsedRuns, selected]
  );

  const summary = useMemo(() => {
    const totals = {
      total: parsedRuns.length,
      running: 0,
      failed: 0,
      success: 0,
      other: 0,
    };
    parsedRuns.forEach((run) => {
      const status = String(run.status || "").toUpperCase();
      if (status === "SUCCESS") totals.success += 1;
      else if (["FAILED", "ERROR", "KILLED"].includes(status)) totals.failed += 1;
      else if (["RUNNING", "PAUSED", "PENDING", "QUEUED"].includes(status)) totals.running += 1;
      else totals.other += 1;
    });
    return totals;
  }, [parsedRuns]);

  if (loading) return <div className="empty-state">Loading execution workspace...</div>;
  if (error) return <div className="empty-state">Error: {error}</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Execution Operations Workspace</h2>
          <p className="muted">Track active automation, inspect outputs, and verify response outcomes.</p>
        </div>
        <div className="page-actions">
          <input
            className="input"
            value={executionSearch}
            onChange={(e) => setExecutionSearch(e.target.value)}
            placeholder="Search by run ID, action, agent, or approver..."
          />
          <select className="input" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All statuses</option>
            <option value="RUNNING">RUNNING</option>
            <option value="PAUSED">PAUSED</option>
            <option value="PENDING">PENDING</option>
            <option value="QUEUED">QUEUED</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="FAILED">FAILED</option>
            <option value="KILLED">KILLED</option>
            <option value="CANCELLED">CANCELLED</option>
          </select>
          <button className="btn secondary" onClick={() => load(true)}>
            Refresh
          </button>
        </div>
      </div>

      <div className="mission-grid">
        <div className="mission-card">
          <div className="mission-label">Total Runs</div>
          <div className="mission-value">{summary.total}</div>
          <div className="mission-meta">Execution records available</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Running</div>
          <div className="mission-value">{summary.running}</div>
          <div className="mission-meta">Active or queued orchestration</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Successful</div>
          <div className="mission-value">{summary.success}</div>
          <div className="mission-meta">Completed without failure</div>
        </div>
        <div className="mission-card">
          <div className="mission-label">Failed</div>
          <div className="mission-value">{summary.failed}</div>
          <div className="mission-meta">Require analyst follow-up</div>
        </div>
      </div>

      <div className="split-view">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Execution Queue</h3>
              <p className="muted">Select a run for live stream and forensic detail.</p>
            </div>
          </div>
          <div className="table-scroll">
            <table className="table compact readable">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Status</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Approved By</th>
                  <th>Started</th>
                  <th>Finished</th>
                </tr>
              </thead>
              <tbody>
                {filteredRuns.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="text-center">
                      No executions found.
                    </td>
                  </tr>
                ) : (
                  pagedRuns.map((run) => (
                    <tr
                      key={run.id}
                      onClick={() => setSelected(run.id)}
                      className={`clickable ${Number(selected) === Number(run.id) ? "selected" : ""}`}
                    >
                      <td>{run.id}</td>
                      <td>
                        <span className={`status-pill ${statusTone(run.status)}`}>{run.status || "-"}</span>
                      </td>
                      <td>{run.action || "-"}</td>
                      <td>{run.agent || "-"}</td>
                      <td>{run.approvedBy || "-"}</td>
                      <td>{formatWazuhTimestamp(run.startedAt)}</td>
                      <td>{formatWazuhTimestamp(run.finishedAt)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <Pager
            total={filteredRuns.length}
            page={queuePage}
            pageSize={queuePageSize}
            onPageChange={setQueuePage}
            onPageSizeChange={(size) => {
              setQueuePageSize(size);
              setQueuePage(1);
            }}
            pageSizeOptions={[25, 50, 100]}
            label="executions"
          />
        </div>

        <div className="panel-stack">
          {selectedRun ? (
            <>
              <div className="card">
                <div className="card-header">
                  <div>
                    <h3>Run Snapshot</h3>
                    <p className="muted">Core metadata for the selected execution.</p>
                  </div>
                </div>
                <div className="kv-grid">
                  <div className="kv-row">
                    <span className="kv-key">Execution ID</span>
                    <span className="kv-value">{selectedRun.id}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Status</span>
                    <span className="kv-value">
                      <span className={`status-pill ${statusTone(selectedRun.status)}`}>{selectedRun.status || "-"}</span>
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Action</span>
                    <span className="kv-value">{selectedRun.action || "-"}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Target</span>
                    <span className="kv-value">{selectedRun.agent || "-"}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Approved By</span>
                    <span className="kv-value">{selectedRun.approvedBy || "-"}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Started At</span>
                    <span className="kv-value">{formatWazuhTimestamp(selectedRun.startedAt)}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Finished At</span>
                    <span className="kv-value">{formatWazuhTimestamp(selectedRun.finishedAt)}</span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Runtime</span>
                    <span className="kv-value">{formatDuration(selectedRun.startedAt, selectedRun.finishedAt)}</span>
                  </div>
                </div>
              </div>
              <ExecutionStream executionId={selectedRun.id} title={`Execution #${selectedRun.id}`} />
            </>
          ) : (
            <div className="empty-state">Select an execution to inspect output and step telemetry.</div>
          )}
        </div>
      </div>
    </div>
  );
}

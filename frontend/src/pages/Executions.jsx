import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { getExecutionAiTriage, getExecutionDetail, getExecutions } from "../api/wazuh";
import ExecutionStream from "../components/ExecutionStream";
import Pager from "../components/Pager";
import RelativeTimestamp from "../components/RelativeTimestamp";
import { parseWazuhTimestamp } from "../utils/time";
import { formatApiError } from "../utils/httpErrors";

const EXECUTION_FETCH_LIMIT = 120;

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
      targetTotal: 0,
      targetCompleted: 0,
      targetSuccess: 0,
      targetFailed: 0,
      batchSize: 0,
      summary: null,
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
    targetTotal: Number(row?.target_total || row?.summary?.total || 0),
    targetCompleted: Number(row?.target_completed || row?.summary?.completed || row?.target_count || 0),
    targetSuccess: Number(row?.target_success || row?.summary?.success || 0),
    targetFailed: Number(row?.target_failed || row?.summary?.failed || 0),
    batchSize: Number(row?.batch_size || row?.summary?.batch_size || 0),
    summary: row?.summary || null,
  };
};

const statusTone = (status) => {
  const value = String(status || "").toUpperCase();
  if (value === "SUCCESS") return "success";
  if (["FAILED", "ERROR", "KILLED"].includes(value)) return "failed";
  if (["RUNNING", "PAUSED", "PENDING", "PENDING_VERIFICATION", "QUEUED", "CANCELLED", "PARTIAL"].includes(value)) return "pending";
  return "neutral";
};

const progressSummary = (run) => {
  const total = Math.max(0, Number(run?.summary?.total || run?.targetTotal || 0));
  const completed = Math.max(0, Number(run?.summary?.completed || run?.targetCompleted || 0));
  const success = Math.max(0, Number(run?.summary?.success || run?.targetSuccess || 0));
  const failed = Math.max(0, Number(run?.summary?.failed || run?.targetFailed || Math.max(completed - success, 0)));
  const remaining = Math.max(0, Number(run?.summary?.remaining || Math.max(total - completed, 0)));
  const percentComplete = total > 0
    ? Math.round((completed / total) * 100)
    : Number(run?.summary?.percent_complete || 0);
  const final = Boolean(run?.summary?.final || run?.finishedAt);
  return {
    total,
    completed,
    success,
    failed,
    remaining,
    percentComplete,
    final,
    show: total > 1,
    label: total > 0 ? `${success}/${total}` : "0/0",
  };
};

const isLaggingRun = (run) => {
  if (!run || run.finishedAt) return false;
  const status = String(run.status || "").toUpperCase();
  if (!["QUEUED", "RUNNING", "PARTIAL", "PENDING", "PENDING_VERIFICATION", "PAUSED"].includes(status)) return false;
  const started = parseWazuhTimestamp(run.startedAt);
  if (!started) return false;
  return Date.now() - started.getTime() >= 10000;
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

const middleMaskToken = (value) => {
  const text = String(value || "").trim();
  if (!text) return "";
  if (text.length <= 12) return text;
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
};

const summarizeTarget = (value) => {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  return raw
    .split(",")
    .map((part) => middleMaskToken(part))
    .filter(Boolean)
    .join(", ");
};

export default function Executions() {
  const location = useLocation();
  const [runs, setRuns] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detailMode, setDetailMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [executionSearch, setExecutionSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [queuePage, setQueuePage] = useState(1);
  const [queuePageSize, setQueuePageSize] = useState(15);
  const [aiTriage, setAiTriage] = useState(null);
  const [aiTriageLoading, setAiTriageLoading] = useState(false);
  const [aiTriageError, setAiTriageError] = useState("");

  const prefillExecutionId = useMemo(() => {
    const fromState = location?.state?.prefillExecutionId;
    const fromQuery = new URLSearchParams(location?.search || "").get("run");
    const raw = fromState ?? fromQuery;
    const parsed = Number(String(raw || "").trim());
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  }, [location?.search, location?.state]);

  const initialLoadRef = useRef(true);
  const loadInFlightRef = useRef(false);
  const load = useCallback((force = false) => {
    if (loadInFlightRef.current) return;
    loadInFlightRef.current = true;
    if (initialLoadRef.current) setLoading(true);
    getExecutions({ limit: EXECUTION_FETCH_LIMIT }, { force })
      .then((r) => {
        const data = (Array.isArray(r.data) ? r.data : []).map((row) => executionRow(row));
        setRuns(data);
        setSelected((prev) => {
          if (prev && data.some((row) => Number(row.id) === Number(prev))) {
            return prev;
          }
          const first = data.length ? data[0] : null;
          return first?.id || null;
        });
        if (initialLoadRef.current) {
          setLoading(false);
          initialLoadRef.current = false;
        }
      })
      .catch((err) => {
        setError(formatApiError(err, "Failed to load execution history"));
        if (initialLoadRef.current) {
          setLoading(false);
          initialLoadRef.current = false;
        }
      })
      .finally(() => {
        loadInFlightRef.current = false;
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!prefillExecutionId) return;
    setExecutionSearch("");
    setStatusFilter("");
    setQueuePage(1);
    setSelected(prefillExecutionId);
  }, [prefillExecutionId]);

  useEffect(() => {
    if (!prefillExecutionId) return;
    let attempts = 0;
    const maxAttempts = 10;
    const timer = window.setInterval(() => {
      attempts += 1;
      load(true);
      if (attempts >= maxAttempts) {
        window.clearInterval(timer);
      }
    }, 1200);
    load(true);
    return () => window.clearInterval(timer);
  }, [load, prefillExecutionId]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      load(true);
    }, 8000);
    return () => window.clearInterval(timer);
  }, [load]);

  const parsedRuns = useMemo(() => runs, [runs]);

  useEffect(() => {
    if (!prefillExecutionId) return;
    if (!parsedRuns.some((run) => Number(run.id) === Number(prefillExecutionId))) return;
    setSelected(prefillExecutionId);
  }, [prefillExecutionId, parsedRuns]);

  useEffect(() => {
    if (!prefillExecutionId) return;
    if (parsedRuns.some((run) => Number(run.id) === Number(prefillExecutionId))) return;
    let active = true;
    getExecutionDetail(prefillExecutionId)
      .then((res) => {
        if (!active) return;
        const detail = res?.data?.execution;
        if (!detail || typeof detail !== "object") return;
        const normalizedDetail = executionRow(detail);
        setRuns((current) => {
          if (current.some((row) => Number(row.id) === Number(prefillExecutionId))) {
            return current;
          }
          return [normalizedDetail, ...current];
        });
        setSelected(prefillExecutionId);
      })
      .catch(() => {
        // Ignore and wait for the next queue refresh cycle.
      });
    return () => {
      active = false;
    };
  }, [parsedRuns, prefillExecutionId]);

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

  useEffect(() => {
    if (!selectedRun) setDetailMode(false);
  }, [selectedRun]);

  useEffect(() => {
    setAiTriage(null);
    setAiTriageError("");
    setAiTriageLoading(false);
  }, [selectedRun?.id]);

  useEffect(() => {
    if (!prefillExecutionId || !selectedRun) return;
    if (Number(selectedRun.id) !== Number(prefillExecutionId)) return;
    setDetailMode(true);
  }, [prefillExecutionId, selectedRun]);

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
      else if (status === "PARTIAL" && run.finishedAt) totals.other += 1;
      else if (["RUNNING", "PAUSED", "PENDING", "PENDING_VERIFICATION", "QUEUED", "PARTIAL"].includes(status)) totals.running += 1;
      else totals.other += 1;
    });
    return totals;
  }, [parsedRuns]);

  const handleAiTriage = async () => {
    if (!selectedRun?.id) return;
    setAiTriageLoading(true);
    setAiTriageError("");
    try {
      const res = await getExecutionAiTriage(selectedRun.id);
      setAiTriage(res?.data || null);
    } catch (err) {
      setAiTriage(null);
      setAiTriageError(formatApiError(err, "Unable to generate AI execution triage right now."));
    } finally {
      setAiTriageLoading(false);
    }
  };

  if (loading) return <div className="page page-route-executions"><div className="empty-state">Loading execution workspace...</div></div>;
  if (error) return <div className="page page-route-executions"><div className="empty-state">Error: {error}</div></div>;

  return (
    <div className="page page-route-executions">
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
            <option value="PENDING_VERIFICATION">PENDING_VERIFICATION</option>
            <option value="QUEUED">QUEUED</option>
            <option value="PARTIAL">PARTIAL</option>
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

      {detailMode && selectedRun ? (
        <div className="card ticketing-detail-full">
          <div className="ticketing-detail-header">
            <div>
              <h3>Execution #{selectedRun.id}</h3>
              <p className="muted">{selectedRun.action || "-"} | {selectedRun.agent || "-"}</p>
            </div>
            <div className="ticketing-detail-actions">
              <button className="btn secondary" onClick={() => setDetailMode(false)}>
                Back to Queue
              </button>
              <button className="btn secondary" onClick={handleAiTriage} disabled={aiTriageLoading}>
                {aiTriageLoading ? "Analyzing..." : "AI Triage"}
              </button>
              <button className="btn secondary" onClick={() => load(true)}>
                Refresh
              </button>
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
              <span className="kv-value"><RelativeTimestamp value={selectedRun.startedAt} /></span>
            </div>
            <div className="kv-row">
              <span className="kv-key">Finished At</span>
              <span className="kv-value"><RelativeTimestamp value={selectedRun.finishedAt} /></span>
            </div>
            <div className="kv-row">
              <span className="kv-key">Runtime</span>
              <span className="kv-value">{formatDuration(selectedRun.startedAt, selectedRun.finishedAt)}</span>
            </div>
          </div>
          <details className="ticketing-detail-section" open>
            <summary>AI Triage</summary>
            {aiTriageError ? <div className="empty-state">{aiTriageError}</div> : null}
            {!aiTriage && !aiTriageError ? (
              <div className="empty-state">Run AI Triage to summarize probable root causes and next actions.</div>
            ) : null}
            {aiTriage ? (
              <div className="mt-8">
                <div className="meta-line ws-normal">{aiTriage.summary || "-"}</div>
                <div className="kv-grid mt-8">
                  <div className="kv-row">
                    <span className="kv-key">Root Causes</span>
                    <span className="kv-value">
                      {Array.isArray(aiTriage.root_causes) && aiTriage.root_causes.length
                        ? aiTriage.root_causes.join(" | ")
                        : "-"}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Recommended Actions</span>
                    <span className="kv-value">
                      {Array.isArray(aiTriage.recommended_actions) && aiTriage.recommended_actions.length
                        ? aiTriage.recommended_actions.join(" | ")
                        : "-"}
                    </span>
                  </div>
                  <div className="kv-row">
                    <span className="kv-key">Token Usage</span>
                    <span className="kv-value">
                      {Number(aiTriage?.usage?.total_tokens || 0) > 0
                        ? `${Number(aiTriage.usage.total_tokens)} total`
                        : "-"}
                    </span>
                  </div>
                </div>
              </div>
            ) : null}
          </details>
          <details className="ticketing-detail-section" open>
            <summary>Execution Stream</summary>
            <ExecutionStream executionId={selectedRun.id} />
          </details>
        </div>
      ) : (
        <div className="card ticketing-table-card">
          <div className="card-header">
            <div>
              <h3>Execution Queue</h3>
              <p className="muted">Select a run for live stream and forensic detail.</p>
            </div>
            <div className="page-actions">
              <span className="muted">{filteredRuns.length} visible runs</span>
            </div>
          </div>
          <div className="table-scroll execution-queue-scroll">
            <table className="table compact readable execution-queue-table">
              <thead>
                <tr>
                  <th className="execution-col-id">ID</th>
                  <th className="execution-col-status">Status</th>
                  <th className="execution-col-action">Action</th>
                  <th className="execution-col-target">Target</th>
                  <th className="execution-col-approver">Approved By</th>
                  <th className="execution-col-time">Started</th>
                  <th className="execution-col-time">Finished</th>
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
                  pagedRuns.map((run) => {
                    const summaryState = progressSummary(run);
                    const lagging = isLaggingRun(run);
                    return (
                      <tr
                        key={run.id}
                        onClick={() => {
                          setSelected(run.id);
                          setDetailMode(true);
                        }}
                        className={`clickable ${Number(selected) === Number(run.id) ? "selected" : ""}`}
                      >
                        <td className="execution-col-id">{run.id}</td>
                        <td className="execution-col-status">
                          <div className="execution-status-stack">
                            <span className={`status-pill ${statusTone(run.status)}${lagging ? " lagging" : ""}`}>{run.status || "-"}</span>
                            {summaryState.show ? (
                              <div className="fraction-progress">
                                <div className="fraction-progress-bar">
                                  <span className="fraction-progress-segment success" style={{ width: `${summaryState.total ? (summaryState.success / summaryState.total) * 100 : 0}%` }} />
                                  <span className="fraction-progress-segment failed" style={{ width: `${summaryState.total ? (summaryState.failed / summaryState.total) * 100 : 0}%` }} />
                                  <span className="fraction-progress-segment remaining" style={{ width: `${summaryState.total ? (summaryState.remaining / summaryState.total) * 100 : 0}%` }} />
                                </div>
                                <div className="fraction-progress-meta">
                                  <span>{summaryState.success}/{summaryState.total} success</span>
                                  <span>{summaryState.failed} failed</span>
                                  <span>{summaryState.percentComplete}% processed</span>
                                </div>
                              </div>
                            ) : null}
                            {lagging ? <span className="lag-indicator">Lagging, platform alive</span> : null}
                          </div>
                        </td>
                        <td className="execution-col-action" title={run.action || "-"}>
                          <span className="execution-cell-text execution-action-text">{run.action || "-"}</span>
                        </td>
                        <td className="execution-col-target" title={run.agent || "-"}>
                          <span className="execution-cell-text execution-target-text">{summarizeTarget(run.agent || "-")}</span>
                        </td>
                        <td className="execution-col-approver" title={run.approvedBy || "-"}>
                          <span className="execution-cell-text">{run.approvedBy || "-"}</span>
                        </td>
                        <td className="execution-col-time"><RelativeTimestamp value={run.startedAt} /></td>
                        <td className="execution-col-time"><RelativeTimestamp value={run.finishedAt} /></td>
                      </tr>
                    );
                  })
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
            pageSizeOptions={[15, 25, 50]}
            label="executions"
          />
        </div>
      )}
    </div>
  );
}


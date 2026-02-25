import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import api from "../api/client";
import { formatWazuhTimestamp } from "../utils/time";

export default function Cases() {
  const [cases, setCases] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [attackPath, setAttackPath] = useState([]);
  const [attachments, setAttachments] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [custody, setCustody] = useState([]);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [iocGraph, setIocGraph] = useState({ nodes: [], edges: [] });
  const [detailLoading, setDetailLoading] = useState(false);
  const [note, setNote] = useState("");
  const [statusValue, setStatusValue] = useState("OPEN");
  const [riskScore, setRiskScore] = useState("");
  const [riskImpact, setRiskImpact] = useState("medium");
  const [file, setFile] = useState(null);
  const [evidenceFile, setEvidenceFile] = useState(null);
  const [evidenceLabel, setEvidenceLabel] = useState("");
  const [evidenceCategory, setEvidenceCategory] = useState("");
  const [evidenceNotes, setEvidenceNotes] = useState("");
  const [timelineFilter, setTimelineFilter] = useState("");
  const [caseSearch, setCaseSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [newCaseTitle, setNewCaseTitle] = useState("");
  const [newCaseDesc, setNewCaseDesc] = useState("");
  const [newAlertId, setNewAlertId] = useState("");
  const [createStatus, setCreateStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedCaseParam = searchParams.get("case") || "";

  const loadCases = async () => {
    try {
      setLoading(true);
      const response = await api.get("/cases");
      setCases(response.data);
      setError(null);
    } catch (err) {
      console.error("Failed to load cases:", err);
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const loadCaseDetail = async (caseId, eventType = timelineFilter) => {
    setDetailLoading(true);
    try {
      const [detailRes, timelineRes] = await Promise.all([
        api.get(`/cases/${caseId}`),
        api.get(`/cases/${caseId}/timeline`, {
          params: eventType ? { event_type: eventType } : undefined
        })
      ]);
      setDetail(detailRes.data);
      setTimeline(timelineRes.data || []);
      const risk = detailRes.data?.risk;
      if (risk) {
        setRiskScore(risk[0] ?? "");
        setRiskImpact(risk[1] || "medium");
      } else {
        setRiskScore("");
        setRiskImpact("medium");
      }
      const [attackRes, attachmentsRes] = await Promise.all([
        api.get(`/cases/${caseId}/attack-path`),
        api.get(`/cases/${caseId}/attachments`)
      ]);
      setAttackPath(attackRes.data || []);
      setAttachments(attachmentsRes.data || []);
      const [evidenceRes, graphRes] = await Promise.all([
        api.get(`/cases/${caseId}/evidence`),
        api.get(`/cases/${caseId}/ioc-graph`)
      ]);
      setEvidence(evidenceRes.data || []);
      setIocGraph(graphRes.data || { nodes: [], edges: [] });
      const currentStatus = detailRes.data?.case?.[3];
      if (currentStatus) {
        setStatusValue(currentStatus);
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setDetailLoading(false);
    }
  };

  const createCase = async () => {
    setCreateStatus("");
    if (!newCaseTitle.trim()) {
      setCreateStatus("Case title is required.");
      return;
    }
    try {
      const res = await api.post("/cases", null, {
        params: {
          title: newCaseTitle,
          description: newCaseDesc || "Investigation case"
        }
      });
      const caseId = res.data?.id;
      if (caseId && newAlertId) {
        await api.post(`/cases/${caseId}/alerts`, null, {
          params: { alert_id: newAlertId }
        });
      }
      setNewCaseTitle("");
      setNewCaseDesc("");
      setNewAlertId("");
      setCreateStatus(caseId ? `Case ${caseId} created.` : "Case created.");
      await loadCases();
      if (caseId) {
        setSearchParams({ case: String(caseId) });
      }
    } catch (err) {
      setCreateStatus(err.response?.data?.detail || err.message);
    }
  };

  useEffect(() => {
    if (!requestedCaseParam || cases.length === 0) return;
    const match = cases.find((c) => String(c[0]) === String(requestedCaseParam));
    if (!match) return;
    const id = Number(match[0]);
    if (selectedId === id) return;
    setSelectedId(id);
    setSelectedEvidence(null);
    setCustody([]);
    loadCaseDetail(id);
  }, [requestedCaseParam, cases, selectedId]);

  const submitNote = async () => {
    if (!note.trim() || !selectedId) return;
    try {
      await api.post(`/cases/${selectedId}/notes`, null, {
        params: { note }
      });
      setNote("");
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const updateStatus = async () => {
    if (!selectedId) return;
    try {
      await api.post(`/cases/${selectedId}/status`, null, {
        params: { status: statusValue }
      });
      await loadCaseDetail(selectedId);
      await loadCases();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const updateRisk = async () => {
    if (!selectedId) return;
    try {
      await api.post(`/cases/${selectedId}/risk`, {
        risk_score: riskScore === "" ? null : Number(riskScore),
        impact: riskImpact
      });
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const uploadAttachment = async () => {
    if (!selectedId || !file) return;
    try {
      const form = new FormData();
      form.append("file", file);
      await api.post(`/cases/${selectedId}/attachments`, form, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      setFile(null);
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const downloadAttachment = async (attachment) => {
    if (!selectedId) return;
    try {
      const id = attachment[0];
      const filename = attachment[1];
      const res = await api.get(`/cases/${selectedId}/attachments/${id}`, {
        responseType: "blob"
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename || "attachment");
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const uploadEvidence = async () => {
    if (!selectedId || !evidenceFile) return;
    try {
      const form = new FormData();
      form.append("file", evidenceFile);
      if (evidenceLabel) form.append("label", evidenceLabel);
      if (evidenceCategory) form.append("category", evidenceCategory);
      if (evidenceNotes) form.append("notes", evidenceNotes);
      await api.post(`/cases/${selectedId}/evidence`, form, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      setEvidenceFile(null);
      setEvidenceLabel("");
      setEvidenceCategory("");
      setEvidenceNotes("");
      await loadCaseDetail(selectedId);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const downloadEvidence = async (item) => {
    if (!selectedId) return;
    try {
      const id = item[0];
      const filename = item[1];
      const res = await api.get(`/cases/${selectedId}/evidence/${id}/download`, {
        responseType: "blob"
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename || "evidence");
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const loadCustody = async (item) => {
    if (!selectedId) return;
    try {
      const id = item[0];
      setSelectedEvidence(item);
      const res = await api.get(`/cases/${selectedId}/evidence/${id}/custody`);
      setCustody(res.data || []);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const exportTimeline = (format) => {
    if (!selectedId) return;
    const params = new URLSearchParams();
    if (timelineFilter) {
      params.append("event_type", timelineFilter);
    }
    params.append("format", format);
    window.open(`/api/cases/${selectedId}/timeline/export?${params.toString()}`, "_blank");
  };

  const timelineTypes = [
    "",
    "case_created",
    "alert_attached",
    "approval_requested",
    "approval_approved",
    "approval_rejected",
    "execution_started",
    "execution_finished",
    "action_executed",
    "note_added",
    "status_changed",
    "attachment_added",
    "evidence_added",
    "evidence_locked",
    "risk_updated"
  ];

  const statusClass = (status) => {
    if (!status) return "neutral";
    if (status === "RESOLVED" || status === "CLOSED") return "success";
    if (status === "IN_PROGRESS") return "pending";
    return "neutral";
  };

  const filteredCases = cases.filter((c) => {
    const id = String(c[0] ?? "");
    const title = String(c[1] ?? "").toLowerCase();
    const status = String(c[3] ?? "");
    const owner = String(c[4] ?? "").toLowerCase();
    const query = caseSearch.trim().toLowerCase();
    const matchesQuery =
      !query ||
      id.includes(query) ||
      title.includes(query) ||
      owner.includes(query);
    const matchesStatus = !statusFilter || status === statusFilter;
    return matchesQuery && matchesStatus;
  });

  const caseStats = cases.reduce(
    (acc, c) => {
      const status = String(c[3] || "OPEN");
      acc.total += 1;
      acc[status] = (acc[status] || 0) + 1;
      return acc;
    },
    { total: 0, OPEN: 0, IN_PROGRESS: 0, RESOLVED: 0, CLOSED: 0 }
  );

  const lockEvidence = async (item) => {
    if (!selectedId) return;
    try {
      const id = item[0];
      await api.post(`/cases/${selectedId}/evidence/${id}/lock`);
      await loadCaseDetail(selectedId);
      await loadCustody(item);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const renderGraph = () => {
    const nodes = iocGraph.nodes || [];
    const edges = iocGraph.edges || [];
    if (nodes.length === 0) {
      return <div className="empty-state">No IOC graph data yet.</div>;
    }

    const columns = {
      case: [],
      alert: [],
      ioc: []
    };
    nodes.forEach((n) => {
      const key = columns[n.type] ? n.type : "ioc";
      columns[key].push(n);
    });

    const columnOrder = ["case", "alert", "ioc"];
    const columnX = { case: 80, alert: 340, ioc: 600 };
    const rowGap = 70;
    const nodeRadius = 18;
    const maxRows = Math.max(
      columns.case.length,
      columns.alert.length,
      columns.ioc.length,
      1
    );
    const height = maxRows * rowGap + 40;

    const positions = {};
    columnOrder.forEach((col) => {
      columns[col].forEach((node, idx) => {
        positions[node.id] = {
          x: columnX[col],
          y: 30 + idx * rowGap
        };
      });
    });

    return (
      <svg width="100%" height={height}>
        {edges.map((e, idx) => {
          const src = positions[e.source];
          const tgt = positions[e.target];
          if (!src || !tgt) return null;
          return (
            <line
              key={`${e.source}-${e.target}-${idx}`}
              x1={src.x}
              y1={src.y}
              x2={tgt.x}
              y2={tgt.y}
              stroke="var(--muted)"
              strokeWidth="2"
              opacity="0.7"
            />
          );
        })}
        {nodes.map((n) => {
          const pos = positions[n.id];
          if (!pos) return null;
          const fill =
            n.type === "case" ? "var(--accent-2)" : n.type === "alert" ? "var(--accent-3)" : "var(--success)";
          return (
            <g key={n.id}>
              <circle cx={pos.x} cy={pos.y} r={nodeRadius} fill={fill} />
              <text
                x={pos.x + 28}
                y={pos.y + 5}
                fill="var(--text)"
                fontSize="12"
              >
                {n.label}
              </text>
            </g>
          );
        })}
      </svg>
    );
  };

  if (loading) return <div>Loading cases...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Cases</h2>
          <p className="muted">Investigation pipeline and current case load.</p>
        </div>
        <div className="page-actions">
          <input
            className="input"
            value={caseSearch}
            onChange={(e) => setCaseSearch(e.target.value)}
            placeholder="Search by title, owner, or ID"
          />
          <select
            className="input"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="IN_PROGRESS">IN_PROGRESS</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="CLOSED">CLOSED</option>
          </select>
          <button className="btn secondary" onClick={loadCases}>Refresh</button>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>New Case</h3>
              <p className="muted">Log an incident and link an alert if needed.</p>
            </div>
          </div>
          <div className="list">
            <div className="list-item">
              <div className="muted">Case title</div>
              <input
                className="input"
                value={newCaseTitle}
                onChange={(e) => setNewCaseTitle(e.target.value)}
                placeholder="Suspicious login investigation"
              />
            </div>
            <div className="list-item">
              <div className="muted">Description</div>
              <textarea
                className="input"
                value={newCaseDesc}
                onChange={(e) => setNewCaseDesc(e.target.value)}
                placeholder="Capture the scope and initial context."
              />
            </div>
            <div className="list-item">
              <div className="muted">Link alert (optional)</div>
              <input
                className="input"
                value={newAlertId}
                onChange={(e) => setNewAlertId(e.target.value)}
                placeholder="Alert ID"
              />
            </div>
            <div className="list-item">
              <button className="btn" onClick={createCase}>Create Case</button>
            </div>
            {createStatus && <div className="empty-state">{createStatus}</div>}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Case Overview</h3>
              <p className="muted">Status distribution for active investigations.</p>
            </div>
          </div>
          <div className="kpi-grid">
            <div className="kpi-card">
              <div className="kpi-label">Total</div>
              <div className="kpi-value">{caseStats.total}</div>
              <div className="kpi-meta">All cases</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Open</div>
              <div className="kpi-value">{caseStats.OPEN}</div>
              <div className="kpi-meta">Awaiting triage</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">In Progress</div>
              <div className="kpi-value">{caseStats.IN_PROGRESS}</div>
              <div className="kpi-meta">Active response</div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Resolved</div>
              <div className="kpi-value">{caseStats.RESOLVED}</div>
              <div className="kpi-meta">Mitigated</div>
            </div>
          </div>
        </div>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Status</th>
            <th>Owner</th>
            <th>Created</th>
          </tr>
        </thead>

        <tbody>
          {filteredCases.length === 0 ? (
            <tr>
              <td colSpan="5" className="text-center">
                No cases found
              </td>
            </tr>
          ) : (
            filteredCases.map(c => (
              <tr
                key={c[0]}
                onClick={() => {
                  setSelectedId(c[0]);
                  setSelectedEvidence(null);
                  setCustody([]);
                  loadCaseDetail(c[0]);
                  setSearchParams({ case: String(c[0]) });
                }}
                className={`clickable ${selectedId === c[0] ? "selected" : ""}`}
              >
                <td>{c[0]}</td>
                <td>{c[1]}</td>
                <td>
                  <span className={`status-pill ${statusClass(c[3])}`}>{c[3]}</span>
                </td>
                <td>{c[4]}</td>
                <td>{formatWazuhTimestamp(c[5])}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      {selectedId && (
        <div className="grid-2 mt-24">
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Case Detail</h3>
                <p className="muted">Context, alerts, and notes.</p>
              </div>
            </div>
            {detailLoading ? (
              <div className="empty-state">Loading details...</div>
            ) : detail ? (
              <div className="list">
                <div className="list-item">
                  <strong>{detail.case?.[1]}</strong>
                  <div className="muted">Status: {detail.case?.[3]}</div>
                  <div className="muted">Owner: {detail.case?.[4]}</div>
                </div>
                <div className="list-item">
                  <div className="muted">Update Status</div>
                  <div className="page-actions mt-8">
                    <select
                      className="input"
                      value={statusValue}
                      onChange={(e) => setStatusValue(e.target.value)}
                    >
                      <option value="OPEN">OPEN</option>
                      <option value="IN_PROGRESS">IN_PROGRESS</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="CLOSED">CLOSED</option>
                    </select>
                    <button className="btn" onClick={updateStatus}>
                      Save
                    </button>
                  </div>
                </div>
                <div className="list-item">
                  <div className="muted">Risk & Impact</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      type="number"
                      min="0"
                      max="100"
                      placeholder="Risk score (0-100)"
                      value={riskScore}
                      onChange={(e) => setRiskScore(e.target.value)}
                    />
                    <select
                      className="input"
                      value={riskImpact}
                      onChange={(e) => setRiskImpact(e.target.value)}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                    <button className="btn secondary" onClick={updateRisk}>
                      Update Risk
                    </button>
                  </div>
                </div>
                <div className="list-item">
                  <div className="muted">Linked Alerts</div>
                  {detail.alerts?.length ? (
                    <ul className="list">
                      {detail.alerts.map((a, i) => (
                        <li key={i} className="list-item">{a[0]}</li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No alerts linked.</div>
                  )}
                </div>
                <div className="list-item">
                  <div className="muted">Notes</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      placeholder="Add a note..."
                    />
                    <button className="btn secondary" onClick={submitNote}>
                      Add Note
                    </button>
                  </div>
                  {detail.notes?.length ? (
                    <ul className="list">
                      {detail.notes.map((n, i) => (
                        <li key={i} className="list-item">
                          <div>{n[1]}</div>
                          <div className="muted">{n[0]} - {formatWazuhTimestamp(n[2])}</div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No notes.</div>
                  )}
                </div>
                <div className="list-item">
                  <div className="muted">Attachments</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      type="file"
                      onChange={(e) => setFile(e.target.files?.[0] || null)}
                    />
                    <button className="btn secondary" onClick={uploadAttachment}>
                      Upload
                    </button>
                  </div>
                  {attachments.length ? (
                    <ul className="list">
                      {attachments.map((a) => (
                        <li key={a[0]} className="list-item">
                          <div>{a[1]}</div>
                          <div className="muted">
                            {a[3]} bytes - {a[5]} - {formatWazuhTimestamp(a[6])}
                          </div>
                          <button className="btn secondary" onClick={() => downloadAttachment(a)}>
                            Download
                          </button>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No attachments.</div>
                  )}
                </div>
                <div className="list-item">
                  <div className="muted">Evidence Locker</div>
                  <div className="page-actions mt-8">
                    <input
                      className="input"
                      type="file"
                      onChange={(e) => setEvidenceFile(e.target.files?.[0] || null)}
                    />
                    <input
                      className="input"
                      value={evidenceLabel}
                      onChange={(e) => setEvidenceLabel(e.target.value)}
                      placeholder="Label"
                    />
                    <input
                      className="input"
                      value={evidenceCategory}
                      onChange={(e) => setEvidenceCategory(e.target.value)}
                      placeholder="Category"
                    />
                    <input
                      className="input"
                      value={evidenceNotes}
                      onChange={(e) => setEvidenceNotes(e.target.value)}
                      placeholder="Notes"
                    />
                    <button className="btn secondary" onClick={uploadEvidence}>
                      Upload Evidence
                    </button>
                  </div>
                  {evidence.length ? (
                    <ul className="list">
                      {evidence.map((ev) => (
                        <li key={ev[0]} className="list-item">
                          <div>
                            <strong>{ev[5] || ev[1]}</strong>
                          </div>
                          <div className="muted">
                            {ev[3]} bytes - {ev[4]} - {formatWazuhTimestamp(ev[10])}
                          </div>
                          <div className="page-actions mt-8">
                            <button className="btn secondary" onClick={() => downloadEvidence(ev)}>
                              Download
                            </button>
                            <button className="btn" onClick={() => loadCustody(ev)}>
                              Custody
                            </button>
                            <button
                              className="btn danger"
                              onClick={() => lockEvidence(ev)}
                              disabled={ev[9]}
                            >
                              {ev[9] ? "Locked" : "Lock"}
                            </button>
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="empty-state">No evidence yet.</div>
                  )}
                </div>
              </div>
            ) : (
              <div className="empty-state">Select a case to view details.</div>
            )}
          </div>
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Timeline</h3>
                <p className="muted">Case actions and approvals.</p>
              </div>
              <div className="page-actions">
                <select
                  className="input"
                  value={timelineFilter}
                  onChange={(e) => {
                    const value = e.target.value;
                    setTimelineFilter(value);
                    if (selectedId) {
                      loadCaseDetail(selectedId, value);
                    }
                  }}
                >
                  {timelineTypes.map((t) => (
                    <option key={t || "all"} value={t}>
                      {t ? t.replace(/_/g, " ") : "All events"}
                    </option>
                  ))}
                </select>
                <button className="btn secondary" onClick={() => exportTimeline("csv")}>
                  Export CSV
                </button>
                <button className="btn" onClick={() => exportTimeline("json")}>
                  Export JSON
                </button>
              </div>
            </div>
            {detailLoading ? (
              <div className="empty-state">Loading timeline...</div>
            ) : timeline.length === 0 ? (
              <div className="empty-state">No timeline events.</div>
            ) : (
              <ul className="list">
                {timeline.map((e) => (
                  <li key={e[0]} className="list-item">
                    <strong>{e[1]}</strong>
                    <div className="muted">{formatWazuhTimestamp(e[4])}</div>
                    {e[2] && <div>{e[2]}</div>}
                    {e[3] && <div className="muted">Actor: {e[3]}</div>}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {selectedId && (
        <div className="card mt-24">
          <div className="card-header">
            <div>
              <h3>Attack Path</h3>
              <p className="muted">MITRE-mapped path inferred from linked alerts.</p>
            </div>
          </div>
          {detailLoading ? (
            <div className="empty-state">Loading attack path...</div>
          ) : attackPath.length === 0 ? (
            <div className="empty-state">No attack path data yet.</div>
          ) : (
            <ul className="list">
              {attackPath.map((step, idx) => (
                <li key={`${step[0]}-${idx}`} className="list-item">
                  <strong>Step {idx + 1}</strong>
                  <div className="muted">{step[1]}</div>
                  <div>
                    {step[2] ? `${step[2]} - ${step[3]} (${step[4]})` : `Alert ${step[0]}`}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {selectedEvidence && (
        <div className="card mt-24">
          <div className="card-header">
            <div>
              <h3>Chain of Custody</h3>
              <p className="muted">Evidence access and custody log.</p>
            </div>
          </div>
          {custody.length === 0 ? (
            <div className="empty-state">No custody events yet.</div>
          ) : (
            <ul className="list">
              {custody.map((e) => (
                <li key={e[0]} className="list-item">
                  <strong>{e[1]}</strong>
                  <div className="muted">{e[4]}</div>
                  {e[2] && <div className="muted">Actor: {e[2]}</div>}
                  {e[3] && <div>{e[3]}</div>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {selectedId && (
        <div className="card mt-24">
          <div className="card-header">
            <div>
              <h3>IOC Graph</h3>
              <p className="muted">Case - alerts - IOCs relationship map.</p>
            </div>
          </div>
          {detailLoading ? (
            <div className="empty-state">Loading IOC graph...</div>
          ) : (
            renderGraph()
          )}
        </div>
      )}
    </div>
  );
}

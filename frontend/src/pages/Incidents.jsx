import { useEffect, useMemo, useState } from "react";
import {
  assignIncident,
  correlateIncidents,
  getIncidents,
  updateIncident,
} from "../api/wazuh";
import { formatWazuhTimestamp } from "../utils/time";

const STATUS_OPTIONS = ["open", "investigate", "contain", "verified", "closed"];
const PRIORITY_OPTIONS = ["critical", "high", "medium", "low"];
const ESCALATION_OPTIONS = ["normal", "watch", "escalated"];
const DUE_STATE_OPTIONS = ["", "none", "on_track", "due_soon", "overdue"];

const toText = (value) => String(value || "").trim();

export default function Incidents() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [selectedId, setSelectedId] = useState(null);
  const [statusMsg, setStatusMsg] = useState("");
  const [loading, setLoading] = useState(true);

  const [filterStatus, setFilterStatus] = useState("");
  const [filterOwner, setFilterOwner] = useState("");
  const [filterPriority, setFilterPriority] = useState("");
  const [filterDueState, setFilterDueState] = useState("");

  const [editTitle, setEditTitle] = useState("");
  const [editSummary, setEditSummary] = useState("");
  const [editStatus, setEditStatus] = useState("open");
  const [editPriority, setEditPriority] = useState("medium");
  const [editOwner, setEditOwner] = useState("");
  const [editDueAt, setEditDueAt] = useState("");
  const [editEscalation, setEditEscalation] = useState("normal");
  const [assignmentNote, setAssignmentNote] = useState("");

  const [assignOwner, setAssignOwner] = useState("");
  const [assignNote, setAssignNote] = useState("");
  const [assignDueAt, setAssignDueAt] = useState("");

  const [lookbackHours, setLookbackHours] = useState("24");
  const [timeWindowMinutes, setTimeWindowMinutes] = useState("120");
  const [minGroupSize, setMinGroupSize] = useState("2");
  const [minScore, setMinScore] = useState("2");
  const [persist, setPersist] = useState(true);
  const [correlationResult, setCorrelationResult] = useState(null);

  const selectedIncident = useMemo(
    () => items.find((item) => Number(item?.id) === Number(selectedId)) || null,
    [items, selectedId],
  );

  const loadIncidents = async () => {
    try {
      setLoading(true);
      const response = await getIncidents({
        status: filterStatus || undefined,
        owner: filterOwner || undefined,
        priority: filterPriority || undefined,
        due_state: filterDueState || undefined,
        include_alerts: true,
        include_history: true,
        history_limit: 20,
        limit: 100,
        offset: 0,
      });
      const payload = response?.data || {};
      const rows = Array.isArray(payload?.items) ? payload.items : [];
      setItems(rows);
      setTotal(Number(payload?.total || rows.length || 0));
      if (rows.length === 0) {
        setSelectedId(null);
      } else if (!rows.some((item) => Number(item?.id) === Number(selectedId))) {
        setSelectedId(rows[0]?.id || null);
      }
      setStatusMsg("");
    } catch (err) {
      setStatusMsg(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  useEffect(() => {
    if (!selectedIncident) return;
    setEditTitle(toText(selectedIncident.title));
    setEditSummary(toText(selectedIncident.summary));
    setEditStatus(toText(selectedIncident.status || "open").toLowerCase() || "open");
    setEditPriority(toText(selectedIncident.priority || "medium").toLowerCase() || "medium");
    setEditOwner(toText(selectedIncident.owner));
    setEditDueAt(toText(selectedIncident.due_at));
    setEditEscalation(toText(selectedIncident.escalation_state || "normal").toLowerCase() || "normal");
    setAssignmentNote("");
    setAssignOwner(toText(selectedIncident.owner));
    setAssignNote("");
    setAssignDueAt(toText(selectedIncident.due_at));
  }, [selectedIncident]);

  const applyFilters = async () => {
    await loadIncidents();
  };

  const saveIncident = async () => {
    if (!selectedIncident?.id) return;
    try {
      setStatusMsg(`Updating incident ${selectedIncident.id}...`);
      await updateIncident(selectedIncident.id, {
        title: editTitle || undefined,
        summary: editSummary || undefined,
        status: editStatus,
        priority: editPriority,
        owner: editOwner || null,
        due_at: editDueAt || null,
        escalation_state: editEscalation,
        assignment_note: assignmentNote || undefined,
      });
      setStatusMsg(`Incident ${selectedIncident.id} updated.`);
      await loadIncidents();
    } catch (err) {
      setStatusMsg(err.response?.data?.detail || err.message);
    }
  };

  const reassignIncident = async () => {
    if (!selectedIncident?.id) return;
    if (!toText(assignOwner)) {
      setStatusMsg("Assignee is required.");
      return;
    }
    try {
      setStatusMsg(`Assigning incident ${selectedIncident.id}...`);
      await assignIncident(selectedIncident.id, {
        owner: assignOwner,
        note: assignNote || undefined,
        due_at: assignDueAt || undefined,
      });
      setStatusMsg(`Incident ${selectedIncident.id} assigned to ${assignOwner}.`);
      await loadIncidents();
    } catch (err) {
      setStatusMsg(err.response?.data?.detail || err.message);
    }
  };

  const runCorrelation = async () => {
    try {
      setStatusMsg("Running correlation...");
      const response = await correlateIncidents({
        lookback_hours: Number(lookbackHours || 24),
        time_window_minutes: Number(timeWindowMinutes || 120),
        min_group_size: Number(minGroupSize || 2),
        min_correlation_score: Number(minScore || 2),
        persist,
      });
      const payload = response?.data || {};
      setCorrelationResult(payload);
      setStatusMsg(
        `Correlation done: ${Number(payload?.correlated_groups || 0)} group(s), ${Number(payload?.created_incidents || 0)} created.`,
      );
      await loadIncidents();
    } catch (err) {
      setStatusMsg(err.response?.data?.detail || err.message);
    }
  };

  if (loading) return <div className="page">Loading incident queue...</div>;

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Incident Queue</h2>
          <p className="muted">Correlated incidents with assignment and SLA workflow state.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={loadIncidents}>Refresh</button>
        </div>
      </div>

      {statusMsg ? <div className="empty-state">{statusMsg}</div> : null}

      <div className="card mb-18">
        <div className="card-header">
          <div>
            <h3>Filters</h3>
            <p className="muted">Queue total: {total}</p>
          </div>
        </div>
        <div className="grid-4">
          <label className="list-item">
            <div className="muted">Status</div>
            <select className="input" value={filterStatus} onChange={(event) => setFilterStatus(event.target.value)}>
              <option value="">All</option>
              {STATUS_OPTIONS.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Owner</div>
            <input className="input" value={filterOwner} onChange={(event) => setFilterOwner(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Priority</div>
            <select className="input" value={filterPriority} onChange={(event) => setFilterPriority(event.target.value)}>
              <option value="">All</option>
              {PRIORITY_OPTIONS.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Due State</div>
            <select className="input" value={filterDueState} onChange={(event) => setFilterDueState(event.target.value)}>
              {DUE_STATE_OPTIONS.map((option) => (
                <option key={option || "all"} value={option}>
                  {option || "All"}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="page-actions mt-8">
          <button className="btn" onClick={applyFilters}>Apply Filters</button>
        </div>
      </div>

      <div className="card mb-18">
        <div className="card-header">
          <div>
            <h3>Correlation</h3>
            <p className="muted">Create/update incidents from alert overlap signals.</p>
          </div>
        </div>
        <div className="grid-4">
          <label className="list-item">
            <div className="muted">Lookback Hours</div>
            <input className="input" type="number" min="1" value={lookbackHours} onChange={(event) => setLookbackHours(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Time Window (min)</div>
            <input className="input" type="number" min="5" value={timeWindowMinutes} onChange={(event) => setTimeWindowMinutes(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Min Group Size</div>
            <input className="input" type="number" min="2" value={minGroupSize} onChange={(event) => setMinGroupSize(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Min Score</div>
            <input className="input" type="number" min="1" value={minScore} onChange={(event) => setMinScore(event.target.value)} />
          </label>
        </div>
        <div className="page-actions mt-8">
          <button className="btn" onClick={runCorrelation}>Run Correlation</button>
          <label className="list-item" style={{ minWidth: 180 }}>
            <div className="muted">Persist Incidents</div>
            <select className="input" value={persist ? "true" : "false"} onChange={(event) => setPersist(event.target.value === "true")}>
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          </label>
        </div>
        {correlationResult?.groups?.length ? (
          <div className="table-scroll h-260 mt-8">
            <table className="table compact">
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Incident</th>
                  <th>Alerts</th>
                  <th>Priority</th>
                  <th>Signals</th>
                  <th>Agents</th>
                </tr>
              </thead>
              <tbody>
                {correlationResult.groups.map((group) => (
                  <tr key={group.group_id}>
                    <td>{group.group_id}</td>
                    <td>{group.incident_id || "-"}</td>
                    <td>{group.alert_count}</td>
                    <td>{group.priority}</td>
                    <td>{Array.isArray(group.signals) ? group.signals.join(", ") : "-"}</td>
                    <td>{Array.isArray(group.agents) ? group.agents.join(", ") : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Incidents</h3>
              <p className="muted">Select an incident to update workflow fields.</p>
            </div>
          </div>
          <div className="table-scroll h-56vh">
            <table className="table compact">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Priority</th>
                  <th>Owner</th>
                  <th>Due</th>
                  <th>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="text-center">No incidents in queue.</td>
                  </tr>
                ) : (
                  items.map((item) => (
                    <tr
                      key={item.id}
                      className={Number(item.id) === Number(selectedId) ? "selected clickable" : "clickable"}
                      onClick={() => setSelectedId(item.id)}
                    >
                      <td>{item.id}</td>
                      <td>{item.title || "-"}</td>
                      <td>{item.status}</td>
                      <td>{item.priority}</td>
                      <td>{item.owner || "-"}</td>
                      <td>{formatWazuhTimestamp(item.due_at)}</td>
                      <td>{item.alert_count || 0}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Incident Detail</h3>
              <p className="muted">{selectedIncident ? `Incident ${selectedIncident.id}` : "Select an incident."}</p>
            </div>
          </div>
          {selectedIncident ? (
            <div className="list-scroll tall">
              <div className="list">
                <label className="list-item">
                  <div className="muted">Title</div>
                  <input className="input" value={editTitle} onChange={(event) => setEditTitle(event.target.value)} />
                </label>
                <label className="list-item">
                  <div className="muted">Summary</div>
                  <textarea className="input" value={editSummary} onChange={(event) => setEditSummary(event.target.value)} />
                </label>
                <div className="grid-2">
                  <label className="list-item">
                    <div className="muted">Status</div>
                    <select className="input" value={editStatus} onChange={(event) => setEditStatus(event.target.value)}>
                      {STATUS_OPTIONS.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </label>
                  <label className="list-item">
                    <div className="muted">Priority</div>
                    <select className="input" value={editPriority} onChange={(event) => setEditPriority(event.target.value)}>
                      {PRIORITY_OPTIONS.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </label>
                </div>
                <div className="grid-2">
                  <label className="list-item">
                    <div className="muted">Owner</div>
                    <input className="input" value={editOwner} onChange={(event) => setEditOwner(event.target.value)} />
                  </label>
                  <label className="list-item">
                    <div className="muted">Escalation</div>
                    <select className="input" value={editEscalation} onChange={(event) => setEditEscalation(event.target.value)}>
                      {ESCALATION_OPTIONS.map((option) => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </label>
                </div>
                <label className="list-item">
                  <div className="muted">Due At (ISO UTC)</div>
                  <input className="input" value={editDueAt} onChange={(event) => setEditDueAt(event.target.value)} />
                </label>
                <label className="list-item">
                  <div className="muted">Assignment Note</div>
                  <textarea className="input" value={assignmentNote} onChange={(event) => setAssignmentNote(event.target.value)} />
                </label>
                <div className="page-actions">
                  <button className="btn" onClick={saveIncident}>Save Incident</button>
                </div>

                <div className="list-item">
                  <div className="muted">Reassign Owner</div>
                  <div className="grid-2 mt-8">
                    <input className="input" placeholder="owner" value={assignOwner} onChange={(event) => setAssignOwner(event.target.value)} />
                    <input className="input" placeholder="due_at (optional)" value={assignDueAt} onChange={(event) => setAssignDueAt(event.target.value)} />
                  </div>
                  <textarea className="input mt-8" placeholder="note" value={assignNote} onChange={(event) => setAssignNote(event.target.value)} />
                  <div className="page-actions mt-8">
                    <button className="btn secondary" onClick={reassignIncident}>Assign</button>
                  </div>
                </div>

                <div className="list-item">
                  <div className="muted">Linked Alerts</div>
                  <div className="table-scroll h-180 mt-8">
                    <table className="table compact">
                      <thead>
                        <tr>
                          <th>Alert</th>
                          <th>Agent</th>
                          <th>Tactic</th>
                          <th>Signals</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(selectedIncident.alerts || []).length === 0 ? (
                          <tr>
                            <td colSpan="4" className="text-center">No linked alerts.</td>
                          </tr>
                        ) : (
                          (selectedIncident.alerts || []).map((alert) => (
                            <tr key={`${alert.alert_id}-${alert.attached_at || ""}`}>
                              <td>{alert.alert_id}</td>
                              <td>{alert.agent_id || "-"}</td>
                              <td>{alert.tactic || "-"}</td>
                              <td>{Array.isArray(alert.matched_signals) ? alert.matched_signals.join(", ") : "-"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="list-item">
                  <div className="muted">SLA Events</div>
                  <div className="table-scroll h-180 mt-8">
                    <table className="table compact">
                      <thead>
                        <tr>
                          <th>Event</th>
                          <th>Detail</th>
                          <th>Actor</th>
                          <th>Created</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(selectedIncident.sla_events || []).length === 0 ? (
                          <tr>
                            <td colSpan="4" className="text-center">No SLA history.</td>
                          </tr>
                        ) : (
                          (selectedIncident.sla_events || []).map((event, index) => (
                            <tr key={`${event.event_type}-${event.created_at || index}`}>
                              <td>{event.event_type}</td>
                              <td>{event.detail || "-"}</td>
                              <td>{event.actor || "-"}</td>
                              <td>{formatWazuhTimestamp(event.created_at)}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="empty-state">Select an incident from the queue.</div>
          )}
        </div>
      </div>
    </div>
  );
}

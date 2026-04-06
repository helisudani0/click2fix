import { useCallback, useEffect, useMemo, useState } from "react";
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

const LOOKBACK_HOUR_OPTIONS = [6, 12, 24, 48, 72, 168];
const TIME_WINDOW_MINUTE_OPTIONS = [30, 60, 120, 180, 240, 360];
const MIN_GROUP_SIZE_OPTIONS = [2, 3, 4, 5, 8, 10];
const MIN_SCORE_OPTIONS = [1, 2, 3, 4, 5, 6];
const DUE_SHORTCUT_OPTIONS = [
  { value: "", label: "No shortcut" },
  { value: "in_4h", label: "Due in 4 hours" },
  { value: "in_24h", label: "Due in 24 hours" },
  { value: "in_72h", label: "Due in 72 hours" },
  { value: "in_7d", label: "Due in 7 days" },
  { value: "clear", label: "Clear due date" },
];

const toText = (value) => String(value || "").trim();

const dueAtFromShortcut = (shortcut) => {
  if (!shortcut) return null;
  if (shortcut === "clear") return "";
  const now = Date.now();
  const offsets = {
    in_4h: 4 * 60 * 60 * 1000,
    in_24h: 24 * 60 * 60 * 1000,
    in_72h: 72 * 60 * 60 * 1000,
    in_7d: 7 * 24 * 60 * 60 * 1000,
  };
  const selectedOffset = offsets[shortcut];
  if (!selectedOffset) return null;
  return new Date(now + selectedOffset).toISOString();
};

const statusTone = (status) => {
  const key = String(status || "").toLowerCase();
  if (["closed", "verified"].includes(key)) return "success";
  if (["contain", "investigate", "escalated"].includes(key)) return "pending";
  return "neutral";
};

const priorityTone = (priority) => {
  const key = String(priority || "").toLowerCase();
  if (key === "critical") return "failed";
  if (key === "high") return "pending";
  if (key === "medium") return "neutral";
  return "success";
};

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
  const [editDueShortcut, setEditDueShortcut] = useState("");
  const [assignmentNote, setAssignmentNote] = useState("");

  const [assignOwner, setAssignOwner] = useState("");
  const [assignNote, setAssignNote] = useState("");
  const [assignDueAt, setAssignDueAt] = useState("");
  const [assignDueShortcut, setAssignDueShortcut] = useState("");

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

  const ownerOptions = useMemo(() => {
    const owners = new Set();
    items.forEach((item) => {
      const owner = toText(item?.owner);
      if (owner) owners.add(owner);
    });
    const selectedOwner = toText(selectedIncident?.owner);
    if (selectedOwner) owners.add(selectedOwner);
    const editOwnerValue = toText(editOwner);
    if (editOwnerValue) owners.add(editOwnerValue);
    const assignOwnerValue = toText(assignOwner);
    if (assignOwnerValue) owners.add(assignOwnerValue);
    return Array.from(owners).sort((left, right) => left.localeCompare(right));
  }, [items, selectedIncident, editOwner, assignOwner]);

  const loadIncidents = useCallback(async () => {
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
  }, [filterDueState, filterOwner, filterPriority, filterStatus, selectedId]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  useEffect(() => {
    if (!selectedIncident) return;
    setEditTitle(toText(selectedIncident.title));
    setEditSummary(toText(selectedIncident.summary));
    setEditStatus(toText(selectedIncident.status || "open").toLowerCase() || "open");
    setEditPriority(toText(selectedIncident.priority || "medium").toLowerCase() || "medium");
    setEditOwner(toText(selectedIncident.owner));
    setEditDueAt(toText(selectedIncident.due_at));
    setEditEscalation(toText(selectedIncident.escalation_state || "normal").toLowerCase() || "normal");
    setEditDueShortcut("");
    setAssignmentNote("");
    setAssignOwner(toText(selectedIncident.owner));
    setAssignNote("");
    setAssignDueAt(toText(selectedIncident.due_at));
    setAssignDueShortcut("");
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

  if (loading) {
    return (
      <div className="page page-route-incidents">
        <div className="empty-state">Loading incident queue...</div>
      </div>
    );
  }

  return (
    <div className="page page-route-incidents">
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

      <div className="card mb-18 incidents-workflow-card">
        <div className="card-header">
          <div>
            <h3>How This Works</h3>
            <p className="muted">Follow this flow to keep investigations consistent and easy to hand off.</p>
          </div>
        </div>
        <ol className="incidents-flow-list">
          <li>Use <strong>Filters</strong> to focus the queue by status, owner, priority, and due state.</li>
          <li>Run <strong>Correlation</strong> to create/update incidents from alert overlap signals.</li>
          <li>Select an item in <strong>Incident Queue</strong> and update workflow fields.</li>
          <li>Use <strong>Reassign</strong>, <strong>Linked Alerts</strong>, and <strong>SLA Events</strong> to finalize ownership and context.</li>
        </ol>
      </div>

      <div className="card mb-18 incidents-filter-card">
        <div className="card-header">
          <div>
            <h3>Filters</h3>
            <p className="muted">Queue total: {total}</p>
          </div>
        </div>
        <div className="grid-4 incidents-filter-grid">
          <label className="list-item">
            <div className="muted">Status</div>
            <select className="input" value={filterStatus} onChange={(event) => setFilterStatus(event.target.value)}>
              <option value="">All</option>
              {STATUS_OPTIONS.map((option) => (
                <option key={`incident-filter-status-${option}`} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Owner</div>
            <select className="input" value={filterOwner} onChange={(event) => setFilterOwner(event.target.value)}>
              <option value="">All owners</option>
              {ownerOptions.map((option) => (
                <option key={`incident-filter-owner-${option}`} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Priority</div>
            <select className="input" value={filterPriority} onChange={(event) => setFilterPriority(event.target.value)}>
              <option value="">All</option>
              {PRIORITY_OPTIONS.map((option) => (
                <option key={`incident-filter-priority-${option}`} value={option}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Due State</div>
            <select className="input" value={filterDueState} onChange={(event) => setFilterDueState(event.target.value)}>
              {DUE_STATE_OPTIONS.map((option) => (
                <option key={`incident-filter-due-${option || "all"}`} value={option}>
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

      <div className="card mb-18 incidents-correlation-card">
        <div className="card-header">
          <div>
            <h3>Correlation</h3>
            <p className="muted">Create/update incidents from alert overlap signals.</p>
          </div>
        </div>
        <div className="grid-4 incidents-correlation-grid">
          <label className="list-item">
            <div className="muted">Lookback Hours</div>
            <select className="input" value={lookbackHours} onChange={(event) => setLookbackHours(event.target.value)}>
              {LOOKBACK_HOUR_OPTIONS.map((option) => (
                <option key={`incident-lookback-${option}`} value={String(option)}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Time Window (min)</div>
            <select className="input" value={timeWindowMinutes} onChange={(event) => setTimeWindowMinutes(event.target.value)}>
              {TIME_WINDOW_MINUTE_OPTIONS.map((option) => (
                <option key={`incident-window-${option}`} value={String(option)}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Min Group Size</div>
            <select className="input" value={minGroupSize} onChange={(event) => setMinGroupSize(event.target.value)}>
              {MIN_GROUP_SIZE_OPTIONS.map((option) => (
                <option key={`incident-group-${option}`} value={String(option)}>{option}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Min Score</div>
            <select className="input" value={minScore} onChange={(event) => setMinScore(event.target.value)}>
              {MIN_SCORE_OPTIONS.map((option) => (
                <option key={`incident-score-${option}`} value={String(option)}>{option}</option>
              ))}
            </select>
          </label>
        </div>
        <div className="page-actions mt-8 incidents-correlation-actions">
          <label className="list-item incidents-persist-card">
            <div className="muted">Persist Incidents</div>
            <select className="input" value={persist ? "true" : "false"} onChange={(event) => setPersist(event.target.value === "true")}>
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          </label>
          <button className="btn" onClick={runCorrelation}>Run Correlation</button>
        </div>
        {correlationResult?.groups?.length ? (
          <div className="table-scroll incidents-correlation-scroll mt-8">
            <table className="table compact incidents-correlation-table">
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

      <div className="card mb-18 incidents-queue-card">
        <div className="card-header">
          <div>
            <h3>Incident Queue</h3>
            <p className="muted">Select an incident to update workflow fields.</p>
          </div>
        </div>
        <div className="table-scroll incidents-queue-scroll">
          <table className="table compact incidents-queue-table">
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
                    <td>
                      <div className="incidents-title-cell">{item.title || "-"}</div>
                    </td>
                    <td>
                      <span className={`status-pill ${statusTone(item.status)}`}>{item.status || "-"}</span>
                    </td>
                    <td>
                      <span className={`status-pill ${priorityTone(item.priority)}`}>{item.priority || "-"}</span>
                    </td>
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

      <div className="card incidents-detail-card">
        <div className="card-header">
          <div>
            <h3>Incident Detail</h3>
            <p className="muted">{selectedIncident ? `Incident ${selectedIncident.id}` : "Select an incident."}</p>
          </div>
        </div>

        {selectedIncident ? (
          <div className="incidents-detail-grid">
            <div className="incidents-detail-form-column">
              <label className="incidents-field">
                <div className="muted">Title</div>
                <input className="input" value={editTitle} onChange={(event) => setEditTitle(event.target.value)} />
              </label>

              <label className="incidents-field">
                <div className="muted">Summary</div>
                <textarea className="input" rows={4} value={editSummary} onChange={(event) => setEditSummary(event.target.value)} />
              </label>

              <div className="incidents-mini-grid">
                <label className="incidents-field">
                  <div className="muted">Status</div>
                  <select className="input" value={editStatus} onChange={(event) => setEditStatus(event.target.value)}>
                    {STATUS_OPTIONS.map((option) => (
                      <option key={`incident-edit-status-${option}`} value={option}>{option}</option>
                    ))}
                  </select>
                </label>
                <label className="incidents-field">
                  <div className="muted">Priority</div>
                  <select className="input" value={editPriority} onChange={(event) => setEditPriority(event.target.value)}>
                    {PRIORITY_OPTIONS.map((option) => (
                      <option key={`incident-edit-priority-${option}`} value={option}>{option}</option>
                    ))}
                  </select>
                </label>
              </div>

              <div className="incidents-mini-grid">
                <label className="incidents-field">
                  <div className="muted">Owner</div>
                  <select className="input" value={editOwner} onChange={(event) => setEditOwner(event.target.value)}>
                    <option value="">Unassigned</option>
                    {ownerOptions.map((option) => (
                      <option key={`incident-edit-owner-${option}`} value={option}>{option}</option>
                    ))}
                  </select>
                </label>
                <label className="incidents-field">
                  <div className="muted">Escalation</div>
                  <select className="input" value={editEscalation} onChange={(event) => setEditEscalation(event.target.value)}>
                    {ESCALATION_OPTIONS.map((option) => (
                      <option key={`incident-edit-escalation-${option}`} value={option}>{option}</option>
                    ))}
                  </select>
                </label>
              </div>

              <div className="incidents-mini-grid">
                <label className="incidents-field">
                  <div className="muted">Due Shortcut</div>
                  <select
                    className="input"
                    value={editDueShortcut}
                    onChange={(event) => {
                      const shortcut = event.target.value;
                      setEditDueShortcut(shortcut);
                      const calculatedDueAt = dueAtFromShortcut(shortcut);
                      if (calculatedDueAt !== null) setEditDueAt(calculatedDueAt);
                    }}
                  >
                    {DUE_SHORTCUT_OPTIONS.map((option) => (
                      <option key={`incident-edit-due-shortcut-${option.value || "none"}`} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="incidents-field">
                  <div className="muted">Due At (ISO UTC)</div>
                  <input className="input" value={editDueAt} onChange={(event) => setEditDueAt(event.target.value)} />
                </label>
              </div>

              <label className="incidents-field">
                <div className="muted">Assignment Note</div>
                <textarea className="input" rows={3} value={assignmentNote} onChange={(event) => setAssignmentNote(event.target.value)} />
              </label>

              <div className="page-actions incidents-save-actions">
                <button className="btn" onClick={saveIncident}>Save Incident</button>
              </div>

              <div className="incidents-section-card">
                <div className="incidents-section-title">Reassign Owner</div>
                <div className="incidents-mini-grid">
                  <label className="incidents-field">
                    <div className="muted">Owner</div>
                    <select className="input" value={assignOwner} onChange={(event) => setAssignOwner(event.target.value)}>
                      <option value="">Select owner</option>
                      {ownerOptions.map((option) => (
                        <option key={`incident-assign-owner-${option}`} value={option}>{option}</option>
                      ))}
                    </select>
                  </label>
                  <label className="incidents-field">
                    <div className="muted">Due Shortcut</div>
                    <select
                      className="input"
                      value={assignDueShortcut}
                      onChange={(event) => {
                        const shortcut = event.target.value;
                        setAssignDueShortcut(shortcut);
                        const calculatedDueAt = dueAtFromShortcut(shortcut);
                        if (calculatedDueAt !== null) setAssignDueAt(calculatedDueAt);
                      }}
                    >
                      {DUE_SHORTCUT_OPTIONS.map((option) => (
                        <option key={`incident-assign-due-shortcut-${option.value || "none"}`} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <label className="incidents-field mt-8">
                  <div className="muted">Due At (ISO UTC)</div>
                  <input className="input" value={assignDueAt} onChange={(event) => setAssignDueAt(event.target.value)} />
                </label>
                <label className="incidents-field mt-8">
                  <div className="muted">Note</div>
                  <textarea className="input" rows={3} value={assignNote} onChange={(event) => setAssignNote(event.target.value)} />
                </label>
                <div className="page-actions mt-8">
                  <button className="btn secondary" onClick={reassignIncident}>Assign</button>
                </div>
              </div>
            </div>

            <div className="incidents-detail-data-column">
              <div className="incidents-section-card">
                <div className="incidents-section-title">Linked Alerts</div>
                <p className="muted">Signals and agents attached to this incident.</p>
                <div className="table-scroll incidents-linked-alerts-scroll">
                  <table className="table compact incidents-linked-alerts-table">
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
                            <td>
                              <div className="incidents-wrap-cell">
                                {Array.isArray(alert.matched_signals) ? alert.matched_signals.join(", ") : "-"}
                              </div>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="incidents-section-card">
                <div className="incidents-section-title">SLA Events</div>
                <p className="muted">Recent due-state and assignment workflow updates.</p>
                <div className="table-scroll incidents-sla-scroll">
                  <table className="table compact incidents-sla-table">
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
                            <td>
                              <div className="incidents-wrap-cell">{event.detail || "-"}</div>
                            </td>
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
  );
}

import { useEffect, useState } from "react";
import { approveChange, closeChange, createChange, getActions, getChanges } from "../api/wazuh";
import api, { decodeLegacyTokenPayload, getLegacyToken } from "../api/client";
import { formatWazuhTimestamp } from "../utils/time";

const changeRow = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      title: row[1],
      actionId: row[2],
      target: row[3],
      riskScore: row[4],
      impact: row[5],
      requestedBy: row[6],
      status: row[7],
      createdAt: row[8],
    };
  }
  return {
    id: row?.id,
    title: row?.title,
    actionId: row?.action_id,
    target: row?.target,
    riskScore: row?.risk_score,
    impact: row?.impact,
    requestedBy: row?.requested_by,
    status: row?.status,
    createdAt: row?.created_at,
  };
};

export default function Changes() {
  const [role, setRole] = useState("user");
  const [rows, setRows] = useState([]);
  const [actions, setActions] = useState([]);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [actionId, setActionId] = useState("");
  const [target, setTarget] = useState("");
  const [riskScore, setRiskScore] = useState("");
  const [impact, setImpact] = useState("medium");
  const [justification, setJustification] = useState("");
  const [status, setStatus] = useState("");

  const load = () => getChanges().then(r => setRows(r.data || []));

  useEffect(() => {
    load();
    const tokenPayload = decodeLegacyTokenPayload();
    if (tokenPayload?.role) {
      setRole(String(tokenPayload.role));
    }
    api
      .get("/auth/me")
      .then((res) => setRole(String(res?.data?.role || "user")))
      .catch((err) => {
        const statusCode = err?.response?.status;
        if ((statusCode === 404 || statusCode === 405) && getLegacyToken()) {
          return;
        }
        setRole("user");
      });
    getActions()
      .then((r) => setActions(r.data || []))
      .catch(() => setActions([]));
  }, []);

  const submit = async () => {
    if (!title) {
      setStatus("Title is required.");
      return;
    }
    try {
      await createChange({
        title,
        description,
        action_id: actionId || undefined,
        target: target || undefined,
        risk_score: riskScore === "" ? null : Number(riskScore),
        impact,
        justification
      });
      setStatus("Change request submitted.");
      setTitle("");
      setDescription("");
      setActionId("");
      setTarget("");
      setRiskScore("");
      setImpact("medium");
      setJustification("");
      await load();
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  const approve = async (id) => {
    await approveChange(id);
    load();
  };

  const close = async (id) => {
    await closeChange(id);
    load();
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Change Management</h2>
          <p className="muted">Governed change requests for sensitive actions.</p>
        </div>
      </div>

      {status && <div className="empty-state">{status}</div>}

      <div className="card mb-18">
        <div className="card-header">
          <div>
            <h3>New Change Request</h3>
            <p className="muted">Capture intent, risk, and impact.</p>
          </div>
        </div>
        <div className="list">
          <div className="list-item">
            <div className="muted">Title</div>
            <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="list-item">
            <div className="muted">Description</div>
            <textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="list-item">
            <div className="muted">Action</div>
            <select className="input" value={actionId} onChange={(e) => setActionId(e.target.value)}>
              <option value="">None</option>
              {actions.map((action) => (
                <option key={action.id} value={action.id}>
                  {(action.label || action.id) + " (" + action.id + ")"}
                </option>
              ))}
            </select>
          </div>
          <div className="list-item">
            <div className="muted">Target (agent/group)</div>
            <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} />
          </div>
          <div className="list-item">
            <div className="muted">Risk & Impact</div>
            <div className="page-actions mt-8">
              <input
                className="input"
                type="number"
                min="0"
                max="100"
                placeholder="Risk score"
                value={riskScore}
                onChange={(e) => setRiskScore(e.target.value)}
              />
              <select className="input" value={impact} onChange={(e) => setImpact(e.target.value)}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>
          <div className="list-item">
            <div className="muted">Justification</div>
            <textarea className="input" value={justification} onChange={(e) => setJustification(e.target.value)} />
          </div>
          <div className="list-item">
            <button className="btn" onClick={submit}>Submit Change</button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Change Requests</h3>
            <p className="muted">Review and approve changes.</p>
          </div>
        </div>
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Action</th>
                <th>Target</th>
                <th>Risk</th>
                <th>Impact</th>
                <th>Status</th>
                <th>Requested By</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan="10" className="text-center">No change requests</td>
                </tr>
              ) : (
                rows.map((raw) => {
                  const row = changeRow(raw);
                  return (
                  <tr key={row.id}>
                    <td>{row.id}</td>
                    <td>{row.title}</td>
                    <td>{row.actionId || "-"}</td>
                    <td>{row.target || "-"}</td>
                    <td>{row.riskScore ?? "-"}</td>
                    <td>{row.impact || "-"}</td>
                    <td>{row.status}</td>
                    <td>{row.requestedBy || "-"}</td>
                    <td>{formatWazuhTimestamp(row.createdAt)}</td>
                    <td>
                      <div className="page-actions">
                        {role === "admin" || role === "superadmin" ? (
                          <>
                            <button className="btn success" onClick={() => approve(row.id)}>Approve</button>
                            <button className="btn secondary" onClick={() => close(row.id)}>Close</button>
                          </>
                        ) : (
                          <span className="muted">-</span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

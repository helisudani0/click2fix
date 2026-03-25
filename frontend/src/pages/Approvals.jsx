import { useEffect, useState } from "react";
import { decideApproval, getPendingApprovals } from "../api/wazuh";
import RelativeTimestamp from "../components/RelativeTimestamp";

const approvalRow = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      agent: row[1],
      action: row[2],
      requestedBy: row[3],
      createdAt: row[4],
      alertId: row[5],
      required: row[6] || 0,
      approved: row[7] || 0,
      justification: row[8],
    };
  }
  return {
    id: row?.id,
    agent: row?.agent,
    action: row?.action || row?.playbook || row?.coalesce || row?.coalesce_1,
    requestedBy: row?.requested_by,
    createdAt: row?.created_at,
    alertId: row?.alert_id,
    required: row?.required_total || 0,
    approved: row?.approved_total || 0,
    justification: row?.justification,
  };
};

export default function Approvals() {

  const [rows, setRows] = useState([]);

  const load = () =>
    getPendingApprovals()
      .then(r => setRows(r.data));

  useEffect(load, []);

  const approve = id =>
    decideApproval(id, { decision: "approve" })
      .then(load);

  const reject = id =>
    decideApproval(id, { decision: "reject" })
      .then(load);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Pending Approvals</h2>
          <p className="muted">Review and approve automation requests.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={load}>Refresh</button>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Approval Queue</h3>
            <p className="muted">Review automation requests before they execute on endpoints.</p>
          </div>
          <span className="chip">{rows.length} pending</span>
        </div>
        <div className="table-scroll">
          <table className="table readable compact">
            <thead>
              <tr>
                <th>ID</th>
                <th>Agent</th>
                <th>Action</th>
                <th>Requested By</th>
                <th>Alert</th>
                <th>Approvals</th>
                <th>Justification</th>
                <th>Requested</th>
                <th>Actions</th>
              </tr>
            </thead>

            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan="9" className="text-center">
                    No pending approvals
                  </td>
                </tr>
              ) : (
                rows.map((raw) => {
                  const row = approvalRow(raw);
                  return (
                    <tr key={row.id}>
                      <td>{row.id}</td>
                      <td>{row.agent || "-"}</td>
                      <td>{row.action || "-"}</td>
                      <td>{row.requestedBy || "-"}</td>
                      <td>{row.alertId || "-"}</td>
                      <td>{row.approved} / {row.required}</td>
                      <td>{row.justification || "-"}</td>
                      <td><RelativeTimestamp value={row.createdAt} /></td>
                      <td>
                        <div className="page-actions">
                          <button className="btn success" onClick={() => approve(row.id)}>Approve</button>
                          <button className="btn danger" onClick={() => reject(row.id)}>Reject</button>
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

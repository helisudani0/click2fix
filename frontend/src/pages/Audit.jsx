import { useEffect, useMemo, useState } from "react";
import { getAudit } from "../api/wazuh";
import RelativeTimestamp from "../components/RelativeTimestamp";

const auditRow = (row) => {
  if (Array.isArray(row)) {
    return {
      id: row[0],
      actor: row[1],
      action: row[2],
      entityType: row[3],
      entityId: row[4],
      detail: row[5],
      ipAddress: row[7],
      createdAt: row[8],
    };
  }
  return {
    id: row?.id,
    actor: row?.actor,
    action: row?.action,
    entityType: row?.entity_type,
    entityId: row?.entity_id,
    detail: row?.detail,
    ipAddress: row?.ip_address,
    createdAt: row?.created_at,
  };
};

export default function Audit() {
  const [rows, setRows] = useState([]);
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [entityType, setEntityType] = useState("");

  const normalizedRows = useMemo(() => rows.map(auditRow), [rows]);
  const activeFilterCount = [actor, action, entityType].filter((value) => String(value || "").trim()).length;
  const uniqueActorCount = useMemo(
    () => new Set(normalizedRows.map((row) => row.actor).filter(Boolean)).size,
    [normalizedRows],
  );
  const uniqueEntityCount = useMemo(
    () => new Set(normalizedRows.map((row) => row.entityType).filter(Boolean)).size,
    [normalizedRows],
  );

  const load = () => {
    getAudit({
      actor: actor || undefined,
      action: action || undefined,
      entity_type: entityType || undefined,
      limit: 200
    }).then(r => setRows(r.data || []));
  };

  useEffect(() => {
    load();
  }, []);

  const exportAudit = (format) => {
    const params = new URLSearchParams();
    if (actor) params.append("actor", actor);
    if (action) params.append("action", action);
    if (entityType) params.append("entity_type", entityType);
    params.append("format", format);
    window.open(`/api/audit/export?${params.toString()}`, "_blank");
  };

  return (
    <div className="page page-route-audit">
      <div className="page-header">
        <div>
          <h2>Audit Log</h2>
          <p className="muted">Immutable security and governance events.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={load}>
            Refresh
          </button>
          <button className="btn secondary" onClick={() => exportAudit("csv")}>
            Export CSV
          </button>
          <button className="btn" onClick={() => exportAudit("json")}>
            Export JSON
          </button>
        </div>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Visible Events</div>
          <div className="stat-value">{normalizedRows.length}</div>
          <div className="stat-sub">Current filtered audit trail</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active Filters</div>
          <div className="stat-value">{activeFilterCount}</div>
          <div className="stat-sub">Actor, action, and entity filters applied</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Actors</div>
          <div className="stat-value">{uniqueActorCount}</div>
          <div className="stat-sub">Unique actors in the visible result set</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Entity Types</div>
          <div className="stat-value">{uniqueEntityCount}</div>
          <div className="stat-sub">Distinct governed resources touched</div>
        </div>
      </div>

      <div className="card">
        <div className="page-actions mb-12">
          <input
            className="input"
            placeholder="Actor"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
          />
          <input
            className="input"
            placeholder="Action"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          />
          <input
            className="input"
            placeholder="Entity type"
            value={entityType}
            onChange={(e) => setEntityType(e.target.value)}
          />
          <button className="btn secondary" onClick={load}>
            Filter
          </button>
        </div>

        <div className="table-scroll">
          <table className="table readable compact">
            <thead>
              <tr>
                <th>ID</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Entity</th>
                <th>Detail</th>
                <th>IP</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {normalizedRows.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center">
                    No audit events
                  </td>
                </tr>
              ) : (
                normalizedRows.map((row) => {
                  return (
                    <tr key={row.id}>
                      <td>{row.id}</td>
                      <td>{row.actor || "-"}</td>
                      <td>{row.action || "-"}</td>
                      <td>{row.entityType}:{row.entityId}</td>
                      <td>{row.detail || "-"}</td>
                      <td>{row.ipAddress || "-"}</td>
                      <td><RelativeTimestamp value={row.createdAt} /></td>
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


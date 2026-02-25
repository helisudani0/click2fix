import { useEffect, useState } from "react";
import api from "../api/client";

export default function MitrePanel({ alertId }) {

  const [rows, setRows] = useState([]);

  useEffect(() => {
    api.get(`/mitre/alert/${alertId}`)
      .then(r => setRows(r.data));
  }, [alertId]);

  return (
    <>
      <h3>MITRE ATT&CK</h3>
      <p className="muted">Tactics and techniques mapped to this alert.</p>

      {rows.length === 0 ? (
        <div className="empty-state">No MITRE mapping available.</div>
      ) : (
        <ul className="list">
          {rows.map((r, i) => (
            <li key={i} className="list-item">
              {r[0]} - {r[1]} ({r[2]})
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

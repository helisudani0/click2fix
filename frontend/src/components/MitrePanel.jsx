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
          {rows.map((row, i) => {
            const item = Array.isArray(row)
              ? {
                  tactic: row[0],
                  technique: row[1],
                  technique_id: row[2],
                  confidence: 0,
                  source: "",
                  mapping_rank: i + 1,
                  is_primary: i === 0,
                }
              : (row || {});
            const confidence = Number.isFinite(Number(item.confidence))
              ? Number(item.confidence)
              : 0;
            const techniqueLabel = item.technique_id
              ? `${item.technique || "Unknown Technique"} (${item.technique_id})`
              : item.technique || "Unknown Technique";
            return (
            <li key={`${item.technique_id || item.technique || "unknown"}-${i}`} className="list-item">
              <div>
                {item.tactic || "Unknown Tactic"} - {techniqueLabel}
              </div>
              <div className="muted">
                Confidence {confidence}%
                {item.source ? ` | ${item.source}` : ""}
                {item.mapping_rank ? ` | rank ${item.mapping_rank}` : ""}
                {item.is_primary ? " | primary" : ""}
              </div>
            </li>
            );
          })}
        </ul>
      )}
    </>
  );
}

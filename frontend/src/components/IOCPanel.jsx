import { useEffect, useState } from "react";
import api from "../api/client";

export default function IOCPanel({ alertId }) {

  const [rows, setRows] = useState([]);

  useEffect(() => {
    api.get(`/ioc/${alertId}`)
      .then(r => setRows(r.data));
  }, [alertId]);

  return (
    <>
      <h3>IOC Enrichment</h3>
      <p className="muted">Indicators matched to the selected alert.</p>

      {rows.length === 0 ? (
        <div className="empty-state">No IOC enrichment available.</div>
      ) : (
        <div className="table-scroll">
          <table className="table">
            <thead>
              <tr>
                <th>IOC</th>
                <th>Type</th>
                <th>Source</th>
                <th>Score</th>
                <th>Verdict</th>
              </tr>
            </thead>

            <tbody>
              {rows.map((r, i) => {
                const row = Array.isArray(r)
                  ? {
                      ioc: r[0],
                      ioc_type: r[1],
                      source: r[2],
                      score: r[3],
                      verdict: r[4],
                    }
                  : r || {};
                return (
                  <tr key={i}>
                    <td>{row.ioc ?? "-"}</td>
                    <td>{row.ioc_type ?? "-"}</td>
                    <td>{row.source ?? "-"}</td>
                    <td>{row.score ?? "-"}</td>
                    <td>{row.verdict ?? "-"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

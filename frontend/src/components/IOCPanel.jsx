import { useEffect, useState } from "react";
import api from "../api/client";

export default function IOCPanel({ alertId }) {

  const [rows, setRows] = useState([]);
  const [summary, setSummary] = useState(null);
  const [indicators, setIndicators] = useState([]);

  useEffect(() => {
    api.get(`/ioc/${alertId}`, { params: { include_summary: true } })
      .then((r) => {
        const payload = r?.data;
        if (Array.isArray(payload)) {
          setRows(payload);
          setSummary(null);
          setIndicators([]);
          return;
        }
        setRows(Array.isArray(payload?.records) ? payload.records : []);
        setSummary(payload?.summary || null);
        setIndicators(Array.isArray(payload?.indicators) ? payload.indicators : []);
      });
  }, [alertId]);

  return (
    <>
      <h3>IOC Enrichment</h3>
      <p className="muted">Indicators matched to the selected alert.</p>

      {rows.length === 0 ? (
        <div className="empty-state">No IOC enrichment available.</div>
      ) : (
        <div>
          {summary ? (
            <div className="list mb-12">
              <div className="list-item">
                <div>Unique Indicators</div>
                <div className="muted">{summary.unique_indicators ?? 0}</div>
              </div>
              <div className="list-item">
                <div>High Confidence</div>
                <div className="muted">{summary.high_confidence_indicators ?? 0}</div>
              </div>
              <div className="list-item">
                <div>Suspicious</div>
                <div className="muted">{summary.suspicious_indicators ?? 0}</div>
              </div>
            </div>
          ) : null}

          {indicators.length ? (
            <div className="list mb-12">
              {indicators.slice(0, 3).map((item, idx) => (
                <div className="list-item" key={`${item.ioc}-${idx}`}>
                  <div>{item.ioc} ({item.ioc_type || "unknown"})</div>
                  <div className="muted">
                    score {item.max_score ?? item.score ?? 0}
                    {Array.isArray(item.sources) && item.sources.length ? ` | ${item.sources.join(", ")}` : ""}
                  </div>
                </div>
              ))}
            </div>
          ) : null}

          <div className="table-scroll">
            <table className="table">
              <thead>
                <tr>
                  <th>IOC</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Score</th>
                  <th>Verdict</th>
                  <th>Observed</th>
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
                        created_at: null,
                      }
                    : r || {};
                  return (
                    <tr key={i}>
                      <td>{row.ioc ?? "-"}</td>
                      <td>{row.ioc_type ?? "-"}</td>
                      <td>{row.source ?? "-"}</td>
                      <td>{row.score ?? "-"}</td>
                      <td>{row.verdict ?? "-"}</td>
                      <td>{row.created_at ? String(row.created_at) : "-"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

import { useState } from "react";
import { getFleetScaHardening } from "../api/wazuh";

const toInt = (value, fallback) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export default function ScaFleet() {
  const [status, setStatus] = useState("active");
  const [platform, setPlatform] = useState("");
  const [group, setGroup] = useState("");
  const [agentIds, setAgentIds] = useState("");
  const [limitAgents, setLimitAgents] = useState("200");
  const [recommendationLimit, setRecommendationLimit] = useState("25");
  const [fleetRecommendationLimit, setFleetRecommendationLimit] = useState("300");
  const [parallelism, setParallelism] = useState("6");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState(null);

  const loadFleetSca = async () => {
    try {
      setLoading(true);
      setError("");
      const response = await getFleetScaHardening({
        status: status || undefined,
        platform: platform || undefined,
        group: group || undefined,
        agent_ids: agentIds || undefined,
        limit_agents: toInt(limitAgents, 200),
        recommendation_limit: toInt(recommendationLimit, 25),
        fleet_recommendation_limit: toInt(fleetRecommendationLimit, 300),
        parallelism: toInt(parallelism, 6),
        include_checks: false,
      });
      setPayload(response?.data || null);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const summary = payload?.summary || {};
  const agents = Array.isArray(payload?.agents) ? payload.agents : [];
  const recs = Array.isArray(payload?.fleet_recommendations) ? payload.fleet_recommendations : [];

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Fleet SCA Hardening</h2>
          <p className="muted">Fleet-wide SCA failures and prioritized hardening recommendations.</p>
        </div>
      </div>

      <div className="card mb-18">
        <div className="card-header">
          <div>
            <h3>Filters</h3>
            <p className="muted">Run `/agents/sca/fleet` across selected agent scope.</p>
          </div>
        </div>
        <div className="grid-4">
          <label className="list-item">
            <div className="muted">Status</div>
            <input className="input" value={status} onChange={(event) => setStatus(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Platform</div>
            <input className="input" value={platform} onChange={(event) => setPlatform(event.target.value)} placeholder="windows,linux" />
          </label>
          <label className="list-item">
            <div className="muted">Group</div>
            <input className="input" value={group} onChange={(event) => setGroup(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Agent IDs</div>
            <input className="input" value={agentIds} onChange={(event) => setAgentIds(event.target.value)} placeholder="001,004,010" />
          </label>
          <label className="list-item">
            <div className="muted">Limit Agents</div>
            <input className="input" type="number" min="1" value={limitAgents} onChange={(event) => setLimitAgents(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Per-Agent Recommendation Limit</div>
            <input className="input" type="number" min="1" value={recommendationLimit} onChange={(event) => setRecommendationLimit(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Fleet Recommendation Limit</div>
            <input className="input" type="number" min="1" value={fleetRecommendationLimit} onChange={(event) => setFleetRecommendationLimit(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Parallelism</div>
            <input className="input" type="number" min="1" value={parallelism} onChange={(event) => setParallelism(event.target.value)} />
          </label>
        </div>
        <div className="page-actions mt-8">
          <button className="btn" onClick={loadFleetSca} disabled={loading}>
            {loading ? "Loading..." : "Load Fleet SCA"}
          </button>
        </div>
      </div>

      {error ? <div className="empty-state">{error}</div> : null}

      {payload ? (
        <>
          <div className="grid-4 mb-18">
            <div className="card">
              <div className="list-item">
                <div className="muted">Agents Evaluated</div>
                <div><strong>{summary.agents_evaluated || 0}</strong></div>
              </div>
            </div>
            <div className="card">
              <div className="list-item">
                <div className="muted">Agents With Errors</div>
                <div><strong>{summary.agents_with_errors || 0}</strong></div>
              </div>
            </div>
            <div className="card">
              <div className="list-item">
                <div className="muted">Total Failed Checks</div>
                <div><strong>{summary.total_failed_checks || 0}</strong></div>
              </div>
            </div>
            <div className="card">
              <div className="list-item">
                <div className="muted">Fleet Recommendations</div>
                <div><strong>{summary.fleet_recommendations || 0}</strong></div>
              </div>
            </div>
          </div>

          <div className="card mb-18">
            <div className="card-header">
              <div>
                <h3>Per-Agent SCA Summary</h3>
                <p className="muted">Quick pass/fail distribution and recommendation count per agent.</p>
              </div>
            </div>
            <div className="table-scroll h-260">
              <table className="table compact">
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Status</th>
                    <th>Platform</th>
                    <th>Policies</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Total</th>
                    <th>Recommendations</th>
                    <th>Error</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.length === 0 ? (
                    <tr>
                      <td colSpan="9" className="text-center">No agent rows returned.</td>
                    </tr>
                  ) : (
                    agents.map((row) => (
                      <tr key={row.agent_id}>
                        <td>{row.agent_name || row.agent_id}</td>
                        <td>{row.status || "-"}</td>
                        <td>{row.platform || "-"}</td>
                        <td>{row.policy_count || 0}</td>
                        <td>{row?.checks_summary?.passed || 0}</td>
                        <td>{row?.checks_summary?.failed || 0}</td>
                        <td>{row?.checks_summary?.total || 0}</td>
                        <td>{Array.isArray(row.recommendations) ? row.recommendations.length : 0}</td>
                        <td>{row.error || "-"}</td>
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
                <h3>Fleet Recommendations</h3>
                <p className="muted">Prioritized failed checks to harden first across the fleet.</p>
              </div>
            </div>
            <div className="table-scroll h-56vh">
              <table className="table readable compact">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Agent</th>
                    <th>Policy</th>
                    <th>Check</th>
                    <th>Priority</th>
                    <th>Score</th>
                    <th>Reason</th>
                    <th>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {recs.length === 0 ? (
                    <tr>
                      <td colSpan="8" className="text-center">No fleet recommendations returned.</td>
                    </tr>
                  ) : (
                    recs.map((rec) => (
                      <tr key={`${rec.fleet_rank}-${rec.agent_id}-${rec.check_id}`}>
                        <td>{rec.fleet_rank || "-"}</td>
                        <td>{rec.agent_name || rec.agent_id}</td>
                        <td>{rec.policy_name || rec.policy_id || "-"}</td>
                        <td>{rec.check_id || "-"}</td>
                        <td>{rec.priority || "-"}</td>
                        <td>{rec.priority_score || "-"}</td>
                        <td>{rec.reason || "-"}</td>
                        <td>{rec.recommendation || "-"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}

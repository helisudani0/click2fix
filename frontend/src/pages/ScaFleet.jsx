import { useState } from "react";
import { getFleetScaHardening } from "../api/wazuh";
import { formatApiError } from "../utils/httpErrors";

const toBoundedInt = (value, fallback, min, max) => {
  const raw = String(value ?? "").trim();
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  const whole = Math.trunc(parsed);
  if (whole < min || whole > max) return fallback;
  return whole;
};

const toSafeText = (value, fallback = "-") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
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
  const [aiAssist, setAiAssist] = useState(false);
  const [aiInstruction, setAiInstruction] = useState("");

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
        limit_agents: toBoundedInt(limitAgents, 200, 0, 2000),
        recommendation_limit: toBoundedInt(recommendationLimit, 25, 1, 250),
        fleet_recommendation_limit: toBoundedInt(fleetRecommendationLimit, 300, 1, 5000),
        parallelism: toBoundedInt(parallelism, 6, 1, 32),
        ai_assist: aiAssist,
        ai_instruction: aiInstruction || undefined,
        ai_max_items: 12,
        include_checks: false,
      });
      setPayload(response?.data || null);
    } catch (err) {
      setError(formatApiError(err, "Failed to load fleet SCA data."));
    } finally {
      setLoading(false);
    }
  };

  const summary = payload?.summary || {};
  const agents = Array.isArray(payload?.agents) ? payload.agents : [];
  const recs = Array.isArray(payload?.fleet_recommendations) ? payload.fleet_recommendations : [];
  const actionPlan = Array.isArray(payload?.fleet_action_plan) ? payload.fleet_action_plan : [];
  const aiMeta = payload?.ai_assist && typeof payload.ai_assist === "object" ? payload.ai_assist : null;

  return (
    <div className="page page-route-sca-fleet">
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
            <p className="muted">
              Run `/agents/sca/fleet` across selected scope. Set <strong>Limit Agents = 0</strong> to evaluate all matched endpoints.
            </p>
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
            <input className="input" type="number" min="0" value={limitAgents} onChange={(event) => setLimitAgents(event.target.value)} />
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
          <label className="list-item">
            <div className="muted">AI Assist</div>
            <select
              className="input"
              value={aiAssist ? "on" : "off"}
              onChange={(event) => setAiAssist(event.target.value === "on")}
            >
              <option value="off">Off</option>
              <option value="on">On (Org Admin AI)</option>
            </select>
          </label>
          <label className="list-item">
            <div className="muted">AI Instruction (optional)</div>
            <input
              className="input"
              value={aiInstruction}
              onChange={(event) => setAiInstruction(event.target.value)}
              placeholder="Example: prioritize low user-impact changes first"
            />
          </label>
        </div>
        <div className="muted mt-8">
          AI uses Org Admin / Platform AI Configuration. If disabled there, this page continues with deterministic recommendations.
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
          <div className="card mb-18">
            <div className="card-header">
              <div>
                <h3>What To Do First</h3>
                <p className="muted">Operator-ready action plan generated from top failed controls.</p>
              </div>
            </div>
            {actionPlan.length === 0 ? (
              <div className="empty-state">No action plan generated for this run yet.</div>
            ) : (
              <div className="table-scroll h-220">
                <table className="table compact">
                  <thead>
                    <tr>
                      <th>Rank</th>
                      <th>Focus Area</th>
                      <th>Priority</th>
                      <th>Impacted Agents</th>
                      <th>Controls</th>
                      <th>Recommended Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {actionPlan.map((step) => (
                      <tr key={`action-plan-${step.rank}-${step.focus_area}`}>
                        <td>{step.rank}</td>
                        <td>{toSafeText(step.focus_label || step.focus_area)}</td>
                        <td>{toSafeText(step.priority)}</td>
                        <td>{toSafeText(step.impacted_agents, "0")}</td>
                        <td>{toSafeText(step.control_count, "0")}</td>
                        <td>{toSafeText(step.recommended_action)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {aiMeta ? (
            <div className="card mb-18">
              <div className="card-header">
                <div>
                  <h3>AI Assist Status</h3>
                  <p className="muted">Visibility into whether AI enrichment was applied for this run.</p>
                </div>
              </div>
              <div className="grid-4">
                <div className="list-item">
                  <div className="muted">Requested</div>
                  <div><strong>{aiMeta.requested ? "Yes" : "No"}</strong></div>
                </div>
                <div className="list-item">
                  <div className="muted">Enabled</div>
                  <div><strong>{aiMeta.enabled ? "Yes" : "No"}</strong></div>
                </div>
                <div className="list-item">
                  <div className="muted">Applied</div>
                  <div><strong>{aiMeta.applied ? "Yes" : "No"}</strong></div>
                </div>
                <div className="list-item">
                  <div className="muted">Rows Updated</div>
                  <div><strong>{toSafeText(aiMeta.rows_updated, "0")}</strong></div>
                </div>
              </div>
              {aiMeta.summary ? <div className="muted mt-8">Summary: {toSafeText(aiMeta.summary)}</div> : null}
              {aiMeta.error ? <div className="empty-state mt-8">{toSafeText(aiMeta.error)}</div> : null}
            </div>
          ) : null}

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
                        <td>{toSafeText(row.status)}</td>
                        <td>{toSafeText(row.platform)}</td>
                        <td>{row.policy_count || 0}</td>
                        <td>{row?.checks_summary?.passed || 0}</td>
                        <td>{row?.checks_summary?.failed || 0}</td>
                        <td>{row?.checks_summary?.total || 0}</td>
                        <td>{Array.isArray(row.recommendations) ? row.recommendations.length : 0}</td>
                        <td>{toSafeText(row.error)}</td>
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
                        <td>{toSafeText(rec.policy_name || rec.policy_id)}</td>
                        <td>{toSafeText(rec.check_id)}</td>
                        <td>{toSafeText(rec.priority)}</td>
                        <td>{toSafeText(rec.priority_score)}</td>
                        <td>{toSafeText(rec.reason)}</td>
                        <td>
                          <div>{toSafeText(rec.recommendation)}</div>
                          {toBoundedInt(rec.duplicate_count, 1, 1, 9999) > 1 ? (
                            <div className="muted">
                              {`Seen in ${toSafeText(rec.duplicate_count)} similar controls`}
                              {Array.isArray(rec.related_policies) && rec.related_policies.length
                                ? ` (examples: ${rec.related_policies.slice(0, 2).join(", ")})`
                                : ""}
                            </div>
                          ) : null}
                          {rec.ai_rationale ? (
                            <div className="muted">
                              AI rationale: {toSafeText(rec.ai_rationale)}
                            </div>
                          ) : null}
                        </td>
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


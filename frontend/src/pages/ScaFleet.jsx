import { useEffect, useState } from "react";
import { getAgents, getAgentGroups, getFleetScaHardening } from "../api/wazuh";
import { formatApiError } from "../utils/httpErrors";

const SCA_LIMITS = {
  limitAgents: { min: 0, max: 2000, label: "0-2000" },
  recommendationLimit: { min: 1, max: 250, label: "1-250" },
  fleetRecommendationLimit: { min: 1, max: 5000, label: "1-5000" },
  parallelism: { min: 1, max: 32, label: "1-32" },
  aiMaxItems: 12,
};

const STATUS_OPTIONS = [
  { value: "active", label: "Active" },
  { value: "disconnected", label: "Disconnected" },
  { value: "pending", label: "Pending" },
  { value: "", label: "Any status" },
];

const PLATFORM_OPTIONS = [
  { value: "windows,linux", label: "Windows + Linux" },
  { value: "windows", label: "Windows only" },
  { value: "linux", label: "Linux only" },
  { value: "", label: "Any platform" },
];

const LIMIT_AGENT_OPTIONS = [0, 50, 100, 200, 300, 500, 1000, 1500, 2000];
const PER_AGENT_REC_OPTIONS = [10, 25, 50, 75, 100, 150, 200, 250];
const FLEET_REC_OPTIONS = [100, 200, 300, 500, 750, 1000, 2000, 3000, 5000];
const PARALLELISM_OPTIONS = [1, 2, 4, 6, 8, 12, 16, 24, 32];

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
  const [platform, setPlatform] = useState("windows,linux");
  const [group, setGroup] = useState("");
  const [selectedAgentIds, setSelectedAgentIds] = useState([]);
  const [limitAgents, setLimitAgents] = useState("200");
  const [recommendationLimit, setRecommendationLimit] = useState("25");
  const [fleetRecommendationLimit, setFleetRecommendationLimit] = useState("300");
  const [parallelism, setParallelism] = useState("6");
  const [aiAssist, setAiAssist] = useState(false);
  const [aiInstruction, setAiInstruction] = useState("");
  const [groupOptions, setGroupOptions] = useState([]);
  const [agentOptions, setAgentOptions] = useState([]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState(null);

  useEffect(() => {
    let active = true;

    const loadFilterOptions = async () => {
      try {
        const [groupRes, agentRes] = await Promise.all([
          getAgentGroups().catch(() => ({ data: [] })),
          getAgents("", { compact: true, status: "active", limit: 500 }).catch(() => ({ data: [] })),
        ]);
        if (!active) return;

        const parsedGroups = (Array.isArray(groupRes?.data) ? groupRes.data : [])
          .map((item) => String(item?.name || item?.group || item?.id || item || "").trim())
          .filter(Boolean);
        const uniqueGroups = Array.from(new Set(parsedGroups)).sort((left, right) => left.localeCompare(right));
        setGroupOptions(uniqueGroups);

        const rawAgents = Array.isArray(agentRes?.data)
          ? agentRes.data
          : (Array.isArray(agentRes?.data?.items) ? agentRes.data.items : []);
        const parsedAgents = rawAgents
          .map((agent) => ({
            id: String(agent?.id || agent?.agent_id || "").trim(),
            name: String(agent?.name || agent?.hostname || agent?.agent_name || "").trim(),
          }))
          .filter((agent) => agent.id);
        const dedupedAgents = Array.from(
          new Map(parsedAgents.map((agent) => [agent.id, agent])).values()
        ).sort((left, right) => left.id.localeCompare(right.id));
        setAgentOptions(dedupedAgents);
      } catch {
        if (!active) return;
        setGroupOptions([]);
        setAgentOptions([]);
      }
    };

    void loadFilterOptions();
    return () => {
      active = false;
    };
  }, []);

  const loadFleetSca = async () => {
    try {
      setLoading(true);
      setError("");
      const response = await getFleetScaHardening({
        status: status || undefined,
        platform: platform || undefined,
        group: group || undefined,
        agent_ids: selectedAgentIds.length ? selectedAgentIds.join(",") : undefined,
        limit_agents: toBoundedInt(limitAgents, 200, SCA_LIMITS.limitAgents.min, SCA_LIMITS.limitAgents.max),
        recommendation_limit: toBoundedInt(
          recommendationLimit,
          25,
          SCA_LIMITS.recommendationLimit.min,
          SCA_LIMITS.recommendationLimit.max
        ),
        fleet_recommendation_limit: toBoundedInt(
          fleetRecommendationLimit,
          300,
          SCA_LIMITS.fleetRecommendationLimit.min,
          SCA_LIMITS.fleetRecommendationLimit.max
        ),
        parallelism: toBoundedInt(parallelism, 6, SCA_LIMITS.parallelism.min, SCA_LIMITS.parallelism.max),
        ai_assist: aiAssist,
        ai_instruction: aiInstruction || undefined,
        ai_max_items: SCA_LIMITS.aiMaxItems,
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
        <div className="grid-4 sca-fleet-filter-grid">
          <label className="list-item">
            <div className="muted">Status</div>
            <select className="input" value={status} onChange={(event) => setStatus(event.target.value)}>
              {STATUS_OPTIONS.map((option) => (
                <option key={`sca-status-${option.value || "any"}`} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Platform</div>
            <select className="input" value={platform} onChange={(event) => setPlatform(event.target.value)}>
              {PLATFORM_OPTIONS.map((option) => (
                <option key={`sca-platform-${option.value || "any"}`} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Group</div>
            <select className="input" value={group} onChange={(event) => setGroup(event.target.value)}>
              <option value="">All groups</option>
              {groupOptions.map((value) => (
                <option key={`sca-group-${value}`} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <div className="list-item">
            <div className="muted">Agent IDs</div>
            <select
              className="input sca-agent-multi"
              multiple
              size={4}
              value={selectedAgentIds}
              onChange={(event) => {
                const values = Array.from(event.target.selectedOptions).map((option) => option.value);
                setSelectedAgentIds(values);
              }}
            >
              {agentOptions.map((agent) => (
                <option key={`sca-agent-${agent.id}`} value={agent.id}>
                  {agent.id}{agent.name ? ` - ${agent.name}` : ""}
                </option>
              ))}
            </select>
            <div className="page-actions mt-8 sca-agent-actions">
              <button
                type="button"
                className="btn secondary"
                onClick={() => setSelectedAgentIds(agentOptions.map((agent) => agent.id))}
                disabled={!agentOptions.length}
              >
                Select All
              </button>
              <button
                type="button"
                className="btn secondary"
                onClick={() => setSelectedAgentIds([])}
                disabled={!selectedAgentIds.length}
              >
                Clear
              </button>
            </div>
          </div>
          <label className="list-item">
            <div className="muted">{`Limit Agents (${SCA_LIMITS.limitAgents.label})`}</div>
            <select className="input" value={limitAgents} onChange={(event) => setLimitAgents(event.target.value)}>
              {LIMIT_AGENT_OPTIONS.map((value) => (
                <option key={`sca-limit-agents-${value}`} value={String(value)}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">{`Per-Agent Recommendation Limit (${SCA_LIMITS.recommendationLimit.label})`}</div>
            <select
              className="input"
              value={recommendationLimit}
              onChange={(event) => setRecommendationLimit(event.target.value)}
            >
              {PER_AGENT_REC_OPTIONS.map((value) => (
                <option key={`sca-per-agent-${value}`} value={String(value)}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">{`Fleet Recommendation Limit (${SCA_LIMITS.fleetRecommendationLimit.label})`}</div>
            <select
              className="input"
              value={fleetRecommendationLimit}
              onChange={(event) => setFleetRecommendationLimit(event.target.value)}
            >
              {FLEET_REC_OPTIONS.map((value) => (
                <option key={`sca-fleet-rec-${value}`} value={String(value)}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">{`Parallelism (${SCA_LIMITS.parallelism.label})`}</div>
            <select className="input" value={parallelism} onChange={(event) => setParallelism(event.target.value)}>
              {PARALLELISM_OPTIONS.map((value) => (
                <option key={`sca-parallel-${value}`} value={String(value)}>
                  {value}
                </option>
              ))}
            </select>
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
          <label className="list-item sca-ai-instruction-item">
            <div className="muted">AI Instruction (optional)</div>
            <textarea
              className="input"
              value={aiInstruction}
              onChange={(event) => setAiInstruction(event.target.value)}
              rows={3}
              placeholder="Example: prioritize low user-impact changes first"
            />
          </label>
        </div>
        <div className="muted mt-8">
          {`Limits: agents ${SCA_LIMITS.limitAgents.label}, per-agent recs ${SCA_LIMITS.recommendationLimit.label}, fleet recs ${SCA_LIMITS.fleetRecommendationLimit.label}, parallelism ${SCA_LIMITS.parallelism.label}.`}
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
              <div className="table-scroll h-220 sca-action-plan-scroll">
                <table className="table compact sca-action-plan-table">
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
                        <td className="sca-action-cell">{toSafeText(step.recommended_action)}</td>
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
            <div className="table-scroll h-260 sca-agent-summary-scroll">
              <table className="table compact sca-agent-summary-table">
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
                        <td className="sca-agent-cell">{row.agent_name || row.agent_id}</td>
                        <td>{toSafeText(row.status)}</td>
                        <td>{toSafeText(row.platform)}</td>
                        <td>{row.policy_count || 0}</td>
                        <td>{row?.checks_summary?.passed || 0}</td>
                        <td>{row?.checks_summary?.failed || 0}</td>
                        <td>{row?.checks_summary?.total || 0}</td>
                        <td>{Array.isArray(row.recommendations) ? row.recommendations.length : 0}</td>
                        <td className="sca-error-cell">{toSafeText(row.error)}</td>
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
            <div className="table-scroll h-56vh sca-fleet-recs-scroll">
              <table className="table readable compact sca-fleet-recs-table">
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
                        <td className="sca-policy-cell">{toSafeText(rec.policy_name || rec.policy_id)}</td>
                        <td>{toSafeText(rec.check_id)}</td>
                        <td>{toSafeText(rec.priority)}</td>
                        <td>{toSafeText(rec.priority_score)}</td>
                        <td className="sca-reason-cell">{toSafeText(rec.reason)}</td>
                        <td>
                          <div className="sca-recommendation-cell">{toSafeText(rec.recommendation)}</div>
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


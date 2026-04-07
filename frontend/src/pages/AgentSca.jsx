import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import Pager from "../components/Pager";
import { getAgentDetail, getAgentSca } from "../api/wazuh";
import { formatWazuhTimestamp } from "../utils/time";

const formatAgentId = (raw) => {
  if (raw === null || raw === undefined) return "";
  if (typeof raw === "number") return String(raw).padStart(3, "0");
  const str = String(raw);
  return /^[0-9]+$/.test(str) && str.length < 3 ? str.padStart(3, "0") : str;
};

const toDisplay = (value, fallback = "-") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) {
    const labels = value
      .map((item) => toDisplay(item, ""))
      .filter(Boolean);
    return labels.length ? labels.join(", ") : fallback;
  }
  if (typeof value === "object") {
    for (const key of ["name", "id", "value", "label", "title", "text"]) {
      if (value[key] !== null && value[key] !== undefined && typeof value[key] !== "object") {
        return String(value[key]);
      }
    }
    return fallback;
  }
  return String(value);
};

const toNumber = (value, fallback = 0) => {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
};

const normalizeAgentDetail = (data) => {
  if (Array.isArray(data)) return data[0] || {};
  if (data?.data?.affected_items?.length) return data.data.affected_items[0];
  if (data?.affected_items?.length) return data.affected_items[0];
  return data || {};
};

const normalizeScaResult = (value) => {
  const token = String(value || "").trim().toLowerCase().replace(/_/g, " ");
  if (["pass", "passed", "ok", "success"].includes(token)) return "passed";
  if (["fail", "failed", "error"].includes(token)) return "failed";
  if (["not applicable", "n/a", "na", "invalid"].includes(token)) return "not applicable";
  return token || "unknown";
};

const scaResultClass = (value) => {
  const result = normalizeScaResult(value);
  if (result === "passed") return "success";
  if (result === "failed") return "failed";
  if (result === "not applicable") return "pending";
  return "neutral";
};

const riskClass = (risk) => {
  const value = String(risk || "").toLowerCase();
  if (value === "critical" || value === "high") return "failed";
  if (value === "medium") return "pending";
  if (value === "low") return "success";
  return "neutral";
};

export default function AgentSca() {
  const navigate = useNavigate();
  const { agentId: routeAgentId } = useParams();
  const agentId = formatAgentId(routeAgentId || "");
  const selectedAgentRef = useRef(agentId);

  const [agentDetail, setAgentDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");

  const [scaPolicies, setScaPolicies] = useState([]);
  const [scaRecommendations, setScaRecommendations] = useState([]);
  const [scaTelemetry, setScaTelemetry] = useState({});
  const [scaSource, setScaSource] = useState("");
  const [scaError, setScaError] = useState("");

  const [scaRecommendationsPage, setScaRecommendationsPage] = useState(1);
  const [scaRecommendationsPageSize, setScaRecommendationsPageSize] = useState(5);
  const [scaChecksPage, setScaChecksPage] = useState(1);
  const [scaChecksPageSize, setScaChecksPageSize] = useState(50);
  const [scaCheckFilter, setScaCheckFilter] = useState("failed");
  const [scaCheckSearch, setScaCheckSearch] = useState("");

  useEffect(() => {
    selectedAgentRef.current = agentId;
  }, [agentId]);

  const loadScaWorkspace = useCallback((withLoading = false) => {
    if (!agentId) return;
    if (withLoading) {
      setDetailLoading(true);
    }

    Promise.allSettled([
      getAgentDetail(agentId),
      getAgentSca(agentId, {
        limit: 200,
        includeChecks: true,
        checksLimit: 20000,
        recommendationLimit: 80,
      }),
    ])
      .then((results) => {
        if (selectedAgentRef.current !== agentId) return;

        const readValue = (idx, fallback = null) =>
          results[idx]?.status === "fulfilled" ? results[idx].value : fallback;
        const readError = (idx) =>
          results[idx]?.status === "rejected"
            ? (results[idx].reason?.response?.data?.detail || results[idx].reason?.message || "Request failed")
            : "";

        const detailRes = readValue(0, { data: {} });
        const scaRes = readValue(1, { data: {} });
        const detail = normalizeAgentDetail(detailRes.data);
        if (detail?.id || detail?.agent_id) {
          detail.id = formatAgentId(detail.id || detail.agent_id);
        }
        setAgentDetail(detail);

        const payload = scaRes.data || {};
        setScaPolicies(Array.isArray(payload.policies) ? payload.policies : []);
        setScaRecommendations(Array.isArray(payload.recommendations) ? payload.recommendations : []);
        setScaTelemetry(payload.telemetry_context && typeof payload.telemetry_context === "object"
          ? payload.telemetry_context
          : {});
        setScaSource(payload.source || "");

        const scaRequestError = readError(1);
        setScaError(payload.error || scaRequestError || "");
        setDetailError(readError(0) || scaRequestError || "");
      })
      .catch((err) => {
        if (selectedAgentRef.current !== agentId) return;
        const message = err.response?.data?.detail || err.message || "Unable to load SCA workspace.";
        setDetailError(message);
        setScaError(message);
        setScaPolicies([]);
        setScaRecommendations([]);
        setScaTelemetry({});
      })
      .finally(() => {
        if (withLoading && selectedAgentRef.current === agentId) {
          setDetailLoading(false);
        }
      });
  }, [agentId]);

  useEffect(() => {
    if (!agentId) return;
    loadScaWorkspace(true);
  }, [agentId, loadScaWorkspace]);

  const summary = useMemo(() => {
    const detail = agentDetail && typeof agentDetail === "object" ? agentDetail : {};
    return {
      id: toDisplay(agentId),
      name: toDisplay(detail.name || detail.hostname || detail.id || detail.agent_id || `Agent ${agentId}`),
      status: toDisplay(detail.status, "unknown"),
      os: toDisplay(detail.os?.name || detail.os?.platform || detail.os?.version || detail.os, "unknown"),
      group: toDisplay(detail.group || detail.group_name || detail.groups),
      lastSeen: formatWazuhTimestamp(
        detail.last_keepalive ||
        detail.lastKeepAlive ||
        detail.status?.last_keepalive ||
        detail.status?.lastKeepAlive ||
        "-"
      ),
    };
  }, [agentDetail, agentId]);

  const scaChecks = useMemo(() => {
    if (!Array.isArray(scaPolicies) || scaPolicies.length === 0) return [];
    const rows = [];
    scaPolicies.forEach((policy) => {
      const checks = Array.isArray(policy?.checks) ? policy.checks : [];
      checks.forEach((check, idx) => {
        rows.push({
          key: `${policy?.policy_id || policy?.policy_name || "policy"}-${check?.id || idx + 1}-${idx}`,
          policyId: policy?.policy_id || "",
          policyName: toDisplay(policy?.policy_name || policy?.name || policy?.policy_id, "Policy"),
          id: toDisplay(check?.id || check?.check_id, String(idx + 1)),
          title: toDisplay(check?.title || check?.name, `Check ${idx + 1}`),
          result: normalizeScaResult(check?.result || check?.status),
          reason: toDisplay(check?.reason, ""),
          remediation: toDisplay(check?.remediation, ""),
        });
      });
    });
    return rows;
  }, [scaPolicies]);

  const scaChecksSummary = useMemo(() => {
    const summaryState = { passed: 0, failed: 0, notApplicable: 0, unknown: 0, total: 0 };
    scaChecks.forEach((check) => {
      const result = normalizeScaResult(check?.result);
      if (result === "passed") summaryState.passed += 1;
      else if (result === "failed") summaryState.failed += 1;
      else if (result === "not applicable") summaryState.notApplicable += 1;
      else summaryState.unknown += 1;
    });
    summaryState.total = summaryState.passed + summaryState.failed + summaryState.notApplicable + summaryState.unknown;
    return summaryState;
  }, [scaChecks]);

  const filteredScaChecks = useMemo(() => {
    const filterValue = normalizeScaResult(scaCheckFilter);
    const query = String(scaCheckSearch || "").trim().toLowerCase();
    return scaChecks.filter((check) => {
      const result = normalizeScaResult(check?.result);
      if (filterValue !== "all" && result !== filterValue) return false;
      if (!query) return true;
      const haystack = [
        check?.policyName,
        check?.policyId,
        check?.id,
        check?.title,
        check?.reason,
        check?.remediation,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [scaCheckFilter, scaCheckSearch, scaChecks]);

  const pagedScaRecommendations = useMemo(() => {
    const start = (Math.max(1, scaRecommendationsPage) - 1) * Math.max(1, scaRecommendationsPageSize);
    return scaRecommendations.slice(start, start + Math.max(1, scaRecommendationsPageSize));
  }, [scaRecommendations, scaRecommendationsPage, scaRecommendationsPageSize]);

  const pagedFilteredScaChecks = useMemo(() => {
    const start = (Math.max(1, scaChecksPage) - 1) * Math.max(1, scaChecksPageSize);
    return filteredScaChecks.slice(start, start + Math.max(1, scaChecksPageSize));
  }, [filteredScaChecks, scaChecksPage, scaChecksPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(scaRecommendations.length / Math.max(1, scaRecommendationsPageSize)));
    if (scaRecommendationsPage > totalPages) {
      setScaRecommendationsPage(totalPages);
    }
  }, [scaRecommendations.length, scaRecommendationsPage, scaRecommendationsPageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredScaChecks.length / Math.max(1, scaChecksPageSize)));
    if (scaChecksPage > totalPages) {
      setScaChecksPage(totalPages);
    }
  }, [filteredScaChecks.length, scaChecksPage, scaChecksPageSize]);

  useEffect(() => {
    setScaRecommendationsPage(1);
    setScaChecksPage(1);
  }, [agentId]);

  useEffect(() => {
    setScaChecksPage(1);
  }, [scaCheckFilter, scaCheckSearch]);

  return (
    <div className="page page-route-agent-sca page-route-agents">
      <div className="page-header">
        <div>
          <h2>Agent SCA Workspace</h2>
          <p className="muted">Focused SCA analysis for hardening priorities and full policy checks.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" type="button" onClick={() => navigate("/agents")}>
            Back to Agents
          </button>
          <button
            className="btn secondary"
            type="button"
            onClick={() => loadScaWorkspace(true)}
            disabled={!agentId}
          >
            Refresh
          </button>
          <button
            className="btn"
            type="button"
            onClick={() =>
              navigate(`/alerts?query=${encodeURIComponent(`agent.id:${agentId || "*"} AND (rule.groups:sca OR rule.description:sca)`)}`)
            }
            disabled={!agentId}
          >
            Hunt SCA Alerts
          </button>
        </div>
      </div>

      {!agentId ? (
        <div className="empty-state">Missing agent ID. Open this page from the Agents workspace.</div>
      ) : null}

      {detailLoading && <div className="empty-state">Loading SCA workspace...</div>}
      {(detailError || scaError) && !detailLoading ? (
        <div className="empty-state">
          {detailError || scaError}
        </div>
      ) : null}

      <div className="grid-4 mb-12">
        <div className="stat-card">
          <div className="stat-label">Agent</div>
          <div className="stat-value">{summary.id}</div>
          <div className="stat-sub">{summary.name}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div className="stat-value">{summary.status}</div>
          <div className="stat-sub">{summary.group}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Policies</div>
          <div className="stat-value">{scaPolicies.length}</div>
          <div className="stat-sub">Source {toDisplay(scaSource || "n/a")}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last Keepalive</div>
          <div className="stat-value">{summary.lastSeen}</div>
          <div className="stat-sub">{summary.os}</div>
        </div>
      </div>

      <div className="agents-sca-layout">
        <div className="card agents-sca-priority-card">
          <div className="card-header">
            <div>
              <h3>SCA Hardening Priorities</h3>
              <p className="muted">Failed checks ranked from this agent&apos;s alerts, vulnerabilities, FIM, and MITRE context.</p>
            </div>
            <span className="chip">Top {scaRecommendations.length}</span>
          </div>
          <div className="grid-4 mb-12">
            <div className="stat-card">
              <div className="stat-label">High Alerts</div>
              <div className="stat-value">{toNumber(scaTelemetry?.alerts_high, 0)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Critical Vulns</div>
              <div className="stat-value">{toNumber(scaTelemetry?.vulnerabilities_critical, 0)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">FIM Events</div>
              <div className="stat-value">{toNumber(scaTelemetry?.fim_events, 0)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Failed Checks</div>
              <div className="stat-value">{scaChecksSummary.failed}</div>
            </div>
          </div>
          {scaRecommendations.length === 0 ? (
            <div className="empty-state">No ranked failed checks available for this agent yet.</div>
          ) : (
            <div className="list agents-sca-priority-list">
              <div className="list-scroll agents-sca-priority-scroll">
                {pagedScaRecommendations.map((rec) => {
                  const title = toDisplay(rec.title);
                  const reason = toDisplay(rec.reason);
                  const remediation = toDisplay(rec.remediation, "-");
                  return (
                    <div
                      key={`${rec.policy_id || rec.policy_name}-${rec.check_id}-${rec.rank}`}
                      className="list-item agents-sca-priority-item"
                    >
                      <div className="list-item split">
                        <div>
                          <strong>
                            #{toDisplay(rec.rank)} | {toDisplay(rec.policy_name)} | Check {toDisplay(rec.check_id)}
                          </strong>
                          <div className="meta-line agents-sca-cell-text">{title}</div>
                        </div>
                        <span className={`status-pill ${riskClass(rec.priority)}`}>
                          {toDisplay(rec.priority)}
                        </span>
                      </div>
                      <div className="meta-line mt-6 agents-sca-cell-text agents-sca-clamp-2" title={reason}>
                        {reason}
                      </div>
                      {remediation !== "-" ? (
                        <details className="agents-sca-remediation-details mt-8">
                          <summary>View remediation guidance</summary>
                          <div className="meta-line mt-6 agents-sca-cell-text">{remediation}</div>
                        </details>
                      ) : null}
                    </div>
                  );
                })}
              </div>
              <Pager
                total={scaRecommendations.length}
                page={scaRecommendationsPage}
                pageSize={scaRecommendationsPageSize}
                onPageChange={setScaRecommendationsPage}
                onPageSizeChange={(size) => {
                  setScaRecommendationsPageSize(size);
                  setScaRecommendationsPage(1);
                }}
                pageSizeOptions={[5, 10, 25, 50]}
                label="recommendations"
              />
            </div>
          )}
        </div>

        <div className="card agents-sca-checks-card">
          <div className="card-header">
            <div>
              <h3>Full SCA Checks</h3>
              <p className="muted">All checks from all policy snapshots for this agent.</p>
            </div>
            <span className="chip">Total {scaChecksSummary.total}</span>
          </div>
          <div className="page-actions mb-12 agents-sca-checks-controls">
            <select
              className="input"
              value={scaCheckFilter}
              onChange={(e) => setScaCheckFilter(e.target.value)}
            >
              <option value="failed">Failed only</option>
              <option value="passed">Passed only</option>
              <option value="not applicable">Not applicable</option>
              <option value="unknown">Unknown</option>
              <option value="all">All</option>
            </select>
            <input
              className="input"
              value={scaCheckSearch}
              onChange={(e) => setScaCheckSearch(e.target.value)}
              placeholder="Search check ID, title, remediation, policy"
            />
          </div>
          <div className="grid-4 mb-12">
            <div className="stat-card">
              <div className="stat-label">Passed</div>
              <div className="stat-value">{scaChecksSummary.passed}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Failed</div>
              <div className="stat-value">{scaChecksSummary.failed}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Not Applicable</div>
              <div className="stat-value">{scaChecksSummary.notApplicable}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Unknown</div>
              <div className="stat-value">{scaChecksSummary.unknown}</div>
            </div>
          </div>
          <div className="table-scroll agents-sca-checks-scroll">
            <table className="table compact readable agents-sca-checks-table">
              <thead>
                <tr>
                  <th className="agents-col-policy">Policy</th>
                  <th className="agents-col-check">Check</th>
                  <th className="agents-col-result">Result</th>
                  <th className="agents-col-title">Title</th>
                  <th className="agents-col-guidance">Guidance</th>
                </tr>
              </thead>
              <tbody>
                {filteredScaChecks.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="text-center">
                      No checks match this filter.
                    </td>
                  </tr>
                ) : (
                  pagedFilteredScaChecks.map((check) => {
                    const policy = toDisplay(check.policyName);
                    const checkId = toDisplay(check.id);
                    const result = toDisplay(check.result);
                    const title = toDisplay(check.title);
                    const reason = toDisplay(check.reason, "-");
                    const remediation = toDisplay(check.remediation, "-");
                    const hasGuidance = reason !== "-" || remediation !== "-";
                    return (
                      <tr key={check.key}>
                        <td className="agents-col-policy">
                          <span className="agents-sca-cell-text" title={policy}>{policy}</span>
                        </td>
                        <td className="agents-col-check">{checkId}</td>
                        <td className="agents-col-result">
                          <span className={`status-pill ${scaResultClass(check.result)}`}>
                            {result}
                          </span>
                        </td>
                        <td className="agents-col-title">
                          <span className="agents-sca-cell-text agents-sca-clamp-2" title={title}>
                            {title}
                          </span>
                        </td>
                        <td className="agents-col-guidance">
                          {!hasGuidance ? (
                            <span className="agents-sca-cell-text">-</span>
                          ) : (
                            <details className="agents-sca-remediation-details">
                              <summary>View guidance</summary>
                              {reason !== "-" ? (
                                <div className="meta-line mt-6 agents-sca-cell-text">
                                  <strong>Reason:</strong> {reason}
                                </div>
                              ) : null}
                              {remediation !== "-" ? (
                                <div className="meta-line mt-6 agents-sca-cell-text">
                                  <strong>Remediation:</strong> {remediation}
                                </div>
                              ) : null}
                            </details>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <Pager
            total={filteredScaChecks.length}
            page={scaChecksPage}
            pageSize={scaChecksPageSize}
            onPageChange={setScaChecksPage}
            onPageSizeChange={(size) => {
              setScaChecksPageSize(size);
              setScaChecksPage(1);
            }}
            pageSizeOptions={[25, 50, 100, 200]}
            label="checks"
          />
        </div>
      </div>
    </div>
  );
}

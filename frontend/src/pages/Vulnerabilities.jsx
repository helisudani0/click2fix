import { useCallback, useEffect, useMemo, useState } from "react";
import Pager from "../components/Pager";
import { getAgents, getAgentGroups, getVulnerabilities } from "../api/wazuh";
import { formatWazuhTimestamp } from "../utils/time";

const SEVERITIES = ["critical", "high", "medium", "low"];
const INITIAL_FETCH_LIMIT = 2500;
const FETCH_LIMIT_MAX = 20000;

const normalizeAgents = (data) => {
  if (Array.isArray(data)) return data;
  if (data?.data?.affected_items) return data.data.affected_items;
  if (data?.affected_items) return data.affected_items;
  if (data?.items) return data.items;
  return [];
};

const formatAgentId = (value) => {
  if (value === null || value === undefined) return "";
  const raw = String(value).trim();
  if (!raw) return "";
  return /^[0-9]+$/.test(raw) && raw.length < 3 ? raw.padStart(3, "0") : raw;
};

const titleCase = (value) => {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "-";
  return text[0].toUpperCase() + text.slice(1);
};

const severityClass = (value) => {
  const key = String(value || "").toLowerCase();
  if (key === "critical" || key === "high") return "failed";
  if (key === "medium") return "pending";
  if (key === "low") return "success";
  return "neutral";
};

const toDisplay = (value, fallback = "-") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) {
    const list = value.map((item) => toDisplay(item, "")).filter(Boolean);
    return list.length ? list.join(", ") : fallback;
  }
  if (typeof value === "object") {
    for (const key of ["name", "label", "id", "title", "text", "value"]) {
      if (value[key] !== null && value[key] !== undefined && typeof value[key] !== "object") {
        return String(value[key]);
      }
    }
    return fallback;
  }
  return String(value);
};

const compactList = (items = [], limit = 6) => {
  const list = Array.isArray(items) ? items.filter(Boolean) : [];
  if (!list.length) return "-";
  if (list.length <= limit) return list.join(", ");
  return `${list.slice(0, limit).join(", ")} +${list.length - limit} more`;
};

const containsAny = (text, markers) => {
  const haystack = String(text || "").toLowerCase();
  return markers.some((marker) => haystack.includes(String(marker || "").toLowerCase()));
};

const deriveIndicators = (row) => {
  const blob = [
    row?.title,
    row?.rationale,
    row?.cwe_reference,
    row?.scanner_reference,
    ...(Array.isArray(row?.references) ? row.references : []),
  ].join(" ");
  const indicators = [];
  if (containsAny(blob, ["known exploited vulnerabilities", "known-exploited-vulnerabilities", "cisa.gov/known-exploited", "kev"])) {
    indicators.push("KEV");
  }
  if (containsAny(blob, ["remote code execution", "rce", "unauthenticated", "internet", "network"])) {
    indicators.push("Remote exploit");
  }
  if (containsAny(blob, ["privilege escalation", "local privilege escalation", "elevate privileges", "lpe"])) {
    indicators.push("Priv-esc");
  }
  if (containsAny(`${row?.package?.source || ""} ${row?.package?.condition || ""} ${row?.package?.name || ""}`, ["os", "windows update", "linux kernel", "kernel", "kb"])) {
    indicators.push("OS-level");
  }
  return indicators;
};

const buildWazuhDetail = (row) => {
  if (!row || typeof row !== "object") return {};
  return {
    id: row.id,
    cve: row.cve,
    title: row.title,
    severity: row.severity,
    score: row.score,
    package: row.package || {},
    classification: row.classification,
    type: row.type,
    rationale: row.rationale,
    cwe_reference: row.cwe_reference,
    assigner: row.assigner,
    status: row.status,
    published: row.published,
    updated: row.updated,
    last_seen: row.last_seen,
    references: Array.isArray(row.references) ? row.references : [],
    scanner_reference: row.scanner_reference,
    affected_count: row.affected_count,
    affected_agents: Array.isArray(row.affected_agents) ? row.affected_agents : [],
    analyst_indicators: deriveIndicators(row),
  };
};

export default function Vulnerabilities() {
  const [agents, setAgents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [targetMode, setTargetMode] = useState("fleet");
  const [targetValue, setTargetValue] = useState("");
  const [targetAgentIds, setTargetAgentIds] = useState([]);
  const [agentSearch, setAgentSearch] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState([...SEVERITIES]);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [items, setItems] = useState([]);
  const [summary, setSummary] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    total: 0,
    records: 0,
    affected_agents: 0,
  });
  const [targetAgents, setTargetAgents] = useState({
    critical: [],
    high: [],
    medium: [],
    low: [],
  });
  const [source, setSource] = useState("-");
  const [error, setError] = useState("");
  const [liveEnabled, setLiveEnabled] = useState(true);
  const [feedPage, setFeedPage] = useState(1);
  const [feedPageSize, setFeedPageSize] = useState(50);
  const [fetchLimit, setFetchLimit] = useState(INITIAL_FETCH_LIMIT);
  const [queryLimit, setQueryLimit] = useState(INITIAL_FETCH_LIMIT);
  const [truncated, setTruncated] = useState(false);
  const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState("");

  const loadAgents = useCallback(async () => {
    try {
      const response = await getAgents(undefined, { limit: 5000 });
      const list = normalizeAgents(response.data).map((row) => ({
        id: formatAgentId(row.id || row.agent_id),
        name: String(row.name || row.hostname || row.id || row.agent_id || "-"),
        status: String(row.status || "unknown"),
        group: Array.isArray(row.groups)
          ? row.groups.join(", ")
          : String(row.group || row.group_name || ""),
      }));
      setAgents(list.filter((row) => row.id));
    } catch {
      setAgents([]);
    }
  }, []);

  const loadGroups = useCallback(async () => {
    try {
      const response = await getAgentGroups();
      const list = Array.isArray(response.data) ? response.data : [];
      setGroups(
        list.map((group) => String(group.name || group.id || group).trim()).filter(Boolean)
      );
    } catch {
      setGroups([]);
    }
  }, []);

  const buildScopeParams = useCallback(() => {
    if (targetMode === "group") {
      return targetValue.trim() ? { group: targetValue.trim() } : null;
    }
    if (targetMode === "agent") {
      return targetValue.trim() ? { agent_id: formatAgentId(targetValue.trim()) } : null;
    }
    if (targetMode === "multi") {
      return targetAgentIds.length ? { agent_ids: targetAgentIds.join(",") } : null;
    }
    return {};
  }, [targetAgentIds, targetMode, targetValue]);

  const loadVulns = useCallback(async () => {
    const scope = buildScopeParams();
    if (scope === null) {
      setStatus("Choose a valid target before loading vulnerabilities.");
      setItems([]);
      return;
    }

    setLoading(true);
    setStatus("");
    setError("");
    try {
      const response = await getVulnerabilities({ ...scope, limit: fetchLimit });
      const payload = response.data || {};
      setItems(Array.isArray(payload.items) ? payload.items : []);
      setSummary({
        critical: Number(payload.summary?.critical || 0),
        high: Number(payload.summary?.high || 0),
        medium: Number(payload.summary?.medium || 0),
        low: Number(payload.summary?.low || 0),
        unknown: Number(payload.summary?.unknown || 0),
        total: Number(payload.summary?.total || 0),
        records: Number(payload.summary?.records || 0),
        affected_agents: Number(payload.summary?.affected_agents || 0),
      });
      setTargetAgents({
        critical: Array.isArray(payload.target_agents?.critical) ? payload.target_agents.critical : [],
        high: Array.isArray(payload.target_agents?.high) ? payload.target_agents.high : [],
        medium: Array.isArray(payload.target_agents?.medium) ? payload.target_agents.medium : [],
        low: Array.isArray(payload.target_agents?.low) ? payload.target_agents.low : [],
      });
      setSource(String(payload.source || "-"));
      setError(String(payload.error || ""));
      setTruncated(Boolean(payload.truncated));
      setQueryLimit(Number(payload.query_limit || fetchLimit));
    } catch (err) {
      setItems([]);
      setSummary({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
        total: 0,
        records: 0,
        affected_agents: 0,
      });
      setTargetAgents({ critical: [], high: [], medium: [], low: [] });
      setSource("-");
      setError(err.response?.data?.detail || err.message || "Failed to load vulnerabilities.");
      setTruncated(false);
      setQueryLimit(fetchLimit);
    } finally {
      setLoading(false);
    }
  }, [buildScopeParams, fetchLimit]);

  useEffect(() => {
    loadAgents();
    loadGroups();
  }, [loadAgents, loadGroups]);

  useEffect(() => {
    loadVulns();
  }, [loadVulns]);

  useEffect(() => {
    if (!liveEnabled) return undefined;
    const timer = setInterval(() => {
      loadVulns();
    }, 30000);
    return () => clearInterval(timer);
  }, [liveEnabled, loadVulns]);

  const filteredAgents = useMemo(() => {
    const query = agentSearch.trim().toLowerCase();
    if (!query) return agents.slice(0, 80);
    return agents
      .filter((agent) =>
        agent.id.toLowerCase().includes(query)
        || agent.name.toLowerCase().includes(query)
        || agent.group.toLowerCase().includes(query)
      )
      .slice(0, 80);
  }, [agentSearch, agents]);

  const filteredItems = useMemo(() => {
    const allowed = new Set(selectedSeverities.map((value) => String(value).toLowerCase()));
    return items.filter((row) => allowed.has(String(row?.severity || "").toLowerCase()));
  }, [items, selectedSeverities]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredItems.length / feedPageSize));
    if (feedPage > totalPages) {
      setFeedPage(totalPages);
    }
  }, [feedPage, feedPageSize, filteredItems.length]);

  useEffect(() => {
    if (!filteredItems.length) {
      if (selectedVulnerabilityId) setSelectedVulnerabilityId("");
      return;
    }
    const stillPresent = filteredItems.some((row) => String(row?.id || "") === String(selectedVulnerabilityId || ""));
    if (!stillPresent) {
      setSelectedVulnerabilityId(String(filteredItems[0]?.id || ""));
    }
  }, [filteredItems, selectedVulnerabilityId]);

  const pagedItems = useMemo(() => {
    const start = (feedPage - 1) * feedPageSize;
    return filteredItems.slice(start, start + feedPageSize);
  }, [feedPage, feedPageSize, filteredItems]);

  const selectedItem = useMemo(
    () => filteredItems.find((row) => String(row?.id || "") === String(selectedVulnerabilityId || "")) || filteredItems[0] || null,
    [filteredItems, selectedVulnerabilityId]
  );

  const wazuhDetailJson = useMemo(
    () => JSON.stringify(buildWazuhDetail(selectedItem), null, 2),
    [selectedItem]
  );

  const toggleSeverity = (severity) => {
    setSelectedSeverities((current) => (
      current.includes(severity)
        ? current.filter((value) => value !== severity)
        : [...current, severity]
    ));
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Vulnerabilities</h2>
          <p className="muted">Analyst-first Wazuh vulnerability triage view with expanded metadata, affected assets, and reference context.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={loadVulns} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh Feed"}
          </button>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}
      {error ? <div className="empty-state">Feed error: {error}</div> : null}

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Scope and Filters</h3>
            <p className="muted">Scope the Wazuh vulnerability feed by agent, group, or fleet, then narrow the analyst view by severity.</p>
          </div>
        </div>

        <div className="list">
          <div className="list-item readable">
            <div className="muted">Target Scope</div>
            <div className="page-actions mt-8">
              <select className="input" value={targetMode} onChange={(event) => setTargetMode(event.target.value)}>
                <option value="fleet">Fleet</option>
                <option value="group">Agent group</option>
                <option value="agent">Single agent</option>
                <option value="multi">Multiple agents</option>
              </select>
              <label className="inline-check">
                <input
                  type="checkbox"
                  checked={liveEnabled}
                  onChange={(event) => setLiveEnabled(Boolean(event.target.checked))}
                />
                <span>Live refresh every 30s</span>
              </label>
            </div>

            {targetMode === "group" ? (
              <div className="page-actions mt-10">
                <select className="input" value={targetValue} onChange={(event) => setTargetValue(event.target.value)}>
                  <option value="">Select group</option>
                  {groups.map((group) => (
                    <option key={group} value={group}>
                      {group}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}

            {targetMode === "agent" ? (
              <div className="page-actions mt-10">
                <input
                  className="input"
                  value={targetValue}
                  onChange={(event) => setTargetValue(event.target.value)}
                  placeholder="Agent ID (example: 004)"
                  list="vulnerabilityAgentIds"
                />
                <datalist id="vulnerabilityAgentIds">
                  {agents.slice(0, 150).map((agent) => (
                    <option key={`agent-${agent.id}`} value={agent.id}>
                      {agent.name}
                    </option>
                  ))}
                </datalist>
              </div>
            ) : null}

            {targetMode === "multi" ? (
              <div className="mt-10">
                <div className="page-actions">
                  <input
                    className="input"
                    placeholder="Search agents by ID, name, or group"
                    value={agentSearch}
                    onChange={(event) => setAgentSearch(event.target.value)}
                  />
                  <button
                    type="button"
                    className="btn secondary"
                    onClick={() => setTargetAgentIds(filteredAgents.map((agent) => agent.id))}
                  >
                    Select Visible
                  </button>
                  <button
                    type="button"
                    className="btn secondary"
                    onClick={() => setTargetAgentIds([])}
                  >
                    Clear
                  </button>
                </div>
                <div className="meta-line mt-6">Selected: {targetAgentIds.length}</div>
                <div className="list-scroll mt-10 h-240">
                  <div className="list">
                    {filteredAgents.map((agent) => {
                      const selected = targetAgentIds.includes(agent.id);
                      return (
                        <button
                          key={agent.id}
                          type="button"
                          className={`list-item ${selected ? "selected" : ""}`}
                          onClick={() =>
                            setTargetAgentIds((current) => (
                              current.includes(agent.id)
                                ? current.filter((id) => id !== agent.id)
                                : [...current, agent.id]
                            ))
                          }
                        >
                          <div>
                            <strong>{agent.id}</strong> - {agent.name}
                            <div className="muted">{agent.group || "No group"}</div>
                          </div>
                          <span className={`status-pill ${selected ? "success" : "neutral"}`}>
                            {selected ? "Selected" : agent.status}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : null}
          </div>

          <div className="list-item readable">
            <div className="muted">Severity Filter</div>
            <div className="page-actions mt-8">
              {SEVERITIES.map((severity) => (
                <label key={severity} className="muted inline-check tight">
                  <input
                    type="checkbox"
                    checked={selectedSeverities.includes(severity)}
                    onChange={() => toggleSeverity(severity)}
                  />
                  {titleCase(severity)}
                </label>
              ))}
            </div>
          </div>

          <div className="list-item readable">
            <div className="muted">Feed Window</div>
            <div className="page-actions mt-8">
              <span className="chip">Source: {source}</span>
              <span className="chip">Query limit: {queryLimit}</span>
              <span className="chip">Fetched: {items.length}</span>
              <span className="chip">Visible: {filteredItems.length}</span>
              {truncated ? <span className="status-pill pending">Truncated</span> : null}
              {truncated && fetchLimit < FETCH_LIMIT_MAX ? (
                <button
                  type="button"
                  className="btn secondary"
                  onClick={() => setFetchLimit((current) => Math.min(FETCH_LIMIT_MAX, current * 2))}
                >
                  Load More From Wazuh
                </button>
              ) : null}
            </div>
          </div>
        </div>
      </div>

      <div className="stat-grid">
        {SEVERITIES.map((severity) => (
          <div className="stat-card" key={severity}>
            <div className="stat-label">{titleCase(severity)}</div>
            <div className="stat-value">{Number(summary?.[severity] || 0)}</div>
            <div className="stat-sub">
              Agents affected: {Array.isArray(targetAgents?.[severity]) ? targetAgents[severity].length : 0}
            </div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Selected Vulnerability</h3>
              <p className="muted">Expanded Wazuh metadata for analyst review. Automated remediation controls were removed from this view.</p>
            </div>
          </div>

          {!selectedItem ? (
            <div className="empty-state">No vulnerability is currently selected.</div>
          ) : (
            <>
              <div>
                <div className="page-actions">
                  <span className={`status-pill ${severityClass(selectedItem.severity)}`}>
                    {titleCase(selectedItem.severity)}
                  </span>
                  {selectedItem.score !== null && selectedItem.score !== undefined ? (
                    <span className="chip">CVSS {selectedItem.score}</span>
                  ) : null}
                  <span className="chip">Status: {toDisplay(selectedItem.status)}</span>
                  <span className="chip">Affected: {selectedItem.affected_count || 0}</span>
                  {deriveIndicators(selectedItem).map((indicator) => (
                    <span className="chip" key={indicator}>{indicator}</span>
                  ))}
                </div>
                <h3 className="mt-10">{selectedItem.cve || selectedItem.title || "Vulnerability"}</h3>
                <div className="meta-line mt-6">{selectedItem.title || "-"}</div>
              </div>

              <div className="kv-grid">
                <div className="kv-row">
                  <div className="kv-key">Package</div>
                  <div className="kv-value">
                    {toDisplay(selectedItem.package?.name)} {selectedItem.package?.version ? `(${selectedItem.package.version})` : ""}
                  </div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Condition</div>
                  <div className="kv-value">{toDisplay(selectedItem.package?.condition)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Package Source</div>
                  <div className="kv-value">{toDisplay(selectedItem.package?.source)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Classification</div>
                  <div className="kv-value">{toDisplay(selectedItem.classification)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Type</div>
                  <div className="kv-value">{toDisplay(selectedItem.type)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">CWE</div>
                  <div className="kv-value">{toDisplay(selectedItem.cwe_reference)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Assigner</div>
                  <div className="kv-value">{toDisplay(selectedItem.assigner)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Published</div>
                  <div className="kv-value">{formatWazuhTimestamp(selectedItem.published)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Updated</div>
                  <div className="kv-value">{formatWazuhTimestamp(selectedItem.updated)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Last Seen</div>
                  <div className="kv-value">{formatWazuhTimestamp(selectedItem.last_seen)}</div>
                </div>
                <div className="kv-row">
                  <div className="kv-key">Scanner Ref</div>
                  <div className="kv-value">{toDisplay(selectedItem.scanner_reference)}</div>
                </div>
              </div>

              <div className="list-item readable">
                <div className="muted">Rationale / Description</div>
                <div className="mt-8">{toDisplay(selectedItem.rationale, "No rationale provided by Wazuh.")}</div>
              </div>

              <div className="list-item readable">
                <div className="muted">References</div>
                {Array.isArray(selectedItem.references) && selectedItem.references.length ? (
                  <div className="list mt-10">
                    {selectedItem.references.map((reference) => (
                      <a
                        key={reference}
                        href={reference}
                        target="_blank"
                        rel="noreferrer"
                        className="list-item clickable readable"
                      >
                        {reference}
                      </a>
                    ))}
                  </div>
                ) : (
                  <div className="meta-line mt-8">No references were provided in the Wazuh record.</div>
                )}
              </div>
            </>
          )}
        </div>

        <div className="stack-col gap-18">
          <div className="card">
            <div className="card-header">
              <div>
                <h3>Affected Assets</h3>
                <p className="muted">Host-level context from the Wazuh feed for the selected vulnerability.</p>
              </div>
            </div>

            {!selectedItem ? (
              <div className="empty-state">Select a vulnerability from the feed to inspect affected assets.</div>
            ) : (
              <div className="table-scroll h-240">
                <table className="table compact readable">
                  <thead>
                    <tr>
                      <th>Agent</th>
                      <th>IP</th>
                      <th>Platform</th>
                      <th>Group</th>
                      <th>Status</th>
                      <th>Local State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(selectedItem.affected_agents || []).length === 0 ? (
                      <tr>
                        <td colSpan="6" className="text-center">
                          No affected agent metadata available.
                        </td>
                      </tr>
                    ) : (
                      (selectedItem.affected_agents || []).map((agent) => (
                        <tr key={`${selectedItem.id}-${agent.id}`}>
                          <td>
                            <div>{agent.id}</div>
                            <div className="meta-line">{agent.name || "-"}</div>
                          </td>
                          <td>{toDisplay(agent.ip)}</td>
                          <td>{toDisplay(agent.platform)}</td>
                          <td>{compactList(agent.groups || [], 4)}</td>
                          <td>{toDisplay(agent.status)}</td>
                          <td>
                            {agent.local_closure ? (
                              <>
                                <div>{toDisplay(agent.local_closure.state)}</div>
                                <div className="meta-line">{toDisplay(agent.local_closure.reason)}</div>
                              </>
                            ) : (
                              <span className="muted">Open</span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <h3>Wazuh Detail JSON</h3>
                <p className="muted">Raw analyst-facing payload for the selected vulnerability after aggregation.</p>
              </div>
            </div>
            <pre className="code-block">{wazuhDetailJson}</pre>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Vulnerability Feed</h3>
            <p className="muted">
              Source: {source}. Unique vulnerabilities: {summary.total}. Records scanned: {summary.records}. Affected agents: {summary.affected_agents}.
            </p>
          </div>
        </div>

        <div className="table-scroll">
          <table className="table readable compact">
            <thead>
              <tr>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Package</th>
                <th>Affected</th>
                <th>Status</th>
                <th>Timeline</th>
                <th>References</th>
              </tr>
            </thead>
            <tbody>
              {pagedItems.length === 0 ? (
                <tr>
                  <td colSpan="7" className="muted">
                    No vulnerabilities in this scope/filter.
                  </td>
                </tr>
              ) : (
                pagedItems.map((row) => {
                  const references = Array.isArray(row.references) ? row.references : [];
                  return (
                    <tr
                      key={row.id}
                      className={`clickable ${String(selectedItem?.id || "") === String(row.id || "") ? "selected" : ""}`}
                      onClick={() => setSelectedVulnerabilityId(String(row.id || ""))}
                    >
                      <td>
                        <div>{row.cve || "-"}</div>
                        <div className="meta-line">{row.title || "-"}</div>
                        <div className="meta-line">
                          {deriveIndicators(row).join(" | ") || "No special indicators derived"}
                        </div>
                      </td>
                      <td>
                        <span className={`status-pill ${severityClass(row.severity)}`}>
                          {titleCase(row.severity)}
                        </span>
                        {row.score !== null && row.score !== undefined ? (
                          <div className="meta-line">CVSS {row.score}</div>
                        ) : null}
                      </td>
                      <td>
                        <div>{toDisplay(row.package?.name)}</div>
                        <div className="meta-line">
                          {toDisplay(row.package?.version)} | {toDisplay(row.package?.source)}
                        </div>
                        <div className="meta-line">{toDisplay(row.package?.condition)}</div>
                      </td>
                      <td>
                        <div>{row.affected_count || 0} agent(s)</div>
                        <div className="meta-line">
                          {compactList(
                            (row.affected_agents || []).map((agent) =>
                              `${agent.id}${agent.name ? `:${agent.name}` : ""}`
                            ),
                            4
                          )}
                        </div>
                      </td>
                      <td>
                        <div>{toDisplay(row.status)}</div>
                        <div className="meta-line">
                          {toDisplay(row.classification)} | {toDisplay(row.type)}
                        </div>
                      </td>
                      <td>
                        <div>Published: {formatWazuhTimestamp(row.published)}</div>
                        <div className="meta-line">Updated: {formatWazuhTimestamp(row.updated)}</div>
                        <div className="meta-line">Last seen: {formatWazuhTimestamp(row.last_seen)}</div>
                      </td>
                      <td>
                        {references.length ? (
                          <a href={references[0]} target="_blank" rel="noreferrer">
                            Open ({references.length})
                          </a>
                        ) : (
                          <span className="muted">-</span>
                        )}
                        {row.scanner_reference ? (
                          <div className="meta-line">{row.scanner_reference}</div>
                        ) : null}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <Pager
          total={filteredItems.length}
          page={feedPage}
          pageSize={feedPageSize}
          onPageChange={setFeedPage}
          onPageSizeChange={(size) => {
            setFeedPageSize(size);
            setFeedPage(1);
          }}
          pageSizeOptions={[25, 50, 100]}
          label="vulnerabilities"
        />
      </div>
    </div>
  );
}

import api from "./client";

const AGENT_CACHE_TTL_MS = 15000;
const agentCache = new Map();
const ALERT_CACHE_TTL_MS = 4000;
const alertsCache = new Map();
const EXECUTION_CACHE_TTL_MS = 3000;
const executionsCache = new Map();

const buildApiUrl = (path, params = {}) => {
  const base = api.defaults.baseURL || "/api";
  const normalizedBase = base.endsWith("/") ? base.slice(0, -1) : base;
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${normalizedBase}${normalizedPath}`, window.location.origin);
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value === undefined || value === null || String(value).trim() === "") return;
    url.searchParams.set(key, String(value));
  });
  return url.toString();
};

let tenantV2SupportPromise = null;

const readTenantGovernanceCapability = async () => {
  try {
    const response = await api.get("/system/version");
    const caps = response?.data?.capabilities;
    if (caps && Object.prototype.hasOwnProperty.call(caps, "tenant_governance_v2")) {
      return Boolean(caps.tenant_governance_v2);
    }
  } catch {
    // Treat any version-capability read failure as unsupported to avoid
    // accidental v2 probing on mixed/stale frontend-backend pairs.
  }
  return false;
};

export const hasTenantGovernanceV2Support = async () => {
  if (!tenantV2SupportPromise) {
    tenantV2SupportPromise = readTenantGovernanceCapability().catch(() => false);
  }
  return tenantV2SupportPromise;
};

const unwrapV2 = (response) => {
  const payload = response?.data;
  if (payload && typeof payload === "object" && "data" in payload) {
    return {
      ...response,
      data: payload.data,
      message: payload.message,
      meta: payload.meta,
      status: payload.status,
    };
  }
  return response;
};

const unwrapV2Items = (response) => {
  const normalized = unwrapV2(response);
  const items = normalized?.data?.items;
  return {
    ...normalized,
    data: Array.isArray(items) ? items : [],
  };
};

const normalizeListResponseData = (payload, keys = ["data", "items", "affected_items", "actions", "commands"]) => {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  for (const key of keys) {
    const value = payload?.[key];
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") {
      for (const nestedKey of keys) {
        if (Array.isArray(value?.[nestedKey])) return value[nestedKey];
      }
    }
  }
  return [];
};

const agentCacheKey = (group, options = {}) => {
  const compact = options.compact !== false ? "compact" : "full";
  const status = String(options.status || "").trim().toLowerCase();
  const platform = String(options.platform || "").trim().toLowerCase();
  const limit = Number(options.limit || 0) || 0;
  return `${String(group || "").trim().toLowerCase()}|${compact}|${status}|${platform}|${limit}`;
};

const stableParamsKey = (params = {}) =>
  Object.entries(params)
    .filter((entry) => entry[1] !== undefined && entry[1] !== null && String(entry[1]).trim() !== "")
    .sort(([left], [right]) => String(left).localeCompare(String(right)))
    .map(([key, value]) => `${key}:${Array.isArray(value) ? value.join(",") : String(value)}`)
    .join("|");

const readCachedResponse = (cache, key, ttlMs, force) => {
  const now = Date.now();
  const cached = cache.get(key);
  if (!force && cached?.data && now - cached.ts <= ttlMs) {
    return {
      data: cached.data,
      status: 200,
      statusText: "OK",
      headers: {},
      config: {},
    };
  }
  return null;
};

const writePromiseCache = (cache, key, request, cached) => {
  cache.set(key, { ts: cached?.ts || 0, data: cached?.data || null, promise: request });
  return request.finally(() => {
    const entry = cache.get(key);
    if (entry?.promise) {
      cache.set(key, { ...entry, promise: null });
    }
  });
};

export const invalidateAgentsCache = (group, options = {}) => {
  if (group === undefined && Object.keys(options || {}).length === 0) {
    agentCache.clear();
    return;
  }
  agentCache.delete(agentCacheKey(group, options));
};

export const getAgents = (group, options = {}) => {
  const opts = options && typeof options === "object" ? options : {};
  const force = Boolean(opts.force);
  const ttlMs = Number(opts.ttlMs || AGENT_CACHE_TTL_MS);
  const key = agentCacheKey(group, opts);
  const now = Date.now();
  const cached = agentCache.get(key);
  if (!force && cached?.data && now - cached.ts <= ttlMs) {
    return Promise.resolve({
      data: cached.data,
      status: 200,
      statusText: "OK",
      headers: {},
      config: {},
    });
  }
  if (!force && cached?.promise) {
    return cached.promise;
  }

  const params = {};
  if (group) params.group = group;
  if (opts.compact !== false) params.compact = true;
  if (opts.status) params.status = opts.status;
  if (opts.platform) params.platform = opts.platform;
  if (opts.limit) params.limit = opts.limit;

  const request = api
    .get("/agents", { params: Object.keys(params).length ? params : undefined })
    .then((res) => {
      agentCache.set(key, { ts: Date.now(), data: res.data, promise: null });
      return res;
    })
    .catch((err) => {
      const stale = agentCache.get(key);
      if (stale?.data) {
        return {
          data: stale.data,
          status: 200,
          statusText: "OK",
          headers: {},
          config: {},
        };
      }
      throw err;
    })
    .finally(() => {
      const entry = agentCache.get(key);
      if (entry?.promise) {
        agentCache.set(key, { ...entry, promise: null });
      }
    });

  agentCache.set(key, { ts: cached?.ts || 0, data: cached?.data || null, promise: request });
  return request;
};
export const getAgentGroups = () => api.get("/agents/groups");
export const getAlerts = (query, limit, options = {}) => {
  const opts = options && typeof options === "object" ? options : {};
  const force = Boolean(opts.force);
  const ttlMs = Number(opts.ttlMs || ALERT_CACHE_TTL_MS);
  const params = { ...(query ? { q: query } : {}) };
  if (Number.isFinite(limit) && Number(limit) > 0) params.limit = Number(limit);
  if (opts.agentId) params.agent_id = opts.agentId;
  if (typeof opts.agentOnly === "boolean") params.agent_only = opts.agentOnly;
  if (opts.start) params.start = opts.start;
  if (opts.end) params.end = opts.end;
  if (opts.includeTotal) params.include_total = true;
  if (opts.includeSummary) params.include_summary = true;

  const key = stableParamsKey(params);
  const cached = alertsCache.get(key);
  const quickHit = readCachedResponse(alertsCache, key, ttlMs, force);
  if (quickHit) return Promise.resolve(quickHit);
  if (!force && cached?.promise) return cached.promise;

  const request = api
    .get("/alerts", { params })
    .then((res) => {
      alertsCache.set(key, { ts: Date.now(), data: res.data, promise: null });
      return res;
    })
    .catch((err) => {
      const stale = alertsCache.get(key);
      if (stale?.data) {
        return {
          data: stale.data,
          status: 200,
          statusText: "OK",
          headers: {},
          config: {},
        };
      }
      throw err;
    });

  return writePromiseCache(alertsCache, key, request, cached);
};
export const getActions = () =>
  api.get("/actions").then((response) => ({
    ...response,
    data: normalizeListResponseData(response?.data),
  }));
export const getActionConnectorStatus = () => api.get("/actions/connector-status");
export const testActionPath = (payload) => api.post("/actions/test", payload);
export const validateAction = (payload) => api.post("/actions/validate", payload);
export const testActionCapability = (payload) => api.post("/actions/test-capability", payload);
export const getIntegrationStatus = () => api.get("/integration/status");
export const getAgentDetail = (agentId) => api.get(`/agents/${agentId}`);
export const getAgentVulnerabilities = (agentId, limit = 200) =>
  api.get(`/agents/${agentId}/vulnerabilities`, { params: { limit } });
export const getVulnerabilities = (params = {}) =>
  api.get("/vulnerabilities", { params });
export const closeVulnerabilityLocal = (payload) =>
  api.post("/vulnerabilities/local-close", payload);
export const getVulnerabilityAiPlan = (payload = {}) =>
  api.post("/vulnerabilities/ai-remediation-plan", payload);
export const getAgentInventory = (agentId, limit = 100) =>
  api.get(`/agents/${agentId}/inventory`, { params: { limit } });
export const getAgentEvents = (agentId, hours = 24) =>
  api.get(`/agents/${agentId}/events`, { params: { hours } });
export const getAgentFim = (agentId, limit = 50) =>
  api.get(`/agents/${agentId}/fim`, { params: { limit } });
export const getAgentMitre = (agentId) => api.get(`/agents/${agentId}/mitre`);
export const getAgentSca = (agentId, options = {}) => {
  const params = {};
  if (typeof options === "number") {
    params.limit = options;
  } else if (options && typeof options === "object") {
    if (options.limit) params.limit = options.limit;
    if (typeof options.includeChecks === "boolean") params.include_checks = options.includeChecks;
    if (options.checksLimit) params.checks_limit = options.checksLimit;
    if (options.recommendationLimit) params.recommendation_limit = options.recommendationLimit;
  }
  return api.get(`/agents/${agentId}/sca`, { params: Object.keys(params).length ? params : undefined });
};
export const getFleetScaHardening = (params = {}) =>
  api.get("/agents/sca/fleet", { params });
export const getPlaybooks = () => api.get("/playbooks");
export const getPlaybook = (name) => api.get(`/playbooks/${name}`);
export const generatePlaybook = (payload) => api.post("/playbooks/generate", payload);
export const generatePlaybookWithAi = (payload = {}) =>
  api.post("/playbooks/generate", { ...payload, use_ai: true });
export const savePlaybook = (payload) => api.post("/playbooks", payload);
export const executePlaybook = (payload) => api.post("/playbooks/execute", payload);
export const seedDefaultPlaybooks = (payload = {}) =>
  api.post("/playbooks/seed-defaults", payload);
export const getAnalyticsOverview = () => api.get("/analytics/overview");
export const getSystemAiConfig = () => api.get("/system/ai-config");
export const updateSystemAiConfig = (payload = {}) => api.put("/system/ai-config", payload);
export const getKillChain = (caseId) =>
  api.get("/analytics/kill-chain", { params: caseId ? { case_id: caseId } : undefined });
export const getAlertSummary = (alertId) => api.get(`/analytics/alert/${alertId}`);
export const getHourlyVolume = (hours = 72) =>
  api.get("/analytics/hourly", { params: { hours } });
export const getAnalyticsAiInsights = (payload = {}) =>
  api.post("/analytics/ai-insights", payload);
export const correlateIncidents = (payload = {}) =>
  api.post("/incidents/correlate", payload);
export const getIncidents = (params = {}) =>
  api.get("/incidents", { params });
export const updateIncident = (incidentId, payload = {}) =>
  api.patch(`/incidents/${incidentId}`, payload);
export const assignIncident = (incidentId, payload = {}) =>
  api.post(`/incidents/${incidentId}/assign`, payload);
export const createAutomationContextProfile = (payload = {}) =>
  api.post("/governance/automation-context/profiles", payload);
export const getAutomationContextProfiles = (params = {}) =>
  api.get("/governance/automation-context/profiles", { params });
export const validateAutomationContext = (payload = {}) =>
  api.post("/governance/automation-context/validate", payload);
export const getCorrelatedExecutionAlerts = (executionId, params = {}) =>
  api.get("/governance/alerts/correlated", {
    params: { execution_id: executionId, ...params },
  });
export const getSchedulerJobs = () => api.get("/scheduler/jobs");
export const createSchedulerJob = (payload = {}) => api.post("/scheduler/jobs", payload);
export const updateSchedulerJob = (jobId, payload = {}) =>
  api.patch(`/scheduler/jobs/${jobId}`, payload);
export const runSchedulerJobNow = (jobId) =>
  api.post(`/scheduler/jobs/${jobId}/run-now`);
export const getAudit = (params) => api.get("/audit", { params });
export const getChanges = (params) => api.get("/changes", { params });
export const createChange = (payload) => api.post("/changes", payload);
export const approveChange = (id) => api.post(`/changes/${id}/approve`);
export const closeChange = (id) => api.post(`/changes/${id}/close`);

export const getTenantsV2 = (params = {}) =>
  api.get("/v2/tenants", { params }).then(unwrapV2Items);
export const createTenantV2 = (payload = {}) =>
  api.post("/v2/tenants", payload).then(unwrapV2);
export const getTenantUsersV2 = (tenantId, params = {}) =>
  api.get(`/v2/tenants/${tenantId}/users`, { params }).then(unwrapV2Items);
export const createTenantUserV2 = (tenantId, payload = {}) =>
  api.post(`/v2/tenants/${tenantId}/users`, payload).then(unwrapV2);
export const getRetentionPoliciesV2 = (tenantId, params = {}) =>
  api.get(`/v2/tenants/${tenantId}/retention-policies`, { params }).then(unwrapV2Items);
export const upsertRetentionPolicyV2 = (tenantId, dataClass, payload = {}) =>
  api.put(`/v2/tenants/${tenantId}/retention-policies/${dataClass}`, payload).then(unwrapV2);

export const getEventLifecycleSummaryV2 = (params = {}) =>
  api.get("/v2/events/lifecycle/summary", { params }).then(unwrapV2);
export const applyEventLifecycleV2 = (payload = {}) =>
  api.post("/v2/events/lifecycle/apply", payload).then(unwrapV2);
export const applyEventLifecycleBatchV2 = (payload = {}) =>
  api.post("/v2/events/lifecycle/apply-all", payload).then(unwrapV2);
export const getEventTimeSeriesV2 = (params = {}) =>
  api.get("/v2/events/timeseries", { params }).then(unwrapV2);
export const getEventCorrelationV2 = (params = {}) =>
  api.get("/v2/events/correlate", { params }).then(unwrapV2);

export const getCases = () => api.get("/cases");
export const getCaseDetail = (caseId) => api.get(`/cases/${caseId}`);
export const createCaseRecord = (payload = {}) =>
  api.post("/cases", null, {
    params: {
      title: payload?.title,
      description: payload?.description
    }
  });
export const attachCaseAlert = (caseId, alertId) =>
  api.post(`/cases/${caseId}/alerts`, null, { params: { alert_id: alertId } });
export const addCaseNote = (caseId, note) =>
  api.post(`/cases/${caseId}/notes`, null, { params: { note } });
export const getCaseTimeline = (caseId, params = {}) =>
  api.get(`/cases/${caseId}/timeline`, { params });
export const getCaseAiSummary = (caseId) =>
  api.get(`/cases/${caseId}/ai-summary`);
export const getCaseTimelineExportUrl = (caseId, params = {}) =>
  buildApiUrl(`/cases/${caseId}/timeline/export`, params);
export const getCaseAttachments = (caseId) =>
  api.get(`/cases/${caseId}/attachments`);
export const uploadCaseAttachment = (caseId, formData) =>
  api.post(`/cases/${caseId}/attachments`, formData, {
    headers: { "Content-Type": "multipart/form-data" }
  });
export const downloadCaseAttachment = (caseId, attachmentId) =>
  api.get(`/cases/${caseId}/attachments/${attachmentId}`, { responseType: "blob" });
export const getCaseAttackPath = (caseId) =>
  api.get(`/cases/${caseId}/attack-path`);
export const getCaseIocGraph = (caseId) =>
  api.get(`/cases/${caseId}/ioc-graph`);
export const getCaseEvidence = (caseId) =>
  api.get(`/cases/${caseId}/evidence`);
export const uploadCaseEvidence = (caseId, formData) =>
  api.post(`/cases/${caseId}/evidence`, formData, {
    headers: { "Content-Type": "multipart/form-data" }
  });
export const downloadCaseEvidence = (caseId, evidenceId) =>
  api.get(`/cases/${caseId}/evidence/${evidenceId}/download`, { responseType: "blob" });
export const lockCaseEvidence = (caseId, evidenceId) =>
  api.post(`/cases/${caseId}/evidence/${evidenceId}/lock`);
export const getCaseEvidenceCustody = (caseId, evidenceId) =>
  api.get(`/cases/${caseId}/evidence/${evidenceId}/custody`);
export const updateCaseRisk = (caseId, payload = {}) =>
  api.post(`/cases/${caseId}/risk`, payload);
export const updateCaseStatus = (caseId, status) =>
  api.post(`/cases/${caseId}/status`, null, { params: { status } });

export const requestApproval = (payload) =>
  api.post("/approvals/request", payload);
export const generateApprovalAiJustification = (payload = {}) =>
  api.post("/approvals/ai-justification", payload);

export const getPendingApprovals = (params = {}) =>
  api.get("/approvals/pending", { params });

export const decideApproval = (id, payload = {}) => {
  const decision = String(payload?.decision || payload?.action || payload?.status || "").trim().toLowerCase() === "reject"
    ? "reject"
    : "approve";
  const path = decision === "reject" ? `/approvals/${id}/reject` : `/approvals/${id}/approve`;
  return api.post(path, { ...payload, decision });
};

export const runAction = (payload) =>
  api.post("/remediate", payload);

export const runGlobalShell = (payload) =>
  api.post("/actions/global-shell", payload);

export const getExecutions = (params = {}, options = {}) => {
  const rawParams = params && typeof params === "object" ? { ...params } : {};
  const rawOptions = options && typeof options === "object" ? options : {};
  const force = Boolean(rawOptions.force || rawParams.force);
  const ttlMs = Number(rawOptions.ttlMs || rawParams.ttlMs || EXECUTION_CACHE_TTL_MS);
  delete rawParams.force;
  delete rawParams.ttlMs;

  const key = stableParamsKey(rawParams);
  const cached = executionsCache.get(key);
  const quickHit = readCachedResponse(executionsCache, key, ttlMs, force);
  if (quickHit) return Promise.resolve(quickHit);
  if (!force && cached?.promise) return cached.promise;

  const request = api
    .get("/executions", { params: rawParams })
    .then((res) => {
      executionsCache.set(key, { ts: Date.now(), data: res.data, promise: null });
      return res;
    })
    .catch((err) => {
      const stale = executionsCache.get(key);
      if (stale?.data) {
        return {
          data: stale.data,
          status: 200,
          statusText: "OK",
          headers: {},
          config: {},
        };
      }
      throw err;
    });

  return writePromiseCache(executionsCache, key, request, cached);
};
export const getExecutionDetail = (executionId) =>
  api.get(`/executions/${executionId}`);
export const getExecutionAiTriage = (executionId) =>
  api.get(`/executions/${executionId}/ai-triage`);
export const suggestGlobalShellCommand = (payload) =>
  api.post("/actions/global-shell/assist", payload);

export const retryFailedExecution = (executionId, payload = {}) =>
  api.post(`/executions/${executionId}/retry-failed`, payload);

export const getExecutionHealth = () =>
  api.get("/executions/health");


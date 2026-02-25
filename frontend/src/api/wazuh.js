import api from "./client";

const AGENT_CACHE_TTL_MS = 15000;
const agentCache = new Map();
const ALERT_CACHE_TTL_MS = 4000;
const alertsCache = new Map();
const EXECUTION_CACHE_TTL_MS = 3000;
const executionsCache = new Map();

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
export const getAlerts = (query, limit = 100, options = {}) => {
  const opts = options && typeof options === "object" ? options : {};
  const force = Boolean(opts.force);
  const ttlMs = Number(opts.ttlMs || ALERT_CACHE_TTL_MS);
  const params = { limit, ...(query ? { q: query } : {}) };
  if (opts.agentId) params.agent_id = opts.agentId;
  if (typeof opts.agentOnly === "boolean") params.agent_only = opts.agentOnly;
  if (opts.start) params.start = opts.start;
  if (opts.end) params.end = opts.end;

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
export const getActions = () => api.get("/actions");
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
export const getAgentInventory = (agentId, limit = 100) =>
  api.get(`/agents/${agentId}/inventory`, { params: { limit } });
export const getAgentEvents = (agentId, hours = 24) =>
  api.get(`/agents/${agentId}/events`, { params: { hours } });
export const getAgentFim = (agentId, limit = 50) =>
  api.get(`/agents/${agentId}/fim`, { params: { limit } });
export const getAgentMitre = (agentId) => api.get(`/agents/${agentId}/mitre`);
export const getAgentSca = (agentId, limit = 10) =>
  api.get(`/agents/${agentId}/sca`, { params: { limit } });
export const getPlaybooks = () => api.get("/playbooks");
export const getPlaybook = (name) => api.get(`/playbooks/${name}`);
export const generatePlaybook = (payload) => api.post("/playbooks/generate", payload);
export const savePlaybook = (payload) => api.post("/playbooks", payload);
export const executePlaybook = (payload) => api.post("/playbooks/execute", payload);
export const seedDefaultPlaybooks = (payload = {}) =>
  api.post("/playbooks/seed-defaults", payload);
export const getAnalyticsOverview = () => api.get("/analytics/overview");
export const getKillChain = (caseId) =>
  api.get("/analytics/kill-chain", { params: caseId ? { case_id: caseId } : undefined });
export const getAlertSummary = (alertId) => api.get(`/analytics/alert/${alertId}`);
export const getHourlyVolume = (hours = 72) =>
  api.get("/analytics/hourly", { params: { hours } });
export const getAudit = (params) => api.get("/audit", { params });
export const getChanges = (params) => api.get("/changes", { params });
export const createChange = (payload) => api.post("/changes", payload);
export const approveChange = (id) => api.post(`/changes/${id}/approve`);
export const closeChange = (id) => api.post(`/changes/${id}/close`);

export const requestApproval = (payload) =>
  api.post("/approvals/request", payload);

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

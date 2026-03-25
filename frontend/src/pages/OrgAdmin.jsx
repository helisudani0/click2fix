import { useEffect, useMemo, useState } from "react";
import {
  applyEventLifecycleV2,
  applyEventLifecycleBatchV2,
  createTenantUserV2,
  createTenantV2,
  getEventLifecycleSummaryV2,
  getRetentionPoliciesV2,
  getTenantsV2,
  getTenantUsersV2,
  upsertRetentionPolicyV2,
} from "../api/wazuh";
import { formatWazuhTimestamp } from "../utils/time";

const RETENTION_STREAMS = ["events", "alerts"];

const normalizeText = (value) => String(value || "").trim();
const normalizeKey = (value) => normalizeText(value).toLowerCase();

const createRetentionForm = (overrides = {}) => ({
  data_class: "events",
  storage_backend: "event_indexer",
  stream: "events",
  warm_after_days: "30",
  cold_after_days: "90",
  archive_after_days: "180",
  delete_after_days: "365",
  archive_backend: "",
  legal_hold: false,
  status: "active",
  notes: "",
  ...overrides,
});

const policyToForm = (policy) =>
  createRetentionForm({
    data_class: normalizeKey(policy?.data_class || "events") || "events",
    storage_backend: normalizeKey(policy?.storage_backend || "event_indexer") || "event_indexer",
    stream: normalizeKey(policy?.stream || policy?.data_class || "events") || "events",
    warm_after_days: String(policy?.warm_after_days ?? 30),
    cold_after_days: String(policy?.cold_after_days ?? 90),
    archive_after_days: String(policy?.archive_after_days ?? 180),
    delete_after_days:
      policy?.delete_after_days === null || policy?.delete_after_days === undefined
        ? ""
        : String(policy.delete_after_days),
    archive_backend: normalizeText(policy?.archive_backend),
    legal_hold: Boolean(policy?.legal_hold),
    status: normalizeKey(policy?.status || "active") || "active",
    notes: normalizeText(policy?.notes),
  });

const toRetentionPayload = (form) => ({
  storage_backend: "event_indexer",
  stream: normalizeKey(form?.stream || "events") || "events",
  warm_after_days: Number(form?.warm_after_days || 0),
  cold_after_days: Number(form?.cold_after_days || 0),
  archive_after_days: Number(form?.archive_after_days || 0),
  delete_after_days:
    normalizeText(form?.delete_after_days) === ""
      ? null
      : Number(form?.delete_after_days || 0),
  archive_backend: normalizeText(form?.archive_backend) || null,
  legal_hold: Boolean(form?.legal_hold),
  status: normalizeKey(form?.status || "active") || "active",
  notes: normalizeText(form?.notes) || null,
});

const retentionTone = (status) => {
  const normalized = normalizeKey(status);
  if (normalized === "active") return "success";
  if (normalized === "paused") return "pending";
  return "neutral";
};

const formatRetentionWindows = (policy) => {
  const warm = Number(policy?.warm_after_days || 0);
  const cold = Number(policy?.cold_after_days || 0);
  const archive = Number(policy?.archive_after_days || 0);
  const deleteAfter = policy?.delete_after_days === null || policy?.delete_after_days === undefined
    ? "keep"
    : `${policy.delete_after_days}d delete`;
  return `${warm}d warm / ${cold}d cold / ${archive}d archive / ${deleteAfter}`;
};

const latestAppliedAt = (policies) =>
  policies
    .map((policy) => normalizeText(policy?.last_applied_at))
    .filter(Boolean)
    .sort()
    .at(-1) || "";

const getErrorMessage = (err, fallback) =>
  err?.response?.data?.detail
  || err?.response?.data?.message
  || err?.message
  || fallback;

export default function OrgAdmin() {
  const [tenants, setTenants] = useState([]);
  const [users, setUsers] = useState([]);
  const [retentionPolicies, setRetentionPolicies] = useState([]);
  const [selectedTenantId, setSelectedTenantId] = useState("");
  const [selectedPolicyDataClass, setSelectedPolicyDataClass] = useState("");

  const [tenantName, setTenantName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [retentionForm, setRetentionForm] = useState(createRetentionForm());

  const [lifecycleSummary, setLifecycleSummary] = useState(null);
  const [lifecyclePreview, setLifecyclePreview] = useState(null);
  const [lifecycleBatchPreview, setLifecycleBatchPreview] = useState(null);

  const [loadingTenants, setLoadingTenants] = useState(false);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [loadingRetention, setLoadingRetention] = useState(false);
  const [loadingLifecycleSummary, setLoadingLifecycleSummary] = useState(false);
  const [savingRetention, setSavingRetention] = useState(false);
  const [runningLifecycle, setRunningLifecycle] = useState(false);
  const [runningLifecycleBatch, setRunningLifecycleBatch] = useState(false);

  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const selectedTenant = useMemo(
    () => tenants.find((tenant) => String(tenant?.tenant_id) === String(selectedTenantId)) || null,
    [tenants, selectedTenantId],
  );

  const selectedPolicy = useMemo(
    () => retentionPolicies.find((policy) => normalizeKey(policy?.data_class) === normalizeKey(selectedPolicyDataClass)) || null,
    [retentionPolicies, selectedPolicyDataClass],
  );

  const summaryCounts = lifecycleSummary?.summary?.counts || null;
  const previewResult = lifecyclePreview?.result || null;
  const previewChanged = previewResult?.changed || null;
  const batchPreviewResults = Array.isArray(lifecycleBatchPreview?.results) ? lifecycleBatchPreview.results : [];

  const activeRetentionCount = retentionPolicies.filter((policy) => normalizeKey(policy?.status) === "active").length;
  const legalHoldCount = retentionPolicies.filter((policy) => Boolean(policy?.legal_hold)).length;
  const activePolicyDataClasses = useMemo(
    () => retentionPolicies
      .filter((policy) => normalizeKey(policy?.status) === "active")
      .map((policy) => normalizeKey(policy?.data_class))
      .filter(Boolean),
    [retentionPolicies],
  );

  const clearFeedback = () => {
    setMessage(null);
    setError(null);
  };

  const loadTenants = async () => {
    setLoadingTenants(true);
    try {
      const response = await getTenantsV2();
      const items = Array.isArray(response?.data) ? response.data : [];
      setTenants(items);
      setSelectedTenantId((current) => {
        if (current && items.some((tenant) => String(tenant?.tenant_id) === String(current))) {
          return current;
        }
        return items[0]?.tenant_id ? String(items[0].tenant_id) : "";
      });
    } catch (err) {
      setError(getErrorMessage(err, "Failed to load tenants."));
    } finally {
      setLoadingTenants(false);
    }
  };

  const loadUsers = async (tenantId) => {
    if (!tenantId) {
      setUsers([]);
      return;
    }
    setLoadingUsers(true);
    try {
      const response = await getTenantUsersV2(Number(tenantId));
      setUsers(Array.isArray(response?.data) ? response.data : []);
    } catch (err) {
      setUsers([]);
      setError(getErrorMessage(err, "Failed to load tenant users."));
    } finally {
      setLoadingUsers(false);
    }
  };

  const loadRetentionPolicies = async (tenantId) => {
    if (!tenantId) {
      setRetentionPolicies([]);
      setSelectedPolicyDataClass("");
      setLifecycleSummary(null);
      setLifecyclePreview(null);
      setLifecycleBatchPreview(null);
      return;
    }
    setLoadingRetention(true);
    try {
      const response = await getRetentionPoliciesV2(Number(tenantId));
      const items = Array.isArray(response?.data) ? response.data : [];
      setRetentionPolicies(items);
      setSelectedPolicyDataClass((current) => {
        if (current && items.some((policy) => normalizeKey(policy?.data_class) === normalizeKey(current))) {
          return current;
        }
        return items[0]?.data_class || "";
      });
      if (items.length === 0) {
        setLifecycleSummary(null);
        setLifecyclePreview(null);
        setLifecycleBatchPreview(null);
      }
    } catch (err) {
      setRetentionPolicies([]);
      setSelectedPolicyDataClass("");
      setLifecycleSummary(null);
      setLifecyclePreview(null);
      setLifecycleBatchPreview(null);
      setError(getErrorMessage(err, "Failed to load retention policies."));
    } finally {
      setLoadingRetention(false);
    }
  };

  const loadLifecycleSummary = async (tenantId, dataClass) => {
    if (!tenantId || !dataClass) {
      setLifecycleSummary(null);
      return;
    }
    setLoadingLifecycleSummary(true);
    try {
      const response = await getEventLifecycleSummaryV2({
        tenant_id: Number(tenantId),
        data_class: normalizeKey(dataClass),
      });
      setLifecycleSummary(response?.data || null);
    } catch (err) {
      if ([404, 409].includes(Number(err?.response?.status || 0))) {
        setLifecycleSummary(null);
      } else {
        setLifecycleSummary(null);
        setError(getErrorMessage(err, "Failed to load lifecycle summary."));
      }
    } finally {
      setLoadingLifecycleSummary(false);
    }
  };

  const refreshWorkspace = async () => {
    clearFeedback();
    await loadTenants();
    if (selectedTenantId) {
      await Promise.all([
        loadUsers(selectedTenantId),
        loadRetentionPolicies(selectedTenantId),
      ]);
    }
  };

  useEffect(() => {
    loadTenants();
  }, []);

  useEffect(() => {
    if (!selectedTenantId) {
      setUsers([]);
      setRetentionPolicies([]);
      setSelectedPolicyDataClass("");
      setRetentionForm(createRetentionForm());
      setLifecycleSummary(null);
      setLifecyclePreview(null);
      setLifecycleBatchPreview(null);
      return;
    }
    loadUsers(selectedTenantId);
    loadRetentionPolicies(selectedTenantId);
  }, [selectedTenantId]);

  useEffect(() => {
    if (selectedPolicy) {
      setRetentionForm(policyToForm(selectedPolicy));
      setLifecyclePreview(null);
      return;
    }
    if (!selectedPolicyDataClass) {
      setRetentionForm(createRetentionForm());
      setLifecyclePreview(null);
    }
  }, [selectedPolicy, selectedPolicyDataClass]);

  useEffect(() => {
    if (!selectedTenantId || !selectedPolicy) {
      setLifecycleSummary(null);
      return;
    }
    if (normalizeKey(selectedPolicy?.status) !== "active") {
      setLifecycleSummary(null);
      return;
    }
    loadLifecycleSummary(selectedTenantId, selectedPolicy.data_class);
  }, [selectedTenantId, selectedPolicy]);

  const createTenant = async () => {
    clearFeedback();
    const name = normalizeText(tenantName);
    if (!name) {
      setError("Tenant name is required.");
      return;
    }
    try {
      const response = await createTenantV2({ name });
      const tenant = response?.data || {};
      setTenantName("");
      setMessage(response?.message || "Tenant created.");
      await loadTenants();
      if (tenant?.tenant_id) {
        setSelectedTenantId(String(tenant.tenant_id));
      }
    } catch (err) {
      setError(getErrorMessage(err, "Failed to create tenant."));
    }
  };

  const createUser = async () => {
    clearFeedback();
    if (!selectedTenantId) {
      setError("Select a tenant first.");
      return;
    }
    const nextUsername = normalizeText(username);
    if (!nextUsername || !password) {
      setError("Username and password are required.");
      return;
    }
    try {
      const response = await createTenantUserV2(Number(selectedTenantId), {
        username: nextUsername,
        password,
        role,
      });
      setUsername("");
      setPassword("");
      setRole("analyst");
      setMessage(response?.message || "User created.");
      await loadUsers(selectedTenantId);
    } catch (err) {
      setError(getErrorMessage(err, "Failed to create tenant user."));
    }
  };

  const startNewPolicy = (preferredClass = "events") => {
    const normalizedClass = normalizeKey(preferredClass) || "events";
    setSelectedPolicyDataClass("");
    setRetentionForm(createRetentionForm({
      data_class: normalizedClass,
      stream: RETENTION_STREAMS.includes(normalizedClass) ? normalizedClass : "events",
    }));
    setLifecycleSummary(null);
    setLifecyclePreview(null);
    setLifecycleBatchPreview(null);
    clearFeedback();
  };

  const saveRetentionPolicy = async () => {
    clearFeedback();
    if (!selectedTenantId) {
      setError("Select a tenant first.");
      return;
    }
    const dataClass = normalizeKey(retentionForm?.data_class);
    if (!dataClass) {
      setError("Data class is required.");
      return;
    }
    const stream = normalizeKey(retentionForm?.stream || "events") || "events";
    if (!RETENTION_STREAMS.includes(stream)) {
      setError("Stream must be one of: events, alerts.");
      return;
    }
    setSavingRetention(true);
    try {
      const response = await upsertRetentionPolicyV2(
        Number(selectedTenantId),
        dataClass,
        {
          ...toRetentionPayload(retentionForm),
          stream,
        },
      );
      const policy = response?.data || {};
      setSelectedPolicyDataClass(policy?.data_class || dataClass);
      setMessage(response?.message || "Retention policy updated.");
      await loadRetentionPolicies(selectedTenantId);
      await loadLifecycleSummary(selectedTenantId, policy?.data_class || dataClass);
    } catch (err) {
      setError(getErrorMessage(err, "Failed to save retention policy."));
    } finally {
      setSavingRetention(false);
    }
  };

  const runLifecycle = async (dryRun) => {
    clearFeedback();
    if (!selectedTenantId || !selectedPolicy) {
      setError("Select and save a retention policy before running lifecycle actions.");
      return;
    }
    setRunningLifecycle(true);
    try {
      const response = await applyEventLifecycleV2({
        tenant_id: Number(selectedTenantId),
        data_class: normalizeKey(selectedPolicy.data_class),
        dry_run: Boolean(dryRun),
      });
      setLifecyclePreview(response?.data || null);
      setMessage(dryRun ? "Lifecycle preview generated." : (response?.message || "Lifecycle policy applied."));
      await loadRetentionPolicies(selectedTenantId);
      await loadLifecycleSummary(selectedTenantId, selectedPolicy.data_class);
    } catch (err) {
      setError(getErrorMessage(err, dryRun ? "Failed to preview lifecycle policy." : "Failed to apply lifecycle policy."));
    } finally {
      setRunningLifecycle(false);
    }
  };

  const runLifecycleBatch = async (dryRun) => {
    clearFeedback();
    if (!selectedTenantId) {
      setError("Select a tenant before running batch lifecycle actions.");
      return;
    }
    if (activePolicyDataClasses.length === 0) {
      setError("No active retention policies are available for batch lifecycle execution.");
      return;
    }
    setRunningLifecycleBatch(true);
    try {
      const response = await applyEventLifecycleBatchV2({
        tenant_id: Number(selectedTenantId),
        data_classes: activePolicyDataClasses,
        dry_run: Boolean(dryRun),
      });
      const result = response?.data || null;
      setLifecycleBatchPreview(result);
      setMessage(
        dryRun
          ? `Batch lifecycle preview generated for ${activePolicyDataClasses.length} active policies.`
          : (response?.message || "Batch lifecycle applied."),
      );
      await loadRetentionPolicies(selectedTenantId);
      if (selectedPolicy?.data_class && normalizeKey(selectedPolicy?.status) === "active") {
        await loadLifecycleSummary(selectedTenantId, selectedPolicy.data_class);
      }
    } catch (err) {
      setError(
        getErrorMessage(
          err,
          dryRun
            ? "Failed to preview batch lifecycle policy run."
            : "Failed to apply batch lifecycle policies.",
        ),
      );
    } finally {
      setRunningLifecycleBatch(false);
    }
  };

  return (
    <div className="page page-route-org-admin">
      <div className="page-header">
        <div>
          <h2>Org Admin</h2>
          <p className="muted">Manage tenants, provision users, and control retention policy lifecycle.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={refreshWorkspace}>
            Refresh
          </button>
        </div>
      </div>

      {message ? <div className="empty-state">{message}</div> : null}
      {error ? <div className="empty-state">{error}</div> : null}

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Tenants</div>
          <div className="stat-value">{tenants.length}</div>
          <div className="stat-sub">Available admin scopes</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Users</div>
          <div className="stat-value">{users.length}</div>
          <div className="stat-sub">Accounts in the selected tenant</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Retention Policies</div>
          <div className="stat-value">{retentionPolicies.length}</div>
          <div className="stat-sub">{activeRetentionCount} active policy windows</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Legal Hold</div>
          <div className="stat-value">{legalHoldCount}</div>
          <div className="stat-sub">Policies with preservation enabled</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Tenants</h3>
              <p className="muted">Create a tenant and choose the active admin scope.</p>
            </div>
            <span className="chip">{loadingTenants ? "loading" : `${tenants.length} tenants`}</span>
          </div>

          <div className="list">
            <label className="list-item">
              <div className="muted">New tenant</div>
              <input
                className="input mt-10"
                value={tenantName}
                onChange={(event) => setTenantName(event.target.value)}
                placeholder="Tenant name"
              />
              <div className="page-actions mt-12">
                <button className="btn" onClick={createTenant}>Create Tenant</button>
              </div>
            </label>

            <label className="list-item">
              <div className="muted">Selected tenant</div>
              <select
                className="input mt-10"
                value={selectedTenantId}
                onChange={(event) => setSelectedTenantId(event.target.value)}
              >
                {tenants.length === 0 ? <option value="">No tenants</option> : null}
                {tenants.map((tenant) => (
                  <option key={tenant.tenant_id} value={tenant.tenant_id}>
                    {tenant.name} (#{tenant.tenant_id})
                  </option>
                ))}
              </select>
            </label>

            <div className="list-item readable">
              <div className="muted">Tenant details</div>
              <div className="meta-line">Name: {selectedTenant?.name || "-"}</div>
              <div className="meta-line">Tenant ID: {selectedTenant?.tenant_id || "-"}</div>
              <div className="meta-line">Created: {formatWazuhTimestamp(selectedTenant?.created_at)}</div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Users</h3>
              <p className="muted">Provision analysts, admins, and superadmins for the selected tenant.</p>
            </div>
            <span className="chip">{loadingUsers ? "loading" : `${users.length} users`}</span>
          </div>

          <div className="list">
            <label className="list-item">
              <div className="muted">Username</div>
              <input
                className="input mt-10"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Username"
              />
            </label>
            <label className="list-item">
              <div className="muted">Password</div>
              <input
                className="input mt-10"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Password"
              />
            </label>
            <label className="list-item">
              <div className="muted">Role</div>
              <select
                className="input mt-10"
                value={role}
                onChange={(event) => setRole(event.target.value)}
              >
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
                <option value="superadmin">Superadmin</option>
              </select>
            </label>
            <div className="page-actions">
              <button className="btn" onClick={createUser} disabled={!selectedTenantId}>
                Create User
              </button>
            </div>

            <div className="table-scroll h-260">
              <table className="table compact">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {users.length === 0 ? (
                    <tr>
                      <td colSpan="3" className="text-center">No users found for this tenant.</td>
                    </tr>
                  ) : (
                    users.map((user) => (
                      <tr key={user.id || user.username}>
                        <td>{user.username}</td>
                        <td>{user.role}</td>
                        <td>{formatWazuhTimestamp(user.created_at)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h3>Retention Policy Management</h3>
            <p className="muted">Per-tenant retention windows, legal hold state, and lifecycle preview/apply.</p>
          </div>
          <div className="page-actions">
            <button className="btn secondary" onClick={() => startNewPolicy("events")} disabled={!selectedTenantId}>
              New Policy
            </button>
            <button
              className="btn secondary"
              onClick={() => loadRetentionPolicies(selectedTenantId)}
              disabled={!selectedTenantId}
            >
              Reload Policies
            </button>
          </div>
        </div>

        <div className="grid-4">
          <div className="list-item readable">
            <div className="muted">Tenant Scope</div>
            <div className="meta-line">{selectedTenant?.name || "No tenant selected"}</div>
          </div>
          <div className="list-item readable">
            <div className="muted">Policies Configured</div>
            <div className="meta-line">{retentionPolicies.length}</div>
          </div>
          <div className="list-item readable">
            <div className="muted">Active Policies</div>
            <div className="meta-line">{activeRetentionCount}</div>
          </div>
          <div className="list-item readable">
            <div className="muted">Last Applied</div>
            <div className="meta-line">{formatWazuhTimestamp(latestAppliedAt(retentionPolicies))}</div>
          </div>
        </div>

        <div className="grid-2">
          <div className="list">
            <div className="list-item readable">
              <div className="muted">Retention Catalog</div>
              <div className="meta-line">
                {loadingRetention
                  ? "Loading retention policies..."
                  : `${retentionPolicies.length} policies configured; ${legalHoldCount} with legal hold.`}
              </div>
            </div>

            <button
              type="button"
              className={`list-item clickable${selectedPolicyDataClass ? "" : " selected"}`}
              onClick={() => startNewPolicy("events")}
              disabled={!selectedTenantId}
            >
              <div>Create New Policy</div>
              <div className="meta-line">Start with an events retention baseline and save under any data class.</div>
            </button>

            {retentionPolicies.length === 0 ? (
              <div className="empty-state">No retention policies configured for this tenant.</div>
            ) : (
              retentionPolicies.map((policy) => (
                <button
                  key={policy.policy_id || policy.data_class}
                  type="button"
                  className={`list-item clickable${
                    normalizeKey(selectedPolicyDataClass) === normalizeKey(policy.data_class) ? " selected" : ""
                  }`}
                  onClick={() => {
                    setSelectedPolicyDataClass(policy.data_class);
                    clearFeedback();
                  }}
                >
                  <div className="list-item split">
                    <strong>{policy.data_class}</strong>
                    <span className={`status-pill ${retentionTone(policy.status)}`}>{policy.status || "unknown"}</span>
                  </div>
                  <div className="meta-line">
                    Stream: {policy.stream || "-"} | Backend: {policy.storage_backend || "event_indexer"}
                  </div>
                  <div className="meta-line">{formatRetentionWindows(policy)}</div>
                  <div className="meta-line">
                    Legal Hold: {policy.legal_hold ? "enabled" : "disabled"} | Last Applied: {formatWazuhTimestamp(policy.last_applied_at)}
                  </div>
                </button>
              ))
            )}
          </div>

          <div className="panel-stack">
            <div className="list-item readable">
              <div className="list-item split">
                <div>
                  <h3>{selectedPolicy ? `Edit ${selectedPolicy.data_class}` : "Create Retention Policy"}</h3>
                  <p className="muted">
                    {selectedPolicy
                      ? "Update retention windows and legal hold state for the selected data class."
                      : "Create a new retention policy for this tenant."}
                  </p>
                </div>
                <span className="chip">{retentionForm.storage_backend}</span>
              </div>

              <div className="grid-3 mt-12">
                <label className="list-item">
                  <div className="muted">Data Class</div>
                  <input
                    className="input mt-10"
                    value={retentionForm.data_class}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        data_class: normalizeKey(event.target.value),
                      }))
                    }
                    placeholder="events"
                  />
                </label>
                <label className="list-item">
                  <div className="muted">Stream</div>
                  <select
                    className="input mt-10"
                    value={retentionForm.stream}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        stream: normalizeKey(event.target.value),
                      }))
                    }
                  >
                    {RETENTION_STREAMS.map((stream) => (
                      <option key={stream} value={stream}>{stream}</option>
                    ))}
                  </select>
                </label>
                <label className="list-item">
                  <div className="muted">Status</div>
                  <select
                    className="input mt-10"
                    value={retentionForm.status}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        status: normalizeKey(event.target.value),
                      }))
                    }
                  >
                    <option value="active">active</option>
                    <option value="paused">paused</option>
                  </select>
                </label>
              </div>

              <div className="grid-4 mt-12">
                <label className="list-item">
                  <div className="muted">Warm After (Days)</div>
                  <input
                    className="input mt-10"
                    type="number"
                    min="1"
                    value={retentionForm.warm_after_days}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        warm_after_days: event.target.value,
                      }))
                    }
                  />
                </label>
                <label className="list-item">
                  <div className="muted">Cold After (Days)</div>
                  <input
                    className="input mt-10"
                    type="number"
                    min="2"
                    value={retentionForm.cold_after_days}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        cold_after_days: event.target.value,
                      }))
                    }
                  />
                </label>
                <label className="list-item">
                  <div className="muted">Archive After (Days)</div>
                  <input
                    className="input mt-10"
                    type="number"
                    min="3"
                    value={retentionForm.archive_after_days}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        archive_after_days: event.target.value,
                      }))
                    }
                  />
                </label>
                <label className="list-item">
                  <div className="muted">Delete After (Days)</div>
                  <input
                    className="input mt-10"
                    type="number"
                    min="4"
                    value={retentionForm.delete_after_days}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        delete_after_days: event.target.value,
                      }))
                    }
                    placeholder="Optional"
                  />
                </label>
              </div>

              <div className="grid-2 mt-12">
                <label className="list-item">
                  <div className="muted">Archive Backend</div>
                  <input
                    className="input mt-10"
                    value={retentionForm.archive_backend}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        archive_backend: event.target.value,
                      }))
                    }
                    placeholder="s3-glacier"
                  />
                </label>
                <label className="list-item">
                  <div className="muted">Legal Hold</div>
                  <select
                    className="input mt-10"
                    value={retentionForm.legal_hold ? "true" : "false"}
                    onChange={(event) =>
                      setRetentionForm((current) => ({
                        ...current,
                        legal_hold: event.target.value === "true",
                      }))
                    }
                  >
                    <option value="false">disabled</option>
                    <option value="true">enabled</option>
                  </select>
                </label>
              </div>

              <label className="list-item mt-12">
                <div className="muted">Notes</div>
                <textarea
                  className="input mt-10"
                  value={retentionForm.notes}
                  onChange={(event) =>
                    setRetentionForm((current) => ({
                      ...current,
                      notes: event.target.value,
                    }))
                  }
                  placeholder="Retention rationale, exceptions, or legal context."
                />
              </label>

              <div className="page-actions mt-12">
                <button className="btn" onClick={saveRetentionPolicy} disabled={!selectedTenantId || savingRetention}>
                  {savingRetention ? "Saving..." : "Save Policy"}
                </button>
                <button
                  className="btn secondary"
                  onClick={() => (
                    selectedPolicy
                      ? setRetentionForm(policyToForm(selectedPolicy))
                      : startNewPolicy(retentionForm.stream || "events")
                  )}
                  disabled={savingRetention}
                >
                  Reset Form
                </button>
              </div>
            </div>

            <div className="list-item readable">
              <div className="list-item split">
                <div>
                  <h3>Lifecycle Execution</h3>
                  <p className="muted">Preview tier transitions and apply the active policy to indexed data.</p>
                </div>
                {selectedPolicy ? (
                  <span className={`status-pill ${retentionTone(selectedPolicy.status)}`}>{selectedPolicy.status}</span>
                ) : null}
              </div>

              {!selectedPolicy ? (
                <div className="empty-state mt-12">Select or save a policy to preview lifecycle actions.</div>
              ) : normalizeKey(selectedPolicy.status) !== "active" ? (
                <div className="empty-state mt-12">Lifecycle preview/apply is available only while the policy is active.</div>
              ) : (
                <>
                  <div className="grid-4 mt-12">
                    <div className="list-item readable">
                      <div className="muted">Hot</div>
                      <div className="meta-line">{loadingLifecycleSummary ? "..." : (summaryCounts?.hot ?? 0)}</div>
                    </div>
                    <div className="list-item readable">
                      <div className="muted">Warm</div>
                      <div className="meta-line">{loadingLifecycleSummary ? "..." : (summaryCounts?.warm ?? 0)}</div>
                    </div>
                    <div className="list-item readable">
                      <div className="muted">Cold</div>
                      <div className="meta-line">{loadingLifecycleSummary ? "..." : (summaryCounts?.cold ?? 0)}</div>
                    </div>
                    <div className="list-item readable">
                      <div className="muted">Archive</div>
                      <div className="meta-line">{loadingLifecycleSummary ? "..." : (summaryCounts?.archive ?? 0)}</div>
                    </div>
                  </div>

                  <div className="grid-3 mt-12">
                    <div className="list-item readable">
                      <div className="muted">Delete Eligible</div>
                      <div className="meta-line">{loadingLifecycleSummary ? "..." : (summaryCounts?.delete_eligible ?? 0)}</div>
                    </div>
                    <div className="list-item readable">
                      <div className="muted">Total Indexed</div>
                      <div className="meta-line">{loadingLifecycleSummary ? "..." : (summaryCounts?.total ?? 0)}</div>
                    </div>
                    <div className="list-item readable">
                      <div className="muted">Last Applied</div>
                      <div className="meta-line">{formatWazuhTimestamp(selectedPolicy.last_applied_at)}</div>
                    </div>
                  </div>

                  <div className="page-actions mt-12">
                    <button
                      className="btn secondary"
                      onClick={() => runLifecycle(true)}
                      disabled={runningLifecycle || runningLifecycleBatch}
                    >
                      {runningLifecycle ? "Running..." : "Preview Changes"}
                    </button>
                    <button
                      className="btn"
                      onClick={() => runLifecycle(false)}
                      disabled={runningLifecycle || runningLifecycleBatch}
                    >
                      Apply Policy
                    </button>
                  </div>

                  <div className="page-actions mt-12">
                    <button
                      className="btn secondary"
                      onClick={() => runLifecycleBatch(true)}
                      disabled={runningLifecycle || runningLifecycleBatch || activePolicyDataClasses.length === 0}
                    >
                      {runningLifecycleBatch ? "Running Batch..." : `Preview All Active (${activePolicyDataClasses.length})`}
                    </button>
                    <button
                      className="btn"
                      onClick={() => runLifecycleBatch(false)}
                      disabled={runningLifecycle || runningLifecycleBatch || activePolicyDataClasses.length === 0}
                    >
                      Apply All Active
                    </button>
                  </div>

                  {previewResult ? (
                    <div className="grid-4 mt-12">
                      <div className="list-item readable">
                        <div className="muted">Hot Changes</div>
                        <div className="meta-line">{previewChanged?.hot ?? 0}</div>
                      </div>
                      <div className="list-item readable">
                        <div className="muted">Warm Changes</div>
                        <div className="meta-line">{previewChanged?.warm ?? 0}</div>
                      </div>
                      <div className="list-item readable">
                        <div className="muted">Cold Changes</div>
                        <div className="meta-line">{previewChanged?.cold ?? 0}</div>
                      </div>
                      <div className="list-item readable">
                        <div className="muted">Archive Changes</div>
                        <div className="meta-line">{previewChanged?.archive ?? 0}</div>
                      </div>
                      <div className="list-item readable">
                        <div className="muted">Deleted</div>
                        <div className="meta-line">{previewResult?.deleted ?? 0}</div>
                      </div>
                      <div className="list-item readable">
                        <div className="muted">Dry Run</div>
                        <div className="meta-line">{previewResult?.dry_run ? "true" : "false"}</div>
                      </div>
                      <div className="list-item readable">
                        <div className="muted">Deletion Suppressed</div>
                        <div className="meta-line">{previewResult?.deletion_suppressed ? "true" : "false"}</div>
                      </div>
                      <div className="list-item readable">
                        <div className="muted">Preview Generated</div>
                        <div className="meta-line">{formatWazuhTimestamp(previewResult?.as_of)}</div>
                      </div>
                    </div>
                  ) : null}

                  {lifecycleBatchPreview ? (
                    <div className="list-item readable mt-12">
                      <div className="list-item split">
                        <div>
                          <h3>Batch Execution Result</h3>
                          <p className="muted">
                            Aggregated lifecycle execution for active retention policies in this tenant.
                          </p>
                        </div>
                        <span className={`status-pill ${lifecycleBatchPreview?.dry_run ? "pending" : "success"}`}>
                          {lifecycleBatchPreview?.dry_run ? "dry_run" : "applied"}
                        </span>
                      </div>

                      <div className="grid-4 mt-12">
                        <div className="list-item readable">
                          <div className="muted">Requested</div>
                          <div className="meta-line">{lifecycleBatchPreview?.requested ?? 0}</div>
                        </div>
                        <div className="list-item readable">
                          <div className="muted">Applied</div>
                          <div className="meta-line">{lifecycleBatchPreview?.applied ?? 0}</div>
                        </div>
                        <div className="list-item readable">
                          <div className="muted">Failed</div>
                          <div className="meta-line">{lifecycleBatchPreview?.failed ?? 0}</div>
                        </div>
                        <div className="list-item readable">
                          <div className="muted">Dry Run</div>
                          <div className="meta-line">{lifecycleBatchPreview?.dry_run ? "true" : "false"}</div>
                        </div>
                      </div>

                      {batchPreviewResults.length > 0 ? (
                        <div className="table-scroll h-260 mt-12">
                          <table className="table compact">
                            <thead>
                              <tr>
                                <th>Data Class</th>
                                <th>Stream</th>
                                <th>Status</th>
                                <th>Deleted</th>
                                <th>Error</th>
                              </tr>
                            </thead>
                            <tbody>
                              {batchPreviewResults.map((item) => {
                                const status = normalizeKey(item?.status);
                                const statusClass = status === "failed" || status === "not_found"
                                  ? "failed"
                                  : status === "applied"
                                    ? "success"
                                    : "pending";
                                const deletedCount = item?.result?.deleted;
                                return (
                                  <tr key={`${item?.data_class || "unknown"}-${item?.status || "unknown"}`}>
                                    <td>{item?.data_class || "-"}</td>
                                    <td>{item?.stream || "-"}</td>
                                    <td>
                                      <span className={`status-pill ${statusClass}`}>{item?.status || "unknown"}</span>
                                    </td>
                                    <td>{deletedCount ?? "-"}</td>
                                    <td>{item?.error || "-"}</td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


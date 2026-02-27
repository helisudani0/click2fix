import { useEffect, useState } from "react";
import {
  createAutomationContextProfile,
  getAutomationContextProfiles,
  getCorrelatedExecutionAlerts,
  validateAutomationContext,
} from "../api/wazuh";
import { formatWazuhTimestamp } from "../utils/time";

const CLASSIFICATIONS = [
  "expected_admin_activity",
  "review_required",
  "suspicious",
];

const toCsvList = (value) =>
  String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

export default function Governance() {
  const [profiles, setProfiles] = useState([]);
  const [enabledOnly, setEnabledOnly] = useState(false);
  const [status, setStatus] = useState("");

  const [profileName, setProfileName] = useState("");
  const [profileDescription, setProfileDescription] = useState("");
  const [profileClassification, setProfileClassification] = useState("review_required");
  const [profileEnabled, setProfileEnabled] = useState(true);
  const [actionsCsv, setActionsCsv] = useState("");
  const [actorsCsv, setActorsCsv] = useState("");
  const [targetsCsv, setTargetsCsv] = useState("");
  const [tacticsCsv, setTacticsCsv] = useState("");
  const [minRuleLevel, setMinRuleLevel] = useState("");
  const [maxRuleLevel, setMaxRuleLevel] = useState("");

  const [validateExecutionId, setValidateExecutionId] = useState("");
  const [validateActionId, setValidateActionId] = useState("");
  const [validateActor, setValidateActor] = useState("");
  const [validateTarget, setValidateTarget] = useState("all");
  const [validateTargetAgents, setValidateTargetAgents] = useState("");
  const [validateLookback, setValidateLookback] = useState("90");
  const [validateAlertLimit, setValidateAlertLimit] = useState("300");
  const [validatePersist, setValidatePersist] = useState(true);
  const [validateResult, setValidateResult] = useState(null);

  const [lookupExecutionId, setLookupExecutionId] = useState("");
  const [lookupAutoCorrelate, setLookupAutoCorrelate] = useState(true);
  const [lookupResult, setLookupResult] = useState(null);

  const loadProfiles = async () => {
    try {
      const response = await getAutomationContextProfiles({
        enabled_only: enabledOnly,
      });
      const payload = response?.data || {};
      setProfiles(Array.isArray(payload?.profiles) ? payload.profiles : []);
      setStatus("");
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  useEffect(() => {
    loadProfiles();
  }, [enabledOnly]);

  const submitProfile = async () => {
    if (!profileName.trim()) {
      setStatus("Profile name is required.");
      return;
    }
    try {
      setStatus("Creating automation context profile...");
      const payload = {
        name: profileName.trim(),
        description: profileDescription || undefined,
        classification: profileClassification,
        enabled: profileEnabled,
        profile: {
          actions: toCsvList(actionsCsv),
          actors: toCsvList(actorsCsv),
          targets: toCsvList(targetsCsv),
          tactics: toCsvList(tacticsCsv),
          min_rule_level: minRuleLevel === "" ? undefined : Number(minRuleLevel),
          max_rule_level: maxRuleLevel === "" ? undefined : Number(maxRuleLevel),
        },
      };
      await createAutomationContextProfile(payload);
      setStatus("Automation context profile created.");
      setProfileName("");
      setProfileDescription("");
      setActionsCsv("");
      setActorsCsv("");
      setTargetsCsv("");
      setTacticsCsv("");
      setMinRuleLevel("");
      setMaxRuleLevel("");
      await loadProfiles();
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  const submitValidation = async () => {
    try {
      setStatus("Running automation context validation...");
      const payload = {
        lookback_minutes: Number(validateLookback || 90),
        alert_limit: Number(validateAlertLimit || 300),
        persist: validatePersist,
      };
      if (String(validateExecutionId || "").trim()) {
        payload.execution_id = Number(validateExecutionId);
      } else {
        payload.action_id = validateActionId || undefined;
        payload.actor = validateActor || undefined;
        payload.target = validateTarget || undefined;
        payload.target_agents = toCsvList(validateTargetAgents);
      }
      const response = await validateAutomationContext(payload);
      setValidateResult(response?.data || null);
      setStatus("Automation context validation complete.");
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  const lookupCorrelatedAlerts = async () => {
    if (!String(lookupExecutionId || "").trim()) {
      setStatus("Execution ID is required for lookup.");
      return;
    }
    try {
      setStatus(`Loading correlated alerts for execution ${lookupExecutionId}...`);
      const response = await getCorrelatedExecutionAlerts(Number(lookupExecutionId), {
        auto_correlate: lookupAutoCorrelate,
      });
      setLookupResult(response?.data || null);
      setStatus(`Loaded correlated alerts for execution ${lookupExecutionId}.`);
    } catch (err) {
      setStatus(err.response?.data?.detail || err.message);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Automation Governance</h2>
          <p className="muted">Automation context profiles, validation, and correlated alert review.</p>
        </div>
      </div>

      {status ? <div className="empty-state">{status}</div> : null}

      <div className="card mb-18">
        <div className="card-header">
          <div>
            <h3>Automation Context Profiles</h3>
            <p className="muted">Classify expected automation behavior for better alert context.</p>
          </div>
          <div className="page-actions">
            <label className="list-item" style={{ minWidth: 180 }}>
              <div className="muted">Enabled Only</div>
              <select
                className="input"
                value={enabledOnly ? "true" : "false"}
                onChange={(event) => setEnabledOnly(event.target.value === "true")}
              >
                <option value="false">false</option>
                <option value="true">true</option>
              </select>
            </label>
          </div>
        </div>

        <div className="grid-3">
          <label className="list-item">
            <div className="muted">Name</div>
            <input className="input" value={profileName} onChange={(event) => setProfileName(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Classification</div>
            <select
              className="input"
              value={profileClassification}
              onChange={(event) => setProfileClassification(event.target.value)}
            >
              {CLASSIFICATIONS.map((classification) => (
                <option key={classification} value={classification}>{classification}</option>
              ))}
            </select>
          </label>
          <label className="list-item">
            <div className="muted">Enabled</div>
            <select
              className="input"
              value={profileEnabled ? "true" : "false"}
              onChange={(event) => setProfileEnabled(event.target.value === "true")}
            >
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          </label>
        </div>

        <label className="list-item mt-8">
          <div className="muted">Description</div>
          <textarea className="input" value={profileDescription} onChange={(event) => setProfileDescription(event.target.value)} />
        </label>

        <div className="grid-4 mt-8">
          <label className="list-item">
            <div className="muted">Actions (CSV)</div>
            <input className="input" value={actionsCsv} onChange={(event) => setActionsCsv(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Actors (CSV)</div>
            <input className="input" value={actorsCsv} onChange={(event) => setActorsCsv(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Targets (CSV)</div>
            <input className="input" value={targetsCsv} onChange={(event) => setTargetsCsv(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Tactics (CSV)</div>
            <input className="input" value={tacticsCsv} onChange={(event) => setTacticsCsv(event.target.value)} />
          </label>
        </div>

        <div className="grid-2 mt-8">
          <label className="list-item">
            <div className="muted">Min Rule Level</div>
            <input
              className="input"
              type="number"
              min="0"
              max="20"
              value={minRuleLevel}
              onChange={(event) => setMinRuleLevel(event.target.value)}
            />
          </label>
          <label className="list-item">
            <div className="muted">Max Rule Level</div>
            <input
              className="input"
              type="number"
              min="0"
              max="20"
              value={maxRuleLevel}
              onChange={(event) => setMaxRuleLevel(event.target.value)}
            />
          </label>
        </div>

        <div className="page-actions mt-8">
          <button className="btn" onClick={submitProfile}>Create Profile</button>
        </div>

        <div className="table-scroll h-260 mt-8">
          <table className="table compact">
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Classification</th>
                <th>Enabled</th>
                <th>Created By</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {profiles.length === 0 ? (
                <tr>
                  <td colSpan="6" className="text-center">No automation context profiles.</td>
                </tr>
              ) : (
                profiles.map((profile) => (
                  <tr key={profile.id}>
                    <td>{profile.id}</td>
                    <td>{profile.name}</td>
                    <td>{profile.classification}</td>
                    <td>{String(Boolean(profile.enabled))}</td>
                    <td>{profile.created_by || "-"}</td>
                    <td>{formatWazuhTimestamp(profile.updated_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Validate Automation Context</h3>
              <p className="muted">Validate by execution ID or provide context manually.</p>
            </div>
          </div>
          <div className="list">
            <label className="list-item">
              <div className="muted">Execution ID (preferred)</div>
              <input className="input" value={validateExecutionId} onChange={(event) => setValidateExecutionId(event.target.value)} />
            </label>
            <div className="grid-2">
              <label className="list-item">
                <div className="muted">Action ID</div>
                <input className="input" value={validateActionId} onChange={(event) => setValidateActionId(event.target.value)} />
              </label>
              <label className="list-item">
                <div className="muted">Actor</div>
                <input className="input" value={validateActor} onChange={(event) => setValidateActor(event.target.value)} />
              </label>
            </div>
            <label className="list-item">
              <div className="muted">Target</div>
              <input className="input" value={validateTarget} onChange={(event) => setValidateTarget(event.target.value)} />
            </label>
            <label className="list-item">
              <div className="muted">Target Agents (CSV)</div>
              <input className="input" value={validateTargetAgents} onChange={(event) => setValidateTargetAgents(event.target.value)} />
            </label>
            <div className="grid-2">
              <label className="list-item">
                <div className="muted">Lookback Minutes</div>
                <input className="input" type="number" min="5" value={validateLookback} onChange={(event) => setValidateLookback(event.target.value)} />
              </label>
              <label className="list-item">
                <div className="muted">Alert Limit</div>
                <input className="input" type="number" min="20" value={validateAlertLimit} onChange={(event) => setValidateAlertLimit(event.target.value)} />
              </label>
            </div>
            <label className="list-item">
              <div className="muted">Persist</div>
              <select
                className="input"
                value={validatePersist ? "true" : "false"}
                onChange={(event) => setValidatePersist(event.target.value === "true")}
              >
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            </label>
            <div className="page-actions">
              <button className="btn" onClick={submitValidation}>Validate Context</button>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Validation Result</h3>
              <p className="muted">
                {validateResult
                  ? `classification=${validateResult.classification}; alerts=${validateResult.correlated_alerts}`
                  : "Run validation to inspect classification and alert correlations."}
              </p>
            </div>
          </div>
          {validateResult ? (
            <div className="table-scroll h-56vh">
              <table className="table compact">
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Agent</th>
                    <th>Class</th>
                    <th>Confidence</th>
                    <th>Reason</th>
                    <th>Rule Level</th>
                  </tr>
                </thead>
                <tbody>
                  {(validateResult.alerts || []).length === 0 ? (
                    <tr>
                      <td colSpan="6" className="text-center">No correlated alerts in validation result.</td>
                    </tr>
                  ) : (
                    (validateResult.alerts || []).map((alert) => (
                      <tr key={`${alert.alert_id}-${alert.event_time || ""}`}>
                        <td>{alert.alert_id}</td>
                        <td>{alert.agent_id || "-"}</td>
                        <td>{alert.classification}</td>
                        <td>{alert.confidence}</td>
                        <td>{alert.reason || "-"}</td>
                        <td>{alert.rule_level ?? "-"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">No validation result yet.</div>
          )}
        </div>
      </div>

      <div className="card mt-8">
        <div className="card-header">
          <div>
            <h3>Correlated Alerts Lookup</h3>
            <p className="muted">Query `/governance/alerts/correlated` for a specific execution.</p>
          </div>
        </div>
        <div className="grid-3">
          <label className="list-item">
            <div className="muted">Execution ID</div>
            <input className="input" value={lookupExecutionId} onChange={(event) => setLookupExecutionId(event.target.value)} />
          </label>
          <label className="list-item">
            <div className="muted">Auto Correlate</div>
            <select
              className="input"
              value={lookupAutoCorrelate ? "true" : "false"}
              onChange={(event) => setLookupAutoCorrelate(event.target.value === "true")}
            >
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          </label>
          <div className="page-actions" style={{ alignSelf: "end" }}>
            <button className="btn secondary" onClick={lookupCorrelatedAlerts}>Fetch Correlated Alerts</button>
          </div>
        </div>

        {lookupResult ? (
          <div className="table-scroll h-240 mt-8">
            <table className="table compact">
              <thead>
                <tr>
                  <th>Alert</th>
                  <th>Agent</th>
                  <th>Class</th>
                  <th>Confidence</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {(lookupResult.alerts || []).length === 0 ? (
                  <tr>
                    <td colSpan="5" className="text-center">No correlated alerts found.</td>
                  </tr>
                ) : (
                  (lookupResult.alerts || []).map((alert) => (
                    <tr key={`${alert.id || alert.alert_id}-${alert.created_at || ""}`}>
                      <td>{alert.alert_id}</td>
                      <td>{alert.agent_id || "-"}</td>
                      <td>{alert.classification}</td>
                      <td>{alert.confidence}</td>
                      <td>{alert.reason || "-"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </div>
  );
}

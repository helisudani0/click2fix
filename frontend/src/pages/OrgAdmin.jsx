import { useEffect, useState } from "react";
import api from "../api/client";

export default function OrgAdmin() {

  const [orgs, setOrgs] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [orgName, setOrgName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const loadOrgs = () =>
    api.get("/orgs")
      .then(r => {
        setOrgs(r.data || []);
        if (!selectedOrg && r.data?.length) {
          setSelectedOrg(r.data[0][0]);
        }
      })
      .catch(err => setError(err.response?.data?.detail || err.message));

  const loadUsers = (orgId) =>
    api.get(`/orgs/${orgId}/users`)
      .then(r => setUsers(r.data || []))
      .catch(err => setError(err.response?.data?.detail || err.message));

  useEffect(() => {
    loadOrgs();
  }, []);

  useEffect(() => {
    if (selectedOrg) {
      loadUsers(selectedOrg);
    }
  }, [selectedOrg]);

  const createOrg = async () => {
    setMessage(null);
    setError(null);
    if (!orgName) return;
    try {
      await api.post("/orgs", null, { params: { name: orgName } });
      setOrgName("");
      loadOrgs();
      setMessage("Organization created.");
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const createUser = async () => {
    setMessage(null);
    setError(null);
    if (!selectedOrg || !username || !password) return;
    try {
      await api.post(`/orgs/${selectedOrg}/users`, null, {
        params: { username, password, role }
      });
      setUsername("");
      setPassword("");
      setRole("analyst");
      loadUsers(selectedOrg);
      setMessage("User created.");
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Org Admin</h2>
          <p className="muted">Manage organizations and SOC users.</p>
        </div>
        <div className="page-actions">
          <button className="btn secondary" onClick={loadOrgs}>Refresh</button>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h3>Organizations</h3>
              <p className="muted">Create and select an org.</p>
            </div>
          </div>

          <div className="list">
            <div className="list-item">
              <div className="muted">New organization</div>
              <input
                className="input"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Org name"
              />
              <div className="page-actions mt-12">
                <button className="btn" onClick={createOrg}>Create Org</button>
              </div>
            </div>

            <div className="list-item">
              <div className="muted">Existing orgs</div>
              <select
                className="input"
                value={selectedOrg}
                onChange={(e) => setSelectedOrg(e.target.value)}
              >
                {orgs.map(org => (
                  <option key={org[0]} value={org[0]}>
                    {org[1]}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Users</h3>
              <p className="muted">Provision access for analysts and admins.</p>
            </div>
          </div>

          <div className="list">
            <div className="list-item">
              <div className="muted">Create user</div>
              <input
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
              />
              <input
                className="input mt-10"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
              />
              <select
                className="input mt-10"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
                <option value="superadmin">Superadmin</option>
              </select>
              <div className="page-actions mt-12">
                <button className="btn" onClick={createUser}>Create User</button>
              </div>
            </div>

            <div className="list-item">
              <div className="muted">Org users</div>
              {users.length === 0 ? (
                <div className="empty-state">No users found.</div>
              ) : (
                <ul className="list">
                  {users.map(u => (
                    <li key={u[0]} className="list-item">
                      {u[1]} - {u[2]}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </div>

      {message && <div className="empty-state">{message}</div>}
      {error && <div className="empty-state">{error}</div>}
    </div>
  );
}

import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { useSession, useTenantId } from "../lib/session";

export function Settings() {
  const tenantId = useTenantId();
  const { isAdmin } = useSession();
  const [tenant, setTenant] = useState(null);
  const [connectors, setConnectors] = useState([]);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const load = useCallback(() => {
    if (!tenantId) return;
    api.getTenant(tenantId).then(setTenant).catch((e) => setError(e.message));
    api.listConnectors(tenantId).then(setConnectors).catch((e) => setError(e.message));
  }, [tenantId]);

  useEffect(load, [load]);

  async function runExposureScan() {
    setError("");
    setMessage("");
    try {
      await api.requestExposureScan(tenantId, tenant.domain);
      setMessage(`Exposure scan of ${tenant.domain} requested — see Incidents shortly for the results.`);
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <>
      <div className="topbar">
        <h1>Settings</h1>
      </div>

      {tenantId && tenant && (
        <div className="panel">
          <h2>Company</h2>
          <p>
            <strong>{tenant.name}</strong> — {tenant.domain} ({tenant.sector})
          </p>
          <button onClick={runExposureScan}>Run exposure scan of {tenant.domain}</button>
          {message && <p className="muted">{message}</p>}
        </div>
      )}

      {tenantId && (
        <div className="panel">
          <h2>Connected data sources</h2>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Active</th>
                <th>Last event</th>
              </tr>
            </thead>
            <tbody>
              {connectors.map((c) => (
                <tr key={c.id}>
                  <td>{c.display_name}</td>
                  <td>{c.connector_type}</td>
                  <td>{c.is_active ? "yes" : "no"}</td>
                  <td>{c.last_event_at ? new Date(c.last_event_at).toLocaleString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted" style={{ marginTop: 10 }}>
            The demo feed is added automatically for every new company. Wiring a real SIEM (e.g. Wazuh) means
            pointing its webhook forwarder at{" "}
            <code>POST /api/tenants/{tenantId}/ingest</code> — see the README for the connector shape.
          </p>
        </div>
      )}

      {error && <div className="panel error-text">{error}</div>}

      {isAdmin && <AdminPanel onChanged={load} />}
      {isAdmin && <PlatformSecurityLog />}
    </>
  );
}

function PlatformSecurityLog() {
  const [entries, setEntries] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.platformAudit().then(setEntries).catch((e) => setError(e.message));
  }, []);

  return (
    <div className="panel">
      <h2>Platform security log</h2>
      <p className="muted" style={{ marginTop: -6, marginBottom: 12 }}>
        Login attempts against SentriMeshAstra itself — not tied to any one company. A run of
        <code> login_locked_out</code> rows from one email or IP means the brute-force lockout is doing its job.
      </p>
      {error && <div className="error-text">{error}</div>}
      {entries.length === 0 ? (
        <div className="muted">No platform-level security events yet.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Event</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.created_at).toLocaleString()}</td>
                <td>{e.actor}</td>
                <td>{e.action}</td>
                <td className="muted">{JSON.stringify(e.payload)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function AdminPanel({ onChanged }) {
  const { refreshTenants, setActiveTenantId } = useSession();
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [sector, setSector] = useState("general");
  const [tenantCreated, setTenantCreated] = useState(null);
  const [error, setError] = useState("");

  const [holderEmail, setHolderEmail] = useState("");
  const [holderPassword, setHolderPassword] = useState("");
  const [holderName, setHolderName] = useState("");
  const [holderTenantId, setHolderTenantId] = useState("");
  const [holderMessage, setHolderMessage] = useState("");

  async function createTenant(e) {
    e.preventDefault();
    setError("");
    try {
      const t = await api.createTenant({ name, domain, sector });
      setTenantCreated(t);
      setHolderTenantId(t.id);
      refreshTenants();
      setActiveTenantId(t.id);
      onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  async function createHolder(e) {
    e.preventDefault();
    setHolderMessage("");
    setError("");
    try {
      await api.createSecurityHolder({
        email: holderEmail,
        password: holderPassword,
        full_name: holderName,
        tenant_id: holderTenantId,
      });
      setHolderMessage(`Security-holder login created for ${holderEmail}.`);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="panel">
      <h2>Admin: onboard a new company</h2>
      <form onSubmit={createTenant} className="row wrap" style={{ marginBottom: 16 }}>
        <input placeholder="Company name" value={name} onChange={(e) => setName(e.target.value)} required />
        <input placeholder="Verified domain (example.com)" value={domain} onChange={(e) => setDomain(e.target.value)} required />
        <select value={sector} onChange={(e) => setSector(e.target.value)}>
          <option value="general">General</option>
          <option value="finance">Finance / Crypto</option>
          <option value="healthcare">Healthcare</option>
          <option value="ecommerce">E-commerce</option>
          <option value="government">Government contractor</option>
        </select>
        <button className="primary" type="submit">Create company</button>
      </form>
      {tenantCreated && <p className="muted">Created: {tenantCreated.name} ({tenantCreated.id})</p>}

      <h2>Admin: create the company's security-holder login</h2>
      <form onSubmit={createHolder} className="row wrap">
        <input placeholder="Tenant ID" value={holderTenantId} onChange={(e) => setHolderTenantId(e.target.value)} required />
        <input placeholder="Full name" value={holderName} onChange={(e) => setHolderName(e.target.value)} />
        <input type="email" placeholder="Email" value={holderEmail} onChange={(e) => setHolderEmail(e.target.value)} required />
        <input
          type="password"
          placeholder="Temporary password (10+ chars)"
          value={holderPassword}
          onChange={(e) => setHolderPassword(e.target.value)}
          required
        />
        <button className="primary" type="submit">Create login</button>
      </form>
      {holderMessage && <p className="muted">{holderMessage}</p>}
      {error && <div className="error-text">{error}</div>}
    </div>
  );
}

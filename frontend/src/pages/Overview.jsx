import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { useTenantId } from "../lib/session";

export function Overview() {
  const tenantId = useTenantId();
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const load = useCallback(() => {
    if (!tenantId) return;
    api.getOverview(tenantId).then(setOverview).catch((e) => setError(e.message));
  }, [tenantId]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, [load]);

  async function toggleKillSwitch(engaged) {
    setBusy(true);
    try {
      await api.setKillSwitch(tenantId, { engaged, reason: engaged ? "Manually engaged from console" : "Resumed by admin" });
      setMessage(engaged ? "Kill switch engaged — all automated response is now blocked." : "Kill switch disengaged.");
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function simulateAttack() {
    setBusy(true);
    setMessage("");
    try {
      await api.simulateAttack(tenantId);
      setMessage("Synthetic attack scenario fired. Watch Incidents and Approvals for the pipeline to react.");
      setTimeout(load, 1500);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (!tenantId) {
    return <div className="panel">Select a company from the sidebar to see its overview.</div>;
  }
  if (error) return <div className="panel error-text">{error}</div>;
  if (!overview) return <div className="panel muted">Loading…</div>;

  return (
    <>
      <div className="topbar">
        <h1>Overview</h1>
        <div className="row">
          <button onClick={simulateAttack} disabled={busy}>
            Simulate demo attack
          </button>
          {overview.kill_switch_engaged ? (
            <button className="primary" onClick={() => toggleKillSwitch(false)} disabled={busy}>
              Disengage kill switch
            </button>
          ) : (
            <button className="danger" onClick={() => toggleKillSwitch(true)} disabled={busy}>
              Engage kill switch
            </button>
          )}
        </div>
      </div>

      {overview.kill_switch_engaged && (
        <div className="kill-switch-banner">
          <span>⚠ Kill switch is ENGAGED — no automated or approved response action will execute.</span>
        </div>
      )}
      {message && <div className="panel muted">{message}</div>}

      <div className="grid grid-4">
        <div className="stat-card">
          <div className="stat-label">Risk score</div>
          <div className="stat-value">{overview.risk_score}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Open incidents</div>
          <div className="stat-value">{overview.open_incidents}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Critical incidents</div>
          <div className="stat-value">{overview.critical_incidents}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Pending approvals</div>
          <div className="stat-value">{overview.pending_approvals}</div>
        </div>
      </div>

      <div className="panel">
        <h2>Coverage health</h2>
        {overview.connector_health.length === 0 && <div className="muted">No connectors configured yet.</div>}
        <table>
          <thead>
            <tr>
              <th>Connector</th>
              <th>Type</th>
              <th>Status</th>
              <th>Last event</th>
            </tr>
          </thead>
          <tbody>
            {overview.connector_health.map((c) => (
              <tr key={c.id}>
                <td>{c.name}</td>
                <td>{c.type}</td>
                <td>
                  {c.healthy === null ? (
                    <span className="muted">No events yet</span>
                  ) : c.healthy ? (
                    <span style={{ color: "var(--ok)" }}>● reporting</span>
                  ) : (
                    <span style={{ color: "var(--critical)" }}>● stale</span>
                  )}
                </td>
                <td>{c.last_event_at ? new Date(c.last_event_at).toLocaleString() : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h2>Last daily report</h2>
        <div className="muted">
          {overview.last_report_at ? new Date(overview.last_report_at).toLocaleString() : "No report generated yet — see Reports."}
        </div>
      </div>
    </>
  );
}

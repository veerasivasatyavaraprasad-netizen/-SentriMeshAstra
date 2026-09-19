import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { useTenantId } from "../lib/session";

export function Reports() {
  const tenantId = useTenantId();
  const [reports, setReports] = useState([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    if (!tenantId) return;
    api.listReports(tenantId).then(setReports).catch((e) => setError(e.message));
  }, [tenantId]);

  useEffect(() => {
    load();
  }, [load]);

  async function generateNow() {
    setBusy(true);
    setError("");
    try {
      await api.generateReport(tenantId);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (!tenantId) return <div className="panel">Select a company from the sidebar.</div>;

  return (
    <>
      <div className="topbar">
        <h1>Reports</h1>
        <button className="primary" onClick={generateNow} disabled={busy}>
          Generate now
        </button>
      </div>
      <p className="muted">
        A report runs automatically every 24 hours. Generating one now covers the trailing 24 hours from this
        moment and is emailed the same way the daily one is.
      </p>
      {error && <div className="panel error-text">{error}</div>}
      {reports.length === 0 && <div className="panel muted">No reports yet.</div>}
      {reports.map((r) => (
        <div className="panel" key={r.id}>
          <div className="row" style={{ marginBottom: 8 }}>
            <strong>{r.report_type} report</strong>
            <span className="muted">
              {new Date(r.period_start).toLocaleString()} – {new Date(r.period_end).toLocaleString()}
            </span>
            <span className="spacer" />
            {r.emailed && <span className="muted">✉ emailed</span>}
          </div>
          <p>{r.summary}</p>
          <div className="grid grid-4">
            <div className="stat-card">
              <div className="stat-label">Incidents</div>
              <div className="stat-value">{r.body.incident_count}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Executed actions</div>
              <div className="stat-value">{r.body.executed_actions}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Pending actions</div>
              <div className="stat-value">{r.body.pending_actions}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">Critical</div>
              <div className="stat-value">{r.body.by_severity?.critical ?? 0}</div>
            </div>
          </div>
        </div>
      ))}
    </>
  );
}

import { Fragment, useCallback, useEffect, useState } from "react";
import { Badge } from "../components/Badge";
import { api } from "../lib/api";
import { useTenantId } from "../lib/session";

export function Incidents() {
  const tenantId = useTenantId();
  const [incidents, setIncidents] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    if (!tenantId) return;
    api.listIncidents(tenantId).then(setIncidents).catch((e) => setError(e.message));
  }, [tenantId]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [load]);

  if (!tenantId) return <div className="panel">Select a company from the sidebar.</div>;

  return (
    <>
      <div className="topbar">
        <h1>Incidents</h1>
      </div>
      {error && <div className="panel error-text">{error}</div>}
      <div className="panel">
        {incidents.length === 0 && <div className="muted">No incidents yet.</div>}
        <table>
          <thead>
            <tr>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>MITRE</th>
              <th>Opened</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((incident) => (
              <Fragment key={incident.id}>
                <tr onClick={() => setExpanded(expanded === incident.id ? null : incident.id)} style={{ cursor: "pointer" }}>
                  <td>{incident.title}</td>
                  <td><Badge value={incident.severity} /></td>
                  <td>{incident.status.replace(/_/g, " ")}</td>
                  <td>{incident.mitre_techniques.join(", ") || "—"}</td>
                  <td>{new Date(incident.created_at).toLocaleString()}</td>
                </tr>
                {expanded === incident.id && (
                  <tr>
                    <td colSpan={5}>
                      <div className="description-pre">{incident.description}</div>
                      <div className="description-pre" style={{ marginTop: 8 }}>
                        {JSON.stringify(incident.enrichment, null, 2)}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

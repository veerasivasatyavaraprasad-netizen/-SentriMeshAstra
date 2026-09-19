import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { useSession, useTenantId } from "../lib/session";

export function Activity() {
  const tenantId = useTenantId();
  const { eventsVersion } = useSession();
  const [entries, setEntries] = useState([]);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null);

  const load = useCallback(() => {
    if (!tenantId) return;
    api.listActivity(tenantId).then(setEntries).catch((e) => setError(e.message));
  }, [tenantId]);

  useEffect(load, [load, eventsVersion]);

  if (!tenantId) return <div className="panel">Select a company from the sidebar.</div>;

  return (
    <>
      <div className="topbar">
        <h1>Agent Activity</h1>
      </div>
      <p className="muted">
        Every message any agent publishes, and every human decision, in order. This is the Guardian's ledger —
        nothing acts without a row appearing here.
      </p>
      {error && <div className="panel error-text">{error}</div>}
      <div className="panel">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Channel</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id} onClick={() => setExpanded(expanded === e.id ? null : e.id)} style={{ cursor: "pointer" }}>
                <td colSpan={expanded === e.id ? 4 : 1}>
                  {new Date(e.created_at).toLocaleString()}
                  {expanded === e.id && (
                    <div className="description-pre" style={{ marginTop: 8 }}>
                      {JSON.stringify(e.payload, null, 2)}
                    </div>
                  )}
                </td>
                {expanded !== e.id && (
                  <>
                    <td>{e.actor}</td>
                    <td>{e.action}</td>
                    <td>{e.channel}</td>
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

import { useCallback, useEffect, useState } from "react";
import { Badge } from "../components/Badge";
import { api } from "../lib/api";
import { useTenantId } from "../lib/session";

export function Approvals() {
  const tenantId = useTenantId();
  const [approvals, setApprovals] = useState([]);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [notes, setNotes] = useState({});

  const load = useCallback(() => {
    if (!tenantId) return;
    api.listApprovals(tenantId).then(setApprovals).catch((e) => setError(e.message));
  }, [tenantId]);

  useEffect(() => {
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, [load]);

  async function decide(id, approve) {
    setBusyId(id);
    setError("");
    try {
      await api.decideApproval(tenantId, id, { approve, note: notes[id] || "" });
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  async function rollback(proposalId) {
    setBusyId(proposalId);
    setError("");
    try {
      const res = await api.rollbackAction(tenantId, proposalId);
      setError(res.outcome.success ? "" : res.outcome.detail);
      load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  if (!tenantId) return <div className="panel">Select a company from the sidebar.</div>;

  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending");

  return (
    <>
      <div className="topbar">
        <h1>Approvals</h1>
      </div>
      <p className="muted">
        Every action here is one the policy engine judged risky enough to need a human. Tier-2 actions are
        reversible and meant for a quick decision; tier-3 actions are destructive or hard to reverse and
        deserve a closer look at the rationale below before approving.
      </p>
      {error && <div className="panel error-text">{error}</div>}

      <div className="panel">
        <h2>Pending ({pending.length})</h2>
        {pending.length === 0 && <div className="muted">Nothing waiting on you right now.</div>}
        {pending.map((a) => (
          <div key={a.id} className="panel" style={{ background: "var(--bg-panel-alt)" }}>
            <div className="row wrap" style={{ marginBottom: 8 }}>
              <strong>{a.action?.action_type}</strong>
              <Badge value={a.action?.tier} />
              <span className="spacer" />
              <span className="muted">{new Date(a.created_at).toLocaleString()}</span>
            </div>
            <div className="muted" style={{ marginBottom: 6 }}>{a.action?.rationale}</div>
            <div className="muted" style={{ marginBottom: 6 }}>
              Reversible: {a.action?.reversible ? "yes" : "no"} — {a.action?.rollback_plan}
            </div>
            <div className="muted" style={{ marginBottom: 10 }}>
              Parameters: <code>{JSON.stringify(a.action?.parameters)}</code>
            </div>
            <input
              placeholder="Optional note"
              value={notes[a.id] || ""}
              onChange={(e) => setNotes({ ...notes, [a.id]: e.target.value })}
              style={{ width: "100%", marginBottom: 10 }}
            />
            <div className="row">
              <button className="primary" disabled={busyId === a.id} onClick={() => decide(a.id, true)}>
                Approve & execute
              </button>
              <button className="danger" disabled={busyId === a.id} onClick={() => decide(a.id, false)}>
                Reject
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="panel">
        <h2>Decided</h2>
        <table>
          <thead>
            <tr>
              <th>Action</th>
              <th>Tier</th>
              <th>Status</th>
              <th>Decided</th>
              <th>Note</th>
              <th>Execution</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {decided.map((a) => {
              const rolledBack = a.action?.execution_result?.rolled_back;
              return (
                <tr key={a.id}>
                  <td>{a.action?.action_type}</td>
                  <td><Badge value={a.action?.tier} /></td>
                  <td><Badge value={a.status} /></td>
                  <td>{a.decided_at ? new Date(a.decided_at).toLocaleString() : "—"}</td>
                  <td>{a.decision_note}</td>
                  <td className="muted">
                    {a.action?.executed
                      ? rolledBack
                        ? "rolled back"
                        : a.action.execution_result?.simulated
                          ? "simulated"
                          : "executed"
                      : "—"}
                  </td>
                  <td>
                    {a.action?.executed && a.action?.reversible && !rolledBack && (
                      <button disabled={busyId === a.action.id} onClick={() => rollback(a.action.id)}>
                        Roll back
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

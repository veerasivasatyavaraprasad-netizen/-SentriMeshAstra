import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { useSession } from "../lib/session";

const NAV_ITEMS = [
  { to: "/overview", label: "Overview" },
  { to: "/incidents", label: "Incidents" },
  { to: "/approvals", label: "Approvals" },
  { to: "/reports", label: "Reports" },
  { to: "/activity", label: "Agent Activity" },
  { to: "/settings", label: "Settings" },
];

export function Layout() {
  const { session, logout, isAdmin, activeTenantId, setActiveTenantId, tenantsVersion } = useSession();
  const [tenants, setTenants] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    api.listTenants().then(setTenants).catch(() => {});
  }, [tenantsVersion]);

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">SentriMeshAstra</div>
        <div className="brand-sub">AI SECURITY TEAM PLATFORM</div>

        {isAdmin && (
          <div style={{ marginBottom: 20 }}>
            <label className="muted" style={{ display: "block", marginBottom: 6 }}>
              Company
            </label>
            <select
              className="tenant-select"
              value={activeTenantId}
              onChange={(e) => setActiveTenantId(e.target.value)}
            >
              <option value="">Select a company…</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>
        )}

        <nav style={{ flex: 1 }}>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="muted" style={{ marginBottom: 8 }}>
          {session?.email} ({session?.role === "admin" ? "Admin" : "Security Holder"})
        </div>
        <button className="ghost" onClick={handleLogout}>
          Log out
        </button>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}

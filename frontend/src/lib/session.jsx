import { createContext, useContext, useEffect, useState } from "react";
import { api, clearSession, getSession, saveSession } from "./api";
import { useTenantEventStream } from "./liveEvents";

const SessionContext = createContext(null);

const ADMIN_ACTIVE_TENANT_KEY = "sma_admin_active_tenant";

export function SessionProvider({ children }) {
  const [session, setSession] = useState(getSession);
  const [activeTenantId, setActiveTenantIdState] = useState(() => {
    const s = getSession();
    if (s?.tenantId) return s.tenantId;
    // An admin isn't tied to one tenant, so the security-holder path
    // above never applies to them — restore whichever company they had
    // selected before the last page refresh, instead of forcing them to
    // re-pick from the sidebar dropdown every single reload.
    return s?.role === "admin" ? localStorage.getItem(ADMIN_ACTIVE_TENANT_KEY) || "" : "";
  });
  function setActiveTenantId(id) {
    setActiveTenantIdState(id);
    if (session?.role === "admin") {
      if (id) localStorage.setItem(ADMIN_ACTIVE_TENANT_KEY, id);
      else localStorage.removeItem(ADMIN_ACTIVE_TENANT_KEY);
    }
  }
  // Bumped whenever a tenant is created/changed elsewhere in the app, so
  // the sidebar's tenant list (fetched by Layout) knows to refetch instead
  // of showing a stale list until the next full page reload.
  const [tenantsVersion, setTenantsVersion] = useState(0);
  const refreshTenants = () => setTenantsVersion((v) => v + 1);

  useEffect(() => {
    if (session?.tenantId) setActiveTenantId(session.tenantId);
  }, [session]);

  const isAdmin = session?.role === "admin";
  const tenantIdForEvents = isAdmin ? activeTenantId : session?.tenantId;
  // One WebSocket per active tenant, shared by every page via context —
  // not one per page, which would open a redundant connection each time
  // the user switches tabs.
  const { version: eventsVersion, connected: liveConnected } = useTenantEventStream(tenantIdForEvents);

  async function login(email, password) {
    const data = await api.login(email, password);
    saveSession(data, email);
    const next = getSession();
    setSession(next);
    setActiveTenantId(next.tenantId || "");
    return next;
  }

  function logout() {
    clearSession();
    setSession(null);
    setActiveTenantId("");
  }

  return (
    <SessionContext.Provider
      value={{
        session,
        login,
        logout,
        isAdmin,
        activeTenantId,
        setActiveTenantId,
        tenantsVersion,
        refreshTenants,
        eventsVersion,
        liveConnected,
      }}
    >
      {children}
    </SessionContext.Provider>
  );
}

export function useSession() {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession must be used within SessionProvider");
  return ctx;
}

/** The tenant a page should operate on: the security holder's own tenant,
 * or whichever tenant the admin picked in the sidebar. */
export function useTenantId() {
  const { session, isAdmin, activeTenantId } = useSession();
  return isAdmin ? activeTenantId : session?.tenantId;
}

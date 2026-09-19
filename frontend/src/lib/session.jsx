import { createContext, useContext, useEffect, useState } from "react";
import { api, clearSession, getSession, saveSession } from "./api";

const SessionContext = createContext(null);

export function SessionProvider({ children }) {
  const [session, setSession] = useState(getSession);
  const [activeTenantId, setActiveTenantId] = useState(() => getSession()?.tenantId || "");
  // Bumped whenever a tenant is created/changed elsewhere in the app, so
  // the sidebar's tenant list (fetched by Layout) knows to refetch instead
  // of showing a stale list until the next full page reload.
  const [tenantsVersion, setTenantsVersion] = useState(0);
  const refreshTenants = () => setTenantsVersion((v) => v + 1);

  useEffect(() => {
    if (session?.tenantId) setActiveTenantId(session.tenantId);
  }, [session]);

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

  const isAdmin = session?.role === "admin";

  return (
    <SessionContext.Provider
      value={{ session, login, logout, isAdmin, activeTenantId, setActiveTenantId, tenantsVersion, refreshTenants }}
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

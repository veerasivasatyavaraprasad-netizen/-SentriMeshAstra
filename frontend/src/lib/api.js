const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

function getToken() {
  return localStorage.getItem("sma_token");
}

export function getSession() {
  const token = getToken();
  const role = localStorage.getItem("sma_role");
  const tenantId = localStorage.getItem("sma_tenant_id");
  const email = localStorage.getItem("sma_email");
  if (!token) return null;
  return { token, role, tenantId, email };
}

export function saveSession({ access_token, role, tenant_id }, email) {
  localStorage.setItem("sma_token", access_token);
  localStorage.setItem("sma_role", role);
  localStorage.setItem("sma_tenant_id", tenant_id || "");
  localStorage.setItem("sma_email", email);
}

export function clearSession() {
  localStorage.removeItem("sma_token");
  localStorage.removeItem("sma_role");
  localStorage.removeItem("sma_tenant_id");
  localStorage.removeItem("sma_email");
}

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = data.detail || JSON.stringify(data);
    } catch {
      /* ignore */
    }
    if (res.status === 401) {
      clearSession();
    }
    throw new ApiError(detail, res.status);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  login: (email, password) => request("/api/auth/login", { method: "POST", body: { email, password }, auth: false }),
  me: () => request("/api/auth/me"),
  createSecurityHolder: (payload) => request("/api/auth/security-holders", { method: "POST", body: payload }),

  listTenants: () => request("/api/tenants"),
  createTenant: (payload) => request("/api/tenants", { method: "POST", body: payload }),
  getTenant: (id) => request(`/api/tenants/${id}`),
  setKillSwitch: (id, payload) => request(`/api/tenants/${id}/kill-switch`, { method: "POST", body: payload }),

  getOverview: (tenantId) => request(`/api/tenants/${tenantId}/overview`),
  listIncidents: (tenantId) => request(`/api/tenants/${tenantId}/incidents`),
  listApprovals: (tenantId) => request(`/api/tenants/${tenantId}/approvals`),
  decideApproval: (tenantId, approvalId, payload) =>
    request(`/api/tenants/${tenantId}/approvals/${approvalId}/decide`, { method: "POST", body: payload }),
  listReports: (tenantId) => request(`/api/tenants/${tenantId}/reports`),
  generateReport: (tenantId) => request(`/api/tenants/${tenantId}/reports/generate-now`, { method: "POST" }),
  listActivity: (tenantId) => request(`/api/tenants/${tenantId}/activity`),
  listConnectors: (tenantId) => request(`/api/tenants/${tenantId}/connectors`),
  addConnector: (tenantId, payload) => request(`/api/tenants/${tenantId}/connectors`, { method: "POST", body: payload }),

  simulateAttack: (tenantId) => request(`/api/tenants/${tenantId}/demo/simulate-attack`, { method: "POST" }),
  requestExposureScan: (tenantId, domain) =>
    request(`/api/tenants/${tenantId}/exposure-scan?domain=${encodeURIComponent(domain)}`, { method: "POST" }),
};

export { ApiError };

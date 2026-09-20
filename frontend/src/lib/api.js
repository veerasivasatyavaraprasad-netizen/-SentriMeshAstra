import { getApiBaseUrl } from "./runtimeConfig";

const BASE_URL = getApiBaseUrl();

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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithColdStartRetry(url, init) {
  // A free-tier backend that's been idle can take up to ~60s to wake,
  // during which the browser's fetch() itself throws (no HTTP response
  // ever arrives) rather than returning an error status — one retry
  // after a short delay silently recovers the common case (a few
  // seconds asleep) without leaving every real network failure to just
  // retry forever.
  try {
    return await fetch(url, init);
  } catch {
    await sleep(3000);
    try {
      return await fetch(url, init);
    } catch {
      throw new Error(
        "Couldn't reach the server. If it's been idle for a while, it may still be waking up (free-tier instances sleep after inactivity and can take up to a minute) — try again in a few seconds."
      );
    }
  }
}

async function request(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetchWithColdStartRetry(`${BASE_URL}${path}`, {
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
  rollbackAction: (tenantId, proposalId) =>
    request(`/api/tenants/${tenantId}/actions/${proposalId}/rollback`, { method: "POST" }),
  listReports: (tenantId) => request(`/api/tenants/${tenantId}/reports`),
  generateReport: (tenantId) => request(`/api/tenants/${tenantId}/reports/generate-now`, { method: "POST" }),
  listActivity: (tenantId) => request(`/api/tenants/${tenantId}/activity`),
  listConnectors: (tenantId) => request(`/api/tenants/${tenantId}/connectors`),
  addConnector: (tenantId, payload) => request(`/api/tenants/${tenantId}/connectors`, { method: "POST", body: payload }),
  rotateConnectorToken: (tenantId, connectorId) =>
    request(`/api/tenants/${tenantId}/connectors/${connectorId}/rotate-token`, { method: "POST" }),

  platformAudit: () => request("/api/admin/platform-audit"),

  requestExposureScan: (tenantId, domain) =>
    request(`/api/tenants/${tenantId}/exposure-scan?domain=${encodeURIComponent(domain)}`, { method: "POST" }),
};

export { ApiError };

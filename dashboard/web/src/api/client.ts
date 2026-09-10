import type {
  Agent,
  Anomaly,
  AnomalyFilters,
  AuditEvent,
  EventFilters,
  Membership,
  Metrics,
  MetricsFilters,
  PendingApproval,
  TenantSettings,
  ToolCatalogEntry,
  User,
} from "./types";

// ApiError carries the HTTP status so callers can special-case 401 (not
// logged in) / 403 (not a member of this tenant, or a viewer hitting an
// admin-only route) per the backend's documented error conventions.
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...init,
  });

  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }

  if (!res.ok) {
    const message =
      (body && typeof body === "object" && "error" in body && typeof (body as { error: unknown }).error === "string"
        ? (body as { error: string }).error
        : undefined) ?? res.statusText ?? "request failed";
    throw new ApiError(res.status, message);
  }

  return body as T;
}

function query(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") sp.set(key, String(value));
  }
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

export const api = {
  signup: (data: { company_name: string; email: string; password: string }) =>
    request<{ user_id: string; tenant_id: string }>("/api/signup", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  login: (data: { email: string; password: string }) =>
    request<{ ok: boolean }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  logout: () => request<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),

  me: () => request<{ user: User; memberships: Membership[] }>("/api/me"),

  createAgent: (tenantId: string, name: string) =>
    request<{ agent_id: string; registration_token: string }>(
      `/api/agents${query({ tenant_id: tenantId })}`,
      { method: "POST", body: JSON.stringify({ name }) },
    ),

  listAgents: (tenantId: string) =>
    request<{ agents: Agent[] }>(`/api/agents${query({ tenant_id: tenantId })}`),

  listEvents: (tenantId: string, filters: EventFilters = {}) =>
    request<{ events: AuditEvent[] }>(
      `/api/events${query({ tenant_id: tenantId, ...filters })}`,
    ),

  metrics: (tenantId: string, filters: MetricsFilters = {}) =>
    request<Metrics>(`/api/metrics${query({ tenant_id: tenantId, ...filters })}`),

  listTools: (tenantId: string) =>
    request<{ tools: ToolCatalogEntry[] }>(`/api/tools${query({ tenant_id: tenantId })}`),

  setToolVerb: (tenantId: string, actionType: string, resource: string, verb: string) =>
    request<{ ok: boolean }>(`/api/tools/verb${query({ tenant_id: tenantId })}`, {
      method: "PUT",
      body: JSON.stringify({ action_type: actionType, resource, verb }),
    }),

  listAnomalies: (tenantId: string, filters: AnomalyFilters = {}) =>
    request<{ anomalies: Anomaly[] }>(
      `/api/anomalies${query({ tenant_id: tenantId, ...filters, unacknowledged: filters.unacknowledged ? "true" : undefined })}`,
    ),

  ackAnomaly: (tenantId: string, anomalyId: string) =>
    request<{ ok: boolean }>(`/api/anomalies/ack${query({ tenant_id: tenantId })}`, {
      method: "POST",
      body: JSON.stringify({ anomaly_id: anomalyId }),
    }),

  getSettings: (tenantId: string) =>
    request<TenantSettings>(`/api/settings${query({ tenant_id: tenantId })}`),

  putSettings: (tenantId: string, settings: TenantSettings) =>
    request<{ ok: boolean }>(`/api/settings${query({ tenant_id: tenantId })}`, {
      method: "PUT",
      body: JSON.stringify(settings),
    }),

  listPending: (tenantId: string) =>
    request<{ pending: PendingApproval[] }>(`/api/pending${query({ tenant_id: tenantId })}`),

  resolvePending: (tenantId: string, pendingId: string, resolution: "approve" | "deny") =>
    request<{ ok: boolean }>(`/api/pending/resolve${query({ tenant_id: tenantId })}`, {
      method: "POST",
      body: JSON.stringify({ pending_id: pendingId, resolution }),
    }),
};

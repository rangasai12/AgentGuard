// Mirrors dashboard/store/models.go exactly — this is the JSON contract
// the Go backend actually serves. Keep in sync with that file, not the
// other way around.

export type Role = "admin" | "viewer";

export interface User {
  id: string;
  email: string;
}

export interface Membership {
  tenant_id: string;
  tenant_name: string;
  role: Role;
}

export type AgentStatus = "pending" | "active";

export interface Agent {
  id: string;
  tenant_id: string;
  name: string;
  status: AgentStatus;
  last_seen_at?: string | null;
  created_at: string;
}

export type Decision = "allow" | "deny" | "require_approval";

export interface AuditEvent {
  id: number;
  tenant_id: string;
  agent_id: string;
  agent_name?: string;
  timestamp: string;
  actor?: string;
  action_type: string;
  resource: string;
  decision: string;
  matched_rule: string;
  reason?: string;
  approval_id?: string;
  latency_ms: number;
}

export interface EventFilters {
  agent_id?: string;
  actor?: string;
  action_type?: string;
  decision?: string;
  resource_contains?: string;
  since?: string;
  until?: string;
  limit?: number;
}

export type PendingStatus = "pending" | "approved" | "denied" | "resolved_elsewhere";

export interface PendingApproval {
  id: string;
  tenant_id: string;
  agent_id: string;
  agent_name?: string;
  local_id: string;
  actor?: string;
  action_type: string;
  resource: string;
  matched_rule: string;
  reason?: string;
  status: PendingStatus;
  requested_resolution?: string;
  created_at: string;
  resolved_at?: string | null;
}

export interface ResourceCount {
  value: string;
  count: number;
}

export interface Metrics {
  allow_count: number;
  deny_count: number;
  require_approval_count: number;
  top_denied_resources: ResourceCount[] | null;
  top_denied_rules: ResourceCount[] | null;
}

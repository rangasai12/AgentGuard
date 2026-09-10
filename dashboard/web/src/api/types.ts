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
  last_agent_version?: string;
  last_policy_hash?: string;
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
  latency_ms: number; // policy evaluation + approval wait, not tool execution
  event_id?: string;
  run_id?: string;
  agent_version?: string;
  policy_hash?: string;
  action?: EventAction;
  outcome?: EventOutcome;
}

// The daemon's structured engine.Action, stored verbatim. Only `type` is
// always present; the rest depends on the action type.
export interface EventAction {
  type: string;
  actor?: string;
  path?: string;
  domain?: string;
  method?: string;
  command?: string;
  server?: string;
  tool?: string;
  env_var?: string;
  name?: string;
  args?: Record<string, unknown>;
}

export type OutcomeStatus = "success" | "error";

export interface EventOutcome {
  status: OutcomeStatus;
  exec_ms: number;
  output?: string;
  output_bytes?: number;
  output_sha256?: string;
  error?: string;
  reported_at?: string | null;
}

export interface EventFilters {
  agent_id?: string;
  actor?: string;
  action_type?: string;
  decision?: string;
  resource_contains?: string;
  run_id?: string;
  agent_version?: string;
  outcome?: OutcomeStatus | "none" | "";
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

// Scopes a metrics request. Mirrors store.MetricsFilter.
export interface MetricsFilters {
  since?: string;
  until?: string;
  agent_id?: string;
  agent_version?: string;
  run_id?: string;
}

export interface VersionSummary {
  agent_version: string;
  first_seen: string;
  last_seen: string;
  count: number;
}

export interface Metrics {
  allow_count: number;
  deny_count: number;
  require_approval_count: number;
  top_denied_resources: ResourceCount[] | null;
  top_denied_rules: ResourceCount[] | null;

  total_count: number;
  reported_count: number;
  error_count: number;
  distinct_resources: number;
  by_action_type: ResourceCount[] | null;
  top_resources: ResourceCount[] | null; // by scope key ("fs_read:/workspace/docs/", "mcp_tool:crm.lookup")
  exec_p50_ms: number | null;
  exec_p95_ms: number | null;
  exec_samples: number;
  events_per_hour: number;
  first_seen?: string;
  last_seen?: string;
  // Only present when the request named an agent_id; every version that
  // agent has ever sent, most recent first, regardless of other filters.
  versions?: VersionSummary[];
}

// One row of the tenant's tool catalog. Mirrors store.ToolCatalogEntry.
export interface ToolCatalogEntry {
  tenant_id: string;
  action_type: string;
  resource: string;
  description?: string;
  arg_keys: string[];
  first_seen_at: string;
  last_seen_at: string;

  verb?: string; // "read" | "write" | "delete" | "permission" | "unknown" | ""
  verb_reason?: string;
  verb_confidence?: number | null;
  verb_source?: "llm" | "heuristic" | "user" | "";
  classified_at?: string | null;
}

// Mirrors store.TenantSettings: the tenant's anomaly-detection thresholds.
export interface TenantSettings {
  tenant_id: string;
  window_minutes: number;
  baseline_hours: number;
  min_baseline_events: number;
  volume_ratio: number;
  share_shift: number;
  deny_rate_ratio: number;
  error_rate_ratio: number;
  latency_ratio: number;
  bulk_ratio: number;
  min_events: number;
  updated_at: string;
}

export type AnomalyKind = "system" | "operation" | "scope" | "volume";

// Mirrors store.Anomaly: one detected deviation for one agent/version/window.
export interface Anomaly {
  id: string;
  tenant_id: string;
  agent_id: string;
  agent_name?: string;
  agent_version: string;
  kind: AnomalyKind;
  key: string;
  score: number;
  detail?: Record<string, unknown>;
  window_start: string;
  window_end: string;
  baseline_start?: string;
  baseline_end?: string;
  baseline_version?: string;
  detected_at: string;
  acknowledged_by?: string;
  acknowledged_at?: string | null;
}

export interface AnomalyFilters {
  agent_id?: string;
  unacknowledged?: boolean;
  since?: string;
}

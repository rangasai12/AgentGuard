package store

import "time"

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// Membership is one (user, tenant, role) tuple.
type Membership struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	Role       Role   `json:"role"`
}

type AgentStatus string

const (
	AgentPending AgentStatus = "pending"
	AgentActive  AgentStatus = "active"
)

// Agent is one registered agentguard-forwarder instance.
type Agent struct {
	ID         string      `json:"id"`
	TenantID   string      `json:"tenant_id"`
	Name       string      `json:"name"`
	Status     AgentStatus `json:"status"`
	LastSeenAt *time.Time  `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
}

// AuditEvent is one ingested policy decision — the same shape as
// daemon.AuditEvent plus the tenant/agent it was ingested under.
type AuditEvent struct {
	ID          int64     `json:"id"`
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	AgentName   string    `json:"agent_name,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Actor       string    `json:"actor,omitempty"`
	ActionType  string    `json:"action_type"`
	Resource    string    `json:"resource"`
	Decision    string    `json:"decision"`
	MatchedRule string    `json:"matched_rule"`
	Reason      string    `json:"reason,omitempty"`
	ApprovalID  string    `json:"approval_id,omitempty"`
	LatencyMS   int64     `json:"latency_ms"`
}

// EventFilter narrows a tenant-scoped event query. Zero-value fields are
// not filtered on. This is a strict superset of daemon.AuditFilter — it
// adds the time range and resource-substring search the local CLI has no
// way to do (the daemon only ever searches its 2000-event in-memory ring).
type EventFilter struct {
	AgentID          string
	Actor            string
	ActionType       string
	Decision         string
	ResourceContains string
	Since            *time.Time
	Until            *time.Time
	Limit            int
}

type PendingStatus string

const (
	PendingWaiting         PendingStatus = "pending"
	PendingApproved        PendingStatus = "approved"
	PendingDenied          PendingStatus = "denied"
	PendingResolvedElsewhere PendingStatus = "resolved_elsewhere"
)

// PendingApproval mirrors daemon.PendingApproval plus tenant/agent scoping
// and the resolution-relay bookkeeping described in schema.sql.
type PendingApproval struct {
	ID                  string        `json:"id"`
	TenantID            string        `json:"tenant_id"`
	AgentID             string        `json:"agent_id"`
	AgentName           string        `json:"agent_name,omitempty"`
	LocalID             string        `json:"local_id"`
	Actor               string        `json:"actor,omitempty"`
	ActionType          string        `json:"action_type"`
	Resource            string        `json:"resource"`
	MatchedRule         string        `json:"matched_rule"`
	Reason              string        `json:"reason,omitempty"`
	Status              PendingStatus `json:"status"`
	RequestedResolution string        `json:"requested_resolution,omitempty"`
	CreatedAt           time.Time     `json:"created_at"`
	ResolvedAt          *time.Time    `json:"resolved_at,omitempty"`
}

// Metrics is the aggregated summary the dashboard's overview page renders.
type Metrics struct {
	AllowCount            int64            `json:"allow_count"`
	DenyCount             int64            `json:"deny_count"`
	RequireApprovalCount  int64            `json:"require_approval_count"`
	TopDeniedResources    []ResourceCount  `json:"top_denied_resources"`
	TopDeniedRules        []ResourceCount  `json:"top_denied_rules"`
}

type ResourceCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

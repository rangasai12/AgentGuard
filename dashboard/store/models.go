package store

import (
	"encoding/json"
	"time"
)

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

	// LastAgentVersion / LastPolicyHash are the most recent values seen on
	// an ingested event from this agent ("" until one carries them).
	LastAgentVersion string `json:"last_agent_version,omitempty"`
	LastPolicyHash   string `json:"last_policy_hash,omitempty"`
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

	EventID      string          `json:"event_id,omitempty"`
	RunID        string          `json:"run_id,omitempty"`
	AgentVersion string          `json:"agent_version,omitempty"`
	PolicyHash   string          `json:"policy_hash,omitempty"`
	Action       json.RawMessage `json:"action,omitempty"` // the daemon's structured engine.Action, stored verbatim
	Outcome      *EventOutcome   `json:"outcome,omitempty"`
}

// EventOutcome mirrors daemon.Outcome plus when it was reported. The store
// does not import the daemon package (it never has), so the shape is
// restated here; the JSON field names are identical by design.
type EventOutcome struct {
	Status       string     `json:"status"`
	ExecMS       int64      `json:"exec_ms"`
	Output       string     `json:"output,omitempty"`
	OutputBytes  int64      `json:"output_bytes,omitempty"`
	OutputSHA256 string     `json:"output_sha256,omitempty"`
	Error        string     `json:"error,omitempty"`
	ReportedAt   *time.Time `json:"reported_at,omitempty"`
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
	RunID            string
	AgentVersion     string
	Outcome          string // "success" | "error" | "" (any); "none" matches events with no outcome yet
	Since            *time.Time
	Until            *time.Time
	Limit            int
}

type PendingStatus string

const (
	PendingWaiting           PendingStatus = "pending"
	PendingApproved          PendingStatus = "approved"
	PendingDenied            PendingStatus = "denied"
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

// MetricsFilter scopes a Metrics computation. Zero-value fields are not
// filtered on: the tenant-wide overview passes only a time range, the
// per-agent profile adds AgentID (and AgentVersion to compare versions),
// and the anomaly detector adds whichever window it is scoring.
type MetricsFilter struct {
	Since        *time.Time
	Until        *time.Time
	AgentID      string
	AgentVersion string
	RunID        string
}

// Metrics is the one aggregated summary over a set of events — the
// tenant-wide overview, an agent's profile, one version of that agent, or
// one anomaly-detection window are all the same shape over a different
// MetricsFilter.
//
// Exec percentiles are over reported outcomes only (ExecSamples of them)
// and nil when there are none. EventsPerHour divides TotalCount by the
// filter's [Since, Until) span, or by the observed FirstSeen..LastSeen span
// (at least one hour) when a bound is open.
type Metrics struct {
	AllowCount           int64           `json:"allow_count"`
	DenyCount            int64           `json:"deny_count"`
	RequireApprovalCount int64           `json:"require_approval_count"`
	TopDeniedResources   []ResourceCount `json:"top_denied_resources"`
	TopDeniedRules       []ResourceCount `json:"top_denied_rules"`

	TotalCount        int64           `json:"total_count"`
	ReportedCount     int64           `json:"reported_count"` // events with any outcome
	ErrorCount        int64           `json:"error_count"`    // events with outcome = error
	DistinctResources int64           `json:"distinct_resources"`
	ByActionType      []ResourceCount `json:"by_action_type"`
	TopResources      []ResourceCount `json:"top_resources"` // by scope key, top 20
	ExecP50MS         *float64        `json:"exec_p50_ms"`
	ExecP95MS         *float64        `json:"exec_p95_ms"`
	ExecSamples       int64           `json:"exec_samples"`
	EventsPerHour     float64         `json:"events_per_hour"`
	FirstSeen         *time.Time      `json:"first_seen,omitempty"`
	LastSeen          *time.Time      `json:"last_seen,omitempty"`

	// Versions lists every agent_version the filtered agent has ever sent,
	// most recent first — only when MetricsFilter.AgentID is set, and
	// deliberately ignoring the version and time filters so it can serve
	// as the option list for a version selector.
	Versions []VersionSummary `json:"versions,omitempty"`
}

// VersionSummary is one agent_version's lifetime as seen from its events.
type VersionSummary struct {
	AgentVersion string    `json:"agent_version"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Count        int64     `json:"count"`
}

// ToolCatalogEntry is one row of tool_catalog: a named tool a tenant's
// agents have called, with whatever description an enforcement point sent
// and, once classified, the coarse verb (read/write/delete/permission/
// unknown) the anomaly detector's "operation" kind buckets it into.
type ToolCatalogEntry struct {
	TenantID    string    `json:"tenant_id"`
	ActionType  string    `json:"action_type"`
	Resource    string    `json:"resource"`
	Description string    `json:"description,omitempty"`
	ArgKeys     []string  `json:"arg_keys"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`

	Verb           string     `json:"verb,omitempty"`
	VerbReason     string     `json:"verb_reason,omitempty"`
	VerbConfidence *float64   `json:"verb_confidence,omitempty"`
	VerbSource     string     `json:"verb_source,omitempty"` // "llm" | "heuristic" | "user"
	ClassifiedAt   *time.Time `json:"classified_at,omitempty"`
}

// TenantSettings holds one tenant's anomaly-detection thresholds, editable
// from the Settings page. See DefaultTenantSettings for what a tenant with
// no saved settings gets.
type TenantSettings struct {
	TenantID          string    `json:"tenant_id"`
	WindowMinutes     int       `json:"window_minutes"`
	BaselineHours     int       `json:"baseline_hours"`
	MinBaselineEvents int       `json:"min_baseline_events"`
	VolumeRatio       float64   `json:"volume_ratio"`
	ShareShift        float64   `json:"share_shift"`
	DenyRateRatio     float64   `json:"deny_rate_ratio"`
	ErrorRateRatio    float64   `json:"error_rate_ratio"`
	LatencyRatio      float64   `json:"latency_ratio"`
	BulkRatio         float64   `json:"bulk_ratio"`
	MinEvents         int       `json:"min_events"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// DefaultTenantSettings is the one place these numbers are named. Every
// caller that needs a tenant's settings but finds no saved row uses this
// rather than repeating the numbers inline.
func DefaultTenantSettings(tenantID string) TenantSettings {
	return TenantSettings{
		TenantID:          tenantID,
		WindowMinutes:     60,
		BaselineHours:     24,
		MinBaselineEvents: 50,
		VolumeRatio:       3,
		ShareShift:        0.3,
		DenyRateRatio:     3,
		ErrorRateRatio:    3,
		LatencyRatio:      3,
		BulkRatio:         5,
		MinEvents:         5,
	}
}

// AnomalyKind is one of the four deviation classes the detector reports.
type AnomalyKind string

const (
	AnomalySystem    AnomalyKind = "system"    // a new footprint, or elevated error rate / latency
	AnomalyOperation AnomalyKind = "operation" // a shift in read/write/delete/permission mix, or deny rate
	AnomalyScope     AnomalyKind = "scope"     // an abnormally large single call for its resource
	AnomalyVolume    AnomalyKind = "volume"    // elevated call rate, overall or per run
)

// Anomaly is one row of the anomalies table: one deviation of one kind,
// for one agent/version/window, scored against its baseline.
type Anomaly struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	AgentID         string          `json:"agent_id"`
	AgentName       string          `json:"agent_name,omitempty"`
	AgentVersion    string          `json:"agent_version"`
	Kind            AnomalyKind     `json:"kind"`
	Key             string          `json:"key"`
	Score           float64         `json:"score"`
	Detail          json.RawMessage `json:"detail,omitempty"`
	WindowStart     time.Time       `json:"window_start"`
	WindowEnd       time.Time       `json:"window_end"`
	BaselineStart   *time.Time      `json:"baseline_start,omitempty"`
	BaselineEnd     *time.Time      `json:"baseline_end,omitempty"`
	BaselineVersion string          `json:"baseline_version,omitempty"`
	DetectedAt      time.Time       `json:"detected_at"`
	AcknowledgedBy  string          `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  *time.Time      `json:"acknowledged_at,omitempty"`
}

// AnomalyFilter narrows ListAnomalies. Zero-value fields are not filtered on.
type AnomalyFilter struct {
	AgentID        string
	Unacknowledged bool
	Since          *time.Time
	Limit          int
}

// ScopeOutputStat is one scope key's output-size profile over a window: how
// large the biggest reported call was (Max) and, for a baseline window,
// what "normal" large looks like (P95) — the "scope" anomaly kind's bulk
// check compares the two.
type ScopeOutputStat struct {
	Max     int64
	P95     float64
	Samples int64
}

type ResourceCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

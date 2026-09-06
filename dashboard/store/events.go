package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// IngestedEvent is what a forwarder sends upstream for one locally-recorded
// AuditEvent — the same fields daemon.AuditEvent carries, minus tenant/agent
// (those come from the authenticated API key, never from this payload).
// Timestamp uses encoding/json's native time.Time (de)serialization
// (RFC3339Nano), so it round-trips exactly with daemon.AuditEvent's own
// Timestamp field with no reformatting on either end.
type IngestedEvent struct {
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

// InsertEvents batch-inserts events under (tenantID, agentID) — both taken
// as explicit parameters derived from the authenticated agent, never from
// the event payloads themselves.
func (s *Store) InsertEvents(ctx context.Context, tenantID, agentID string, events []IngestedEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range events {
		batch.Queue(
			`INSERT INTO audit_events
			 (tenant_id, agent_id, ts, actor, action_type, resource, decision, matched_rule, reason, approval_id, latency_ms)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			tenantID, agentID, e.Timestamp, e.Actor, e.ActionType, e.Resource, e.Decision, e.MatchedRule, e.Reason, e.ApprovalID, e.LatencyMS,
		)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range events {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("inserting audit event: %w", err)
		}
	}
	return nil
}

// QueryEvents returns events for tenantID matching filter, most recent
// first. filter.Limit defaults to 100 and is capped at 1000.
func (s *Store) QueryEvents(ctx context.Context, tenantID string, filter EventFilter) ([]AuditEvent, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	var b strings.Builder
	args := []any{tenantID}
	b.WriteString(`SELECT audit_events.id, audit_events.tenant_id, audit_events.agent_id, agents.name,
	                       audit_events.ts, audit_events.actor, audit_events.action_type, audit_events.resource,
	                       audit_events.decision, audit_events.matched_rule, audit_events.reason,
	                       audit_events.approval_id, audit_events.latency_ms
	                FROM audit_events JOIN agents ON agents.id = audit_events.agent_id
	                WHERE audit_events.tenant_id = $1`)

	addFilter := func(clause string, val any) {
		args = append(args, val)
		fmt.Fprintf(&b, " AND %s $%d", clause, len(args))
	}
	if filter.AgentID != "" {
		addFilter("audit_events.agent_id =", filter.AgentID)
	}
	if filter.Actor != "" {
		addFilter("audit_events.actor =", filter.Actor)
	}
	if filter.ActionType != "" {
		addFilter("audit_events.action_type =", filter.ActionType)
	}
	if filter.Decision != "" {
		addFilter("audit_events.decision =", filter.Decision)
	}
	if filter.ResourceContains != "" {
		addFilter("audit_events.resource ILIKE", "%"+filter.ResourceContains+"%")
	}
	if filter.Since != nil {
		addFilter("audit_events.ts >=", *filter.Since)
	}
	if filter.Until != nil {
		addFilter("audit_events.ts <=", *filter.Until)
	}

	args = append(args, limit)
	fmt.Fprintf(&b, " ORDER BY audit_events.ts DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, b.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("querying events: %w", err)
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AgentID, &e.AgentName, &e.Timestamp, &e.Actor,
			&e.ActionType, &e.Resource, &e.Decision, &e.MatchedRule, &e.Reason, &e.ApprovalID, &e.LatencyMS); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Metrics computes the aggregated summary for tenantID over [since, until).
// A nil since/until leaves that bound open.
func (s *Store) Metrics(ctx context.Context, tenantID string, since, until *time.Time) (Metrics, error) {
	var m Metrics

	where := `tenant_id = $1`
	args := []any{tenantID}
	if since != nil {
		args = append(args, *since)
		where += fmt.Sprintf(" AND ts >= $%d", len(args))
	}
	if until != nil {
		args = append(args, *until)
		where += fmt.Sprintf(" AND ts <= $%d", len(args))
	}

	rows, err := s.pool.Query(ctx,
		`SELECT decision, count(*) FROM audit_events WHERE `+where+` GROUP BY decision`, args...)
	if err != nil {
		return m, fmt.Errorf("counting decisions: %w", err)
	}
	for rows.Next() {
		var decision string
		var count int64
		if err := rows.Scan(&decision, &count); err != nil {
			rows.Close()
			return m, err
		}
		switch decision {
		case "allow":
			m.AllowCount = count
		case "deny":
			m.DenyCount = count
		case "require_approval":
			m.RequireApprovalCount = count
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, err
	}

	m.TopDeniedResources, err = s.topN(ctx, "resource", where+" AND decision = 'deny'", args)
	if err != nil {
		return m, err
	}
	m.TopDeniedRules, err = s.topN(ctx, "matched_rule", where+" AND decision = 'deny'", args)
	if err != nil {
		return m, err
	}
	return m, nil
}

func (s *Store) topN(ctx context.Context, column, where string, args []any) ([]ResourceCount, error) {
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s, count(*) c FROM audit_events WHERE %s GROUP BY %s ORDER BY c DESC LIMIT 10`, column, where, column),
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("aggregating top %s: %w", column, err)
	}
	defer rows.Close()

	var out []ResourceCount
	for rows.Next() {
		var rc ResourceCount
		if err := rows.Scan(&rc.Value, &rc.Count); err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

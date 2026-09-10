package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"agentguard/engine"
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

	// Kind is "" for a decision and "outcome" for a patch that carries only
	// EventID + Outcome (see daemon.KindOutcome); a patch updates the
	// matching decision row rather than inserting one.
	Kind         string          `json:"kind,omitempty"`
	EventID      string          `json:"event_id,omitempty"`
	RunID        string          `json:"run_id,omitempty"`
	AgentVersion string          `json:"agent_version,omitempty"`
	PolicyHash   string          `json:"policy_hash,omitempty"`
	Action       json.RawMessage `json:"action,omitempty"`
	Outcome      *EventOutcome   `json:"outcome,omitempty"`
}

// IngestKindOutcome is the IngestedEvent.Kind value of an outcome patch —
// the same string daemon.KindOutcome uses on the wire.
const IngestKindOutcome = "outcome"

// InsertEvents batch-inserts events under (tenantID, agentID) — both taken
// as explicit parameters derived from the authenticated agent, never from
// the event payloads themselves.
func (s *Store) InsertEvents(ctx context.Context, tenantID, agentID string, events []IngestedEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	queued := 0
	lastVersion, lastPolicy := "", ""
	seenTools := map[string]*toolSeen{}
	for _, e := range events {
		if e.Kind == IngestKindOutcome {
			// An outcome patch: update the decision it refers to. Zero rows
			// matched (the decision was never shipped, or arrived later) is
			// not an error — the patch is simply lost, same as locally.
			if e.EventID == "" || e.Outcome == nil {
				continue
			}
			batch.Queue(
				`UPDATE audit_events
				 SET outcome = $4, exec_ms = $5, output = $6, output_bytes = $7, output_sha256 = $8, error = $9, reported_at = $10
				 WHERE tenant_id = $1 AND agent_id = $2 AND event_id = $3 AND outcome = ''`,
				tenantID, agentID, e.EventID,
				e.Outcome.Status, e.Outcome.ExecMS, e.Outcome.Output, e.Outcome.OutputBytes, e.Outcome.OutputSHA256, e.Outcome.Error, e.Timestamp,
			)
			queued++
			continue
		}
		var action any // nil -> SQL NULL; JSONB otherwise
		if len(e.Action) > 0 {
			action = string(e.Action)
		}
		batch.Queue(
			`INSERT INTO audit_events
			 (tenant_id, agent_id, ts, actor, action_type, resource, decision, matched_rule, reason, approval_id, latency_ms,
			  event_id, run_id, agent_version, policy_hash, action, scope_key)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
			tenantID, agentID, e.Timestamp, e.Actor, e.ActionType, e.Resource, e.Decision, e.MatchedRule, e.Reason, e.ApprovalID, e.LatencyMS,
			e.EventID, e.RunID, e.AgentVersion, e.PolicyHash, action, engine.ScopeKey(engine.ActionType(e.ActionType), e.Resource),
		)
		queued++
		observeTool(seenTools, e)
		if e.AgentVersion != "" {
			lastVersion = e.AgentVersion
		}
		if e.PolicyHash != "" {
			lastPolicy = e.PolicyHash
		}
	}
	if lastVersion != "" || lastPolicy != "" {
		batch.Queue(
			`UPDATE agents SET last_agent_version = CASE WHEN $2 = '' THEN last_agent_version ELSE $2 END,
			                   last_policy_hash   = CASE WHEN $3 = '' THEN last_policy_hash   ELSE $3 END
			 WHERE id = $1 AND tenant_id = $4`,
			agentID, lastVersion, lastPolicy, tenantID,
		)
		queued++
	}
	queued += queueToolCatalogUpserts(batch, tenantID, seenTools)
	if queued == 0 {
		return nil
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < queued; i++ {
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
	                       audit_events.approval_id, audit_events.latency_ms,
	                       audit_events.event_id, audit_events.run_id, audit_events.agent_version, audit_events.policy_hash,
	                       audit_events.action, audit_events.outcome, audit_events.exec_ms, audit_events.output,
	                       audit_events.output_bytes, audit_events.output_sha256, audit_events.error, audit_events.reported_at
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
	if filter.RunID != "" {
		addFilter("audit_events.run_id =", filter.RunID)
	}
	if filter.AgentVersion != "" {
		addFilter("audit_events.agent_version =", filter.AgentVersion)
	}
	switch filter.Outcome {
	case "":
	case "none":
		b.WriteString(" AND audit_events.outcome = ''")
	default:
		addFilter("audit_events.outcome =", filter.Outcome)
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
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// scanEvent reads one row of the column list QueryEvents selects — kept
// next to that SELECT so the two are changed together.
func scanEvent(rows pgx.Rows) (AuditEvent, error) {
	var e AuditEvent
	var action []byte
	var outcome, output, outputSHA, errText string
	var execMS *int64
	var outputBytes int64
	var reportedAt *time.Time
	if err := rows.Scan(&e.ID, &e.TenantID, &e.AgentID, &e.AgentName, &e.Timestamp, &e.Actor,
		&e.ActionType, &e.Resource, &e.Decision, &e.MatchedRule, &e.Reason, &e.ApprovalID, &e.LatencyMS,
		&e.EventID, &e.RunID, &e.AgentVersion, &e.PolicyHash,
		&action, &outcome, &execMS, &output, &outputBytes, &outputSHA, &errText, &reportedAt); err != nil {
		return e, err
	}
	if len(action) > 0 {
		e.Action = json.RawMessage(action)
	}
	if outcome != "" {
		o := &EventOutcome{Status: outcome, Output: output, OutputBytes: outputBytes, OutputSHA256: outputSHA, Error: errText, ReportedAt: reportedAt}
		if execMS != nil {
			o.ExecMS = *execMS
		}
		e.Outcome = o
	}
	return e, nil
}

// scopeKeyExpr is the grouping expression for an event's footprint: the
// stored scope_key, falling back to the raw resource for rows ingested
// before that column existed.
const scopeKeyExpr = `COALESCE(NULLIF(scope_key, ''), resource)`

// metricsWhere builds the WHERE clause + positional args every
// MetricsFilter-scoped query shares (Metrics itself, and the Phase 4
// anomaly detector's narrower aggregates below) — one filter-to-SQL
// translation, reused rather than re-derived per query.
func metricsWhere(tenantID string, filter MetricsFilter) (string, []any) {
	where := `tenant_id = $1`
	args := []any{tenantID}
	add := func(clause string, v any) {
		args = append(args, v)
		where += fmt.Sprintf(" AND %s $%d", clause, len(args))
	}
	if filter.Since != nil {
		add("ts >=", *filter.Since)
	}
	if filter.Until != nil {
		add("ts <", *filter.Until)
	}
	if filter.AgentID != "" {
		add("agent_id =", filter.AgentID)
	}
	if filter.AgentVersion != "" {
		add("agent_version =", filter.AgentVersion)
	}
	if filter.RunID != "" {
		add("run_id =", filter.RunID)
	}
	return where, args
}

// Metrics computes the aggregated summary for tenantID over the events
// filter selects. See MetricsFilter for what each caller passes.
func (s *Store) Metrics(ctx context.Context, tenantID string, filter MetricsFilter) (Metrics, error) {
	var m Metrics
	where, args := metricsWhere(tenantID, filter)

	var first, last *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE decision = 'allow'),
		       count(*) FILTER (WHERE decision = 'deny'),
		       count(*) FILTER (WHERE decision = 'require_approval'),
		       count(*) FILTER (WHERE outcome <> ''),
		       count(*) FILTER (WHERE outcome = 'error'),
		       count(DISTINCT `+scopeKeyExpr+`),
		       count(exec_ms),
		       percentile_cont(0.5) WITHIN GROUP (ORDER BY exec_ms),
		       percentile_cont(0.95) WITHIN GROUP (ORDER BY exec_ms),
		       min(ts), max(ts)
		FROM audit_events WHERE `+where, args...,
	).Scan(&m.TotalCount, &m.AllowCount, &m.DenyCount, &m.RequireApprovalCount,
		&m.ReportedCount, &m.ErrorCount, &m.DistinctResources, &m.ExecSamples,
		&m.ExecP50MS, &m.ExecP95MS, &first, &last)
	if err != nil {
		return m, fmt.Errorf("aggregating events: %w", err)
	}
	m.FirstSeen, m.LastSeen = first, last
	m.EventsPerHour = eventsPerHour(m.TotalCount, filter, first, last)

	if m.TopDeniedResources, err = s.topN(ctx, "resource", where+" AND decision = 'deny'", args, 10); err != nil {
		return m, err
	}
	if m.TopDeniedRules, err = s.topN(ctx, "matched_rule", where+" AND decision = 'deny'", args, 10); err != nil {
		return m, err
	}
	if m.ByActionType, err = s.topN(ctx, "action_type", where, args, 10); err != nil {
		return m, err
	}
	if m.TopResources, err = s.topN(ctx, scopeKeyExpr, where, args, 20); err != nil {
		return m, err
	}

	if filter.AgentID != "" {
		rows, err := s.pool.Query(ctx,
			`SELECT agent_version, min(ts), max(ts), count(*) FROM audit_events
			 WHERE tenant_id = $1 AND agent_id = $2 GROUP BY agent_version ORDER BY max(ts) DESC`,
			tenantID, filter.AgentID)
		if err != nil {
			return m, fmt.Errorf("listing agent versions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v VersionSummary
			if err := rows.Scan(&v.AgentVersion, &v.FirstSeen, &v.LastSeen, &v.Count); err != nil {
				return m, err
			}
			m.Versions = append(m.Versions, v)
		}
		if err := rows.Err(); err != nil {
			return m, err
		}
	}
	return m, nil
}

// eventsPerHour is total over the filter's span, or over the observed span
// (never less than an hour) when a bound is open.
func eventsPerHour(total int64, filter MetricsFilter, first, last *time.Time) float64 {
	if total == 0 {
		return 0
	}
	var span time.Duration
	switch {
	case filter.Since != nil && filter.Until != nil:
		span = filter.Until.Sub(*filter.Since)
	case first != nil && last != nil:
		span = last.Sub(*first)
	}
	if span < time.Hour {
		span = time.Hour
	}
	return float64(total) / span.Hours()
}

// topN groups the events `where` selects by expr (a column or a fixed SQL
// expression — never caller input) and returns the most frequent limit
// values.
func (s *Store) topN(ctx context.Context, expr, where string, args []any, limit int) ([]ResourceCount, error) {
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s v, count(*) c FROM audit_events WHERE %s GROUP BY v ORDER BY c DESC, v ASC LIMIT %d`, expr, where, limit),
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("aggregating top %s: %w", expr, err)
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

// RunEventCounts returns how many events each run_id contains among the
// events filter selects (events with no run_id excluded). The anomaly
// detector's "volume" kind uses this to compare calls-per-run in the
// window against the baseline distribution. A thin wrapper over the
// existing topN rather than a new query: topN's (value, count) shape is
// exactly what's needed here, grouped by run_id instead of a resource.
func (s *Store) RunEventCounts(ctx context.Context, tenantID string, filter MetricsFilter) ([]ResourceCount, error) {
	where, args := metricsWhere(tenantID, filter)
	return s.topN(ctx, "run_id", where+" AND run_id <> ''", args, 1000)
}

// VerbCounts buckets the events filter selects by engine.Verb: mcp_tool/
// function calls resolve through the tenant's tool_catalog (unclassified
// rows count as VerbUnknown), everything else resolves directly via
// engine.HeuristicVerb. Also a topN wrapper, grouping on a composite
// action_type+resource expression so the (action_type, resource) pairs it
// returns can be bucketed by verb afterward — topN's single-count-per-group
// shape is otherwise exactly what's needed; a bespoke query would just
// duplicate it.
func (s *Store) VerbCounts(ctx context.Context, tenantID string, filter MetricsFilter) (map[engine.Verb]int64, error) {
	catalog, err := s.ListToolCatalog(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byKey := map[string]ToolCatalogEntry{}
	for _, t := range catalog {
		byKey[t.ActionType+"\x00"+t.Resource] = t
	}

	where, args := metricsWhere(tenantID, filter)
	// Postgres text can never hold a null byte, so the composite grouping
	// key uses an ASCII unit separator instead — vanishingly unlikely to
	// appear in an action type or resource string, and cheap to split
	// back apart in Go.
	rows, err := s.topN(ctx, `action_type || chr(31) || resource`, where, args, 100000)
	if err != nil {
		return nil, fmt.Errorf("bucketing verbs: %w", err)
	}
	counts := map[engine.Verb]int64{}
	for _, rc := range rows {
		actionType, resource, _ := strings.Cut(rc.Value, "\x1f")
		counts[verbFor(byKey, actionType, resource)] += rc.Count
	}
	return counts, nil
}

// ScopeOutputStats returns, per scope key, the largest reported output
// size (Max) and — over a baseline window — the 95th-percentile size
// (P95), restricted to events with a reported outcome. The "scope"
// anomaly kind compares a window's Max for a key against the baseline's
// P95 for that key to catch an abnormally bulk single call. Distinct from
// topN (count-only per group): this needs two aggregates per group, which
// is a different SQL shape, not a parameterization of the same one.
func (s *Store) ScopeOutputStats(ctx context.Context, tenantID string, filter MetricsFilter) (map[string]ScopeOutputStat, error) {
	where, args := metricsWhere(tenantID, filter)
	rows, err := s.pool.Query(ctx, `
		SELECT `+scopeKeyExpr+` k, max(output_bytes), percentile_cont(0.95) WITHIN GROUP (ORDER BY output_bytes), count(*)
		FROM audit_events WHERE `+where+` AND outcome <> ''
		GROUP BY k`, args...,
	)
	if err != nil {
		return nil, fmt.Errorf("aggregating scope output stats: %w", err)
	}
	defer rows.Close()
	out := map[string]ScopeOutputStat{}
	for rows.Next() {
		var key string
		var stat ScopeOutputStat
		if err := rows.Scan(&key, &stat.Max, &stat.P95, &stat.Samples); err != nil {
			return nil, err
		}
		out[key] = stat
	}
	return out, rows.Err()
}

// NewScopeKeys returns scope keys that appear for (tenantID, agentID,
// windowVersion) in [windowStart, windowEnd) but never appeared for
// (tenantID, agentID, baselineVersion) in [baselineStart, baselineEnd) —
// the "system" anomaly kind's new-footprint check. Ordered by how often
// the new key occurred in the window, most first, capped at limit. This is
// a set-difference query no existing method can express: topN counts
// within one filter, it does not exclude what a second filter already saw.
func (s *Store) NewScopeKeys(
	ctx context.Context, tenantID, agentID, windowVersion string, windowStart, windowEnd time.Time,
	baselineVersion string, baselineStart, baselineEnd time.Time, limit int,
) ([]ResourceCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT k, count(*) c FROM (
			SELECT `+scopeKeyExpr+` k FROM audit_events
			WHERE tenant_id = $1 AND agent_id = $2 AND agent_version = $3 AND ts >= $4 AND ts < $5
		) window_keys
		WHERE k NOT IN (
			SELECT DISTINCT `+scopeKeyExpr+` FROM audit_events
			WHERE tenant_id = $1 AND agent_id = $2 AND agent_version = $6 AND ts >= $7 AND ts < $8
		)
		GROUP BY k ORDER BY c DESC, k ASC LIMIT $9`,
		tenantID, agentID, windowVersion, windowStart, windowEnd,
		baselineVersion, baselineStart, baselineEnd, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("finding new scope keys: %w", err)
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

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"agentguard/engine"
)

// catalogedActionTypes are the action types whose resources are stable
// tool names worth cataloging. Built-in types (fs paths, shell command
// lines, network domains) have implied semantics and unbounded cardinality.
var catalogedActionTypes = map[string]bool{"mcp_tool": true, "function": true}

// toolSeen is what InsertEvents learns about one tool from a batch: the
// description if any event in the batch carried one, and the union of
// argument names seen.
type toolSeen struct {
	actionType, resource string
	description          string
	argKeys              map[string]bool
	lastSeen             time.Time
}

// observeTool folds one event into seen (keyed by action_type + "\x00" +
// resource). Called by InsertEvents for every decision event.
func observeTool(seen map[string]*toolSeen, e IngestedEvent) {
	if !catalogedActionTypes[e.ActionType] || e.Resource == "" {
		return
	}
	key := e.ActionType + "\x00" + e.Resource
	ts := seen[key]
	if ts == nil {
		ts = &toolSeen{actionType: e.ActionType, resource: e.Resource, argKeys: map[string]bool{}}
		seen[key] = ts
	}
	if e.Timestamp.After(ts.lastSeen) {
		ts.lastSeen = e.Timestamp
	}
	if len(e.Action) == 0 {
		return
	}
	var a struct {
		Description string                     `json:"description"`
		Args        map[string]json.RawMessage `json:"args"`
	}
	if json.Unmarshal(e.Action, &a) != nil {
		return
	}
	if a.Description != "" {
		ts.description = a.Description
	}
	for k := range a.Args {
		ts.argKeys[k] = true
	}
}

// queueToolCatalogUpserts adds one upsert per tool seen in the batch. A
// batch that carries no description for a tool keeps whatever description
// the row already has; argument names accumulate.
func queueToolCatalogUpserts(batch *pgx.Batch, tenantID string, seen map[string]*toolSeen) int {
	n := 0
	for _, ts := range seen {
		keys := make([]string, 0, len(ts.argKeys))
		for k := range ts.argKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		keysJSON, _ := json.Marshal(keys)
		batch.Queue(
			`INSERT INTO tool_catalog (tenant_id, action_type, resource, description, arg_keys, first_seen_at, last_seen_at)
			 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $6)
			 ON CONFLICT (tenant_id, action_type, resource) DO UPDATE SET
			   description  = CASE WHEN EXCLUDED.description = '' THEN tool_catalog.description ELSE EXCLUDED.description END,
			   arg_keys     = (SELECT COALESCE(jsonb_agg(DISTINCT k ORDER BY k), '[]'::jsonb)
			                   FROM jsonb_array_elements_text(tool_catalog.arg_keys || EXCLUDED.arg_keys) AS k),
			   last_seen_at = GREATEST(tool_catalog.last_seen_at, EXCLUDED.last_seen_at)`,
			tenantID, ts.actionType, ts.resource, ts.description, string(keysJSON), ts.lastSeen,
		)
		n++
	}
	return n
}

// ListToolCatalog returns every tool tenantID's agents have called, most
// recently seen first.
func (s *Store) ListToolCatalog(ctx context.Context, tenantID string) ([]ToolCatalogEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT tenant_id, action_type, resource, description, arg_keys, first_seen_at, last_seen_at,
		        verb, verb_reason, verb_confidence, verb_source, classified_at
		 FROM tool_catalog WHERE tenant_id = $1 ORDER BY last_seen_at DESC, resource ASC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing tool catalog: %w", err)
	}
	defer rows.Close()
	var out []ToolCatalogEntry
	for rows.Next() {
		var e ToolCatalogEntry
		var keys []byte
		if err := rows.Scan(&e.TenantID, &e.ActionType, &e.Resource, &e.Description, &keys, &e.FirstSeenAt, &e.LastSeenAt,
			&e.Verb, &e.VerbReason, &e.VerbConfidence, &e.VerbSource, &e.ClassifiedAt); err != nil {
			return nil, err
		}
		if len(keys) > 0 {
			_ = json.Unmarshal(keys, &e.ArgKeys)
		}
		if e.ArgKeys == nil {
			e.ArgKeys = []string{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetToolVerb sets one tool_catalog row's verb classification — either the
// classifier's answer (source "llm"/"heuristic") or an admin's manual
// override (source "user"). It is the one writer of these columns.
func (s *Store) SetToolVerb(ctx context.Context, tenantID, actionType, resource, verb, reason string, confidence *float64, source string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE tool_catalog SET verb = $4, verb_reason = $5, verb_confidence = $6, verb_source = $7, classified_at = now()
		 WHERE tenant_id = $1 AND action_type = $2 AND resource = $3`,
		tenantID, actionType, resource, verb, reason, confidence, source,
	)
	if err != nil {
		return fmt.Errorf("setting tool verb: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// verbFor classifies one (action_type, resource) pair for VerbCounts:
// mcp_tool/function calls resolve through the tenant's tool_catalog (a row
// with no verb yet counts as unknown), everything else resolves directly
// via the one heuristic definition, engine.HeuristicVerb — never a second
// copy of that logic in SQL.
func verbFor(catalog map[string]ToolCatalogEntry, actionType, resource string) engine.Verb {
	if actionType == "mcp_tool" || actionType == "function" {
		if entry, ok := catalog[actionType+"\x00"+resource]; ok && entry.Verb != "" {
			return engine.Verb(entry.Verb)
		}
		return engine.VerbUnknown
	}
	return engine.HeuristicVerb(engine.ActionType(actionType), resource)
}

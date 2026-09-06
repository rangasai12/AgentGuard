package store

import (
	"context"
	"fmt"
)

// SyncedPending is one entry from a forwarder's snapshot of what its local
// daemon currently reports as pending (daemon.PendingApproval, minus
// tenant/agent scoping — that comes from the authenticated API key).
type SyncedPending struct {
	LocalID     string `json:"local_id"`
	Actor       string `json:"actor,omitempty"`
	ActionType  string `json:"action_type"`
	Resource    string `json:"resource"`
	MatchedRule string `json:"matched_rule"`
	Reason      string `json:"reason,omitempty"`
}

// SyncPending reconciles agentID's currently-pending approvals with what
// its forwarder just reported. Upserts each entry as 'pending' (idempotent
// across repeated polls, via the (agent_id, local_id) unique constraint),
// then marks any row that was 'pending' for this agent but is absent from
// the current snapshot as 'resolved_elsewhere' — it was resolved locally
// via `agentctl approve/deny` (or timed out) between polls, not through the
// dashboard.
func (s *Store) SyncPending(ctx context.Context, tenantID, agentID string, current []SyncedPending) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	localIDs := make([]string, len(current))
	for i, p := range current {
		localIDs[i] = p.LocalID
		_, err := tx.Exec(ctx,
			`INSERT INTO pending_approvals
			   (id, tenant_id, agent_id, local_id, actor, action_type, resource, matched_rule, reason, status)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
			 ON CONFLICT (agent_id, local_id) DO NOTHING`,
			newID("pending"), tenantID, agentID, p.LocalID, p.Actor, p.ActionType, p.Resource, p.MatchedRule, p.Reason,
		)
		if err != nil {
			return fmt.Errorf("upserting pending approval %s: %w", p.LocalID, err)
		}
	}

	if len(localIDs) == 0 {
		localIDs = []string{""} // NOT IN () is invalid SQL; this never matches a real local_id
	}
	if _, err := tx.Exec(ctx,
		`UPDATE pending_approvals SET status = 'resolved_elsewhere', resolved_at = now()
		 WHERE agent_id = $1 AND status = 'pending' AND local_id != ALL($2)`,
		agentID, localIDs,
	); err != nil {
		return fmt.Errorf("reconciling resolved-elsewhere approvals: %w", err)
	}

	return tx.Commit(ctx)
}

// ListPending returns every currently-pending approval for tenantID.
func (s *Store) ListPending(ctx context.Context, tenantID string) ([]PendingApproval, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT pending_approvals.id, pending_approvals.tenant_id, pending_approvals.agent_id, agents.name,
		        pending_approvals.local_id, pending_approvals.actor, pending_approvals.action_type,
		        pending_approvals.resource, pending_approvals.matched_rule, pending_approvals.reason,
		        pending_approvals.status, coalesce(pending_approvals.requested_resolution, ''),
		        pending_approvals.created_at, pending_approvals.resolved_at
		 FROM pending_approvals JOIN agents ON agents.id = pending_approvals.agent_id
		 WHERE pending_approvals.tenant_id = $1 AND pending_approvals.status = 'pending'
		 ORDER BY pending_approvals.created_at ASC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing pending approvals: %w", err)
	}
	defer rows.Close()

	var out []PendingApproval
	for rows.Next() {
		var p PendingApproval
		if err := rows.Scan(&p.ID, &p.TenantID, &p.AgentID, &p.AgentName, &p.LocalID, &p.Actor, &p.ActionType,
			&p.Resource, &p.MatchedRule, &p.Reason, &p.Status, &p.RequestedResolution, &p.CreatedAt, &p.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RequestResolution records that a dashboard user clicked Approve/Deny on
// pendingID. It does NOT mark the approval resolved — status stays
// 'pending' until the owning agent's forwarder actually relays the
// decision to its local daemon and calls AckResolution. This is what makes
// "the browser click was recorded" distinguishable from "the local daemon
// enforced it", which matters because only the latter is real enforcement.
func (s *Store) RequestResolution(ctx context.Context, tenantID, pendingID, resolvedByUserID, resolution string) error {
	if resolution != "approve" && resolution != "deny" {
		return fmt.Errorf("invalid resolution %q, must be \"approve\" or \"deny\"", resolution)
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE pending_approvals SET requested_resolution = $1, resolved_by = $2
		 WHERE id = $3 AND tenant_id = $4 AND status = 'pending'`,
		resolution, resolvedByUserID, pendingID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("requesting resolution: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolutionRequest is one pending approval a forwarder needs to relay to
// its local daemon.
type ResolutionRequest struct {
	LocalID    string `json:"local_id"`
	Resolution string `json:"resolution"` // "approve" or "deny"
}

// PendingResolutions returns the approvals for agentID that have a
// requested resolution awaiting relay to the local daemon.
func (s *Store) PendingResolutions(ctx context.Context, agentID string) ([]ResolutionRequest, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT local_id, requested_resolution FROM pending_approvals
		 WHERE agent_id = $1 AND status = 'pending' AND requested_resolution IS NOT NULL`,
		agentID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing resolution requests: %w", err)
	}
	defer rows.Close()

	var out []ResolutionRequest
	for rows.Next() {
		var r ResolutionRequest
		if err := rows.Scan(&r.LocalID, &r.Resolution); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AckResolution finalizes a resolution the forwarder confirms it relayed to
// its local daemon (via the daemon's own approve/deny socket command).
func (s *Store) AckResolution(ctx context.Context, agentID, localID, resolution string) error {
	status := PendingApproved
	if resolution == "deny" {
		status = PendingDenied
	} else if resolution != "approve" {
		return fmt.Errorf("invalid resolution %q", resolution)
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE pending_approvals SET status = $1, requested_resolution = NULL, resolved_at = now()
		 WHERE agent_id = $2 AND local_id = $3`,
		status, agentID, localID,
	)
	if err != nil {
		return fmt.Errorf("acking resolution: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

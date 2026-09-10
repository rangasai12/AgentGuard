package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CreateAgent registers a new (pending) agent for tenantID and returns its
// id plus a one-time registration token. The token is handed to whoever is
// about to run agentguard-forwarder on the customer's machine; it's
// redeemed exactly once via RedeemRegistration for a long-lived API key.
func (s *Store) CreateAgent(ctx context.Context, tenantID, name string) (agentID, registrationToken string, err error) {
	agentID = newID("agent")
	registrationToken = newSecret()
	_, err = s.pool.Exec(ctx,
		`INSERT INTO agents (id, tenant_id, name, status, registration_token_hash)
		 VALUES ($1, $2, $3, 'pending', $4)`,
		agentID, tenantID, name, hashSecret(registrationToken),
	)
	if err != nil {
		return "", "", fmt.Errorf("creating agent: %w", err)
	}
	return agentID, registrationToken, nil
}

// RedeemRegistration exchanges a registration token for a long-lived API
// key, activating the agent. It fails if the token has already been
// redeemed (registration_token_hash is cleared on success, so a second
// attempt with the same token finds no matching row).
func (s *Store) RedeemRegistration(ctx context.Context, registrationToken string) (agentID, apiKey string, err error) {
	hash := hashSecret(registrationToken)
	apiKey = newSecret()

	row := s.pool.QueryRow(ctx,
		`UPDATE agents SET status = 'active', api_key_hash = $1, registration_token_hash = NULL
		 WHERE registration_token_hash = $2 AND status = 'pending'
		 RETURNING id`,
		hashSecret(apiKey), hash,
	)
	if err := row.Scan(&agentID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", fmt.Errorf("invalid or already-used registration token")
		}
		return "", "", fmt.Errorf("redeeming registration: %w", err)
	}
	return agentID, apiKey, nil
}

// AgentFromAPIKey resolves an API key to the agent it authenticates as,
// scoping every subsequent controlapi call to that agent's own tenant_id —
// the API key, not any client-supplied field, is what determines tenant
// identity for the whole request.
func (s *Store) AgentFromAPIKey(ctx context.Context, apiKey string) (Agent, error) {
	hash := hashSecret(apiKey)
	var a Agent
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, status, last_seen_at, created_at, last_agent_version, last_policy_hash
		 FROM agents WHERE api_key_hash = $1 AND status = 'active'`,
		hash,
	).Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.LastSeenAt, &a.CreatedAt, &a.LastAgentVersion, &a.LastPolicyHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("looking up agent by api key: %w", err)
	}
	return a, nil
}

// GetAgent returns one agent by id, scoped to tenantID — the one place
// that needs a single fresh row (e.g. its last_agent_version right after
// an ingest just updated it) rather than the whole tenant's list.
func (s *Store) GetAgent(ctx context.Context, tenantID, agentID string) (Agent, error) {
	var a Agent
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, status, last_seen_at, created_at, last_agent_version, last_policy_hash
		 FROM agents WHERE id = $1 AND tenant_id = $2`,
		agentID, tenantID,
	).Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.LastSeenAt, &a.CreatedAt, &a.LastAgentVersion, &a.LastPolicyHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	if err != nil {
		return Agent{}, fmt.Errorf("getting agent: %w", err)
	}
	return a, nil
}

// TouchAgent updates last_seen_at — called on every accepted controlapi
// request from that agent, so the dashboard's fleet view can show
// online/offline based on recency rather than a separate heartbeat command.
func (s *Store) TouchAgent(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agents SET last_seen_at = $1 WHERE id = $2`, time.Now(), agentID)
	return err
}

// ListAgents returns every agent registered under tenantID.
func (s *Store) ListAgents(ctx context.Context, tenantID string) ([]Agent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, name, status, last_seen_at, created_at, last_agent_version, last_policy_hash
		 FROM agents WHERE tenant_id = $1 ORDER BY created_at DESC`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	defer rows.Close()

	var out []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.TenantID, &a.Name, &a.Status, &a.LastSeenAt, &a.CreatedAt, &a.LastAgentVersion, &a.LastPolicyHash); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

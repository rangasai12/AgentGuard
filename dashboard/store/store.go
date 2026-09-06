// Package store is the only part of the dashboard that talks to Postgres.
// Both dashboard/controlapi (agent-facing) and dashboard/webapi
// (browser-facing) go through it rather than writing SQL themselves, so
// tenant-scoping rules live in exactly one place — see the doc comment on
// each method for which caller-supplied tenant_id it trusts (in practice:
// none; every method takes tenantID as an explicit parameter that the
// caller must have already derived from an authenticated identity).
package store

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaFS embed.FS

// Store wraps a Postgres connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres at connString (a standard libpq connection
// string / URL, e.g. "postgres://localhost/agentguard_dashboard_dev").
func Open(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Migrate applies schema.sql. It's idempotent (every statement is
// CREATE ... IF NOT EXISTS), so it's safe to call on every process start
// rather than requiring a separate migration step for Phase 1.
func (s *Store) Migrate(ctx context.Context) error {
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("reading embedded schema.sql: %w", err)
	}
	if _, err := s.pool.Exec(ctx, string(schema)); err != nil {
		return fmt.Errorf("applying schema: %w", err)
	}
	return nil
}

// Close closes the underlying connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// ResetForTests truncates every table. Exported (rather than keeping this
// as a package-internal test helper) so dashboard/server's own tests —
// which exercise the real Store from outside this package — can start each
// test from a clean database too, without either package reaching into the
// other's unexported fields.
func (s *Store) ResetForTests(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE pending_approvals, audit_events, sessions, memberships, agents, users, tenants CASCADE`)
	return err
}

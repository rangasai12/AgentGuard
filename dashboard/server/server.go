// Package server wires the Control API (agent-facing, under /v1/) and the
// Web API (browser-facing, under /api/) into one http.Handler, sharing one
// Store and one Postgres connection pool. Phase 1 runs both from a single
// process/binary (cmd/agentguard-cloud) — see CHANGELOG.md for why this is
// a deliberate simplification, not a shortcut: the two route groups have
// distinct auth (agent API key vs. user session) and could be split into
// separate deployables later without changing either package's code.
package server

import (
	"net/http"

	"agentguard/dashboard/store"
)

// New returns the combined Control API + Web API handler.
func New(s *store.Store) http.Handler {
	mux := http.NewServeMux()
	registerControlAPI(mux, s)
	registerWebAPI(mux, s)
	return mux
}

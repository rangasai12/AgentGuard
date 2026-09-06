package server

import (
	"net/http"
	"strings"

	"agentguard/dashboard/store"
)

// registerControlAPI mounts the agent-facing endpoints every
// agentguard-forwarder instance calls. Every handler except /register
// authenticates via an agent API key (Authorization: Bearer <key>) and
// derives tenant_id/agent_id from that key alone — never from the request
// body — so a forwarder can only ever act as the one agent its key was
// issued for.
func registerControlAPI(mux *http.ServeMux, s *store.Store) {
	mux.HandleFunc("POST /v1/agents/register", handleRegisterAgent(s))
	mux.HandleFunc("POST /v1/events", withAgentAuth(s, handleIngestEvents(s)))
	mux.HandleFunc("POST /v1/pending/sync", withAgentAuth(s, handleSyncPending(s)))
	mux.HandleFunc("GET /v1/pending/resolutions", withAgentAuth(s, handlePendingResolutions(s)))
	mux.HandleFunc("POST /v1/pending/ack", withAgentAuth(s, handleAckResolution(s)))
}

// withAgentAuth resolves the bearer token to an agent, touches its
// last-seen timestamp (so the dashboard's fleet view can show
// online/offline from recency alone), and calls next with that agent.
func withAgentAuth(s *store.Store, next func(http.ResponseWriter, *http.Request, store.Agent)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		apiKey := strings.TrimPrefix(auth, prefix)

		agent, err := s.AgentFromAPIKey(r.Context(), apiKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or inactive agent api key")
			return
		}
		_ = s.TouchAgent(r.Context(), agent.ID) // best-effort; a heartbeat miss shouldn't fail the real request

		next(w, r, agent)
	}
}

func handleRegisterAgent(s *store.Store) http.HandlerFunc {
	type request struct {
		RegistrationToken string `json:"registration_token"`
	}
	type response struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := readJSON(r, &req); err != nil || req.RegistrationToken == "" {
			writeError(w, http.StatusBadRequest, "registration_token is required")
			return
		}
		agentID, apiKey, err := s.RedeemRegistration(r.Context(), req.RegistrationToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, response{AgentID: agentID, APIKey: apiKey})
	}
}

func handleIngestEvents(s *store.Store) func(http.ResponseWriter, *http.Request, store.Agent) {
	type request struct {
		Events []store.IngestedEvent `json:"events"`
	}
	return func(w http.ResponseWriter, r *http.Request, agent store.Agent) {
		var req request
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		if err := s.InsertEvents(r.Context(), agent.TenantID, agent.ID, req.Events); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"accepted": len(req.Events)})
	}
}

func handleSyncPending(s *store.Store) func(http.ResponseWriter, *http.Request, store.Agent) {
	type request struct {
		Pending []store.SyncedPending `json:"pending"`
	}
	return func(w http.ResponseWriter, r *http.Request, agent store.Agent) {
		var req request
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		if err := s.SyncPending(r.Context(), agent.TenantID, agent.ID, req.Pending); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func handlePendingResolutions(s *store.Store) func(http.ResponseWriter, *http.Request, store.Agent) {
	return func(w http.ResponseWriter, r *http.Request, agent store.Agent) {
		resolutions, err := s.PendingResolutions(r.Context(), agent.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string][]store.ResolutionRequest{"resolutions": resolutions})
	}
}

func handleAckResolution(s *store.Store) func(http.ResponseWriter, *http.Request, store.Agent) {
	type request struct {
		LocalID    string `json:"local_id"`
		Resolution string `json:"resolution"`
	}
	return func(w http.ResponseWriter, r *http.Request, agent store.Agent) {
		var req request
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		if err := s.AckResolution(r.Context(), agent.ID, req.LocalID, req.Resolution); err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, "no such pending resolution")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// webapi.go implements the browser-facing endpoints under /api/, session-
// cookie authenticated. Every tenant-scoped handler takes a `tenant_id`
// query parameter naming which of the caller's tenants they want to view
// (the same way GitHub lets you switch organizations) — but withTenantAuth
// below always checks store.MembershipRole before touching any data for
// it, so a client can *ask* for any tenant_id but can only ever see one
// it's actually a member of. That check, not the absence of the parameter,
// is what enforces isolation — see store.TestTenantIsolation for the
// database-level half of this guarantee.
package server

import (
	"net/http"
	"strconv"
	"time"

	"agentguard/dashboard/store"
)

const sessionCookieName = "ag_session"
const sessionTTL = 7 * 24 * time.Hour

func registerWebAPI(mux *http.ServeMux, s *store.Store) {
	mux.HandleFunc("POST /api/signup", handleSignUp(s))
	mux.HandleFunc("POST /api/auth/login", handleLogin(s))
	mux.HandleFunc("POST /api/auth/logout", handleLogout(s))
	mux.HandleFunc("GET /api/me", withUserAuth(s, handleMe(s)))

	mux.HandleFunc("POST /api/agents", withTenantAuth(s, store.RoleAdmin, handleCreateAgent(s)))
	mux.HandleFunc("GET /api/agents", withTenantAuth(s, store.RoleViewer, handleListAgents(s)))
	mux.HandleFunc("GET /api/events", withTenantAuth(s, store.RoleViewer, handleListEvents(s)))
	mux.HandleFunc("GET /api/metrics", withTenantAuth(s, store.RoleViewer, handleMetrics(s)))
	mux.HandleFunc("GET /api/tools", withTenantAuth(s, store.RoleViewer, handleListTools(s)))
	mux.HandleFunc("PUT /api/tools/verb", withTenantAuth(s, store.RoleAdmin, handleSetToolVerb(s)))
	mux.HandleFunc("GET /api/pending", withTenantAuth(s, store.RoleViewer, handleListPending(s)))
	mux.HandleFunc("POST /api/pending/resolve", withTenantAuth(s, store.RoleAdmin, handleResolvePending(s)))
	mux.HandleFunc("GET /api/anomalies", withTenantAuth(s, store.RoleViewer, handleListAnomalies(s)))
	mux.HandleFunc("POST /api/anomalies/ack", withTenantAuth(s, store.RoleAdmin, handleAckAnomaly(s)))
	mux.HandleFunc("GET /api/settings", withTenantAuth(s, store.RoleViewer, handleGetSettings(s)))
	mux.HandleFunc("PUT /api/settings", withTenantAuth(s, store.RoleAdmin, handlePutSettings(s)))
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// withUserAuth resolves the session cookie to a user and calls next with
// it, or 401s if there's no valid session.
func withUserAuth(s *store.Store, next func(http.ResponseWriter, *http.Request, store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		user, err := s.UserFromSession(r.Context(), cookie.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session expired or invalid")
			return
		}
		next(w, r, user)
	}
}

// withTenantAuth builds on withUserAuth: it additionally requires a
// `tenant_id` query parameter and verifies the caller has at least
// minRole in that tenant before calling next.
func withTenantAuth(s *store.Store, minRole store.Role, next func(http.ResponseWriter, *http.Request, store.User, string)) http.HandlerFunc {
	return withUserAuth(s, func(w http.ResponseWriter, r *http.Request, user store.User) {
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			writeError(w, http.StatusBadRequest, "tenant_id is required")
			return
		}
		role, err := s.MembershipRole(r.Context(), user.ID, tenantID)
		if err != nil {
			writeError(w, http.StatusForbidden, "not a member of this tenant")
			return
		}
		if minRole == store.RoleAdmin && role != store.RoleAdmin {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r, user, tenantID)
	})
}

func handleSignUp(s *store.Store) http.HandlerFunc {
	type request struct {
		CompanyName string `json:"company_name"`
		Email       string `json:"email"`
		Password    string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := readJSON(r, &req); err != nil || req.CompanyName == "" || req.Email == "" || len(req.Password) < 8 {
			writeError(w, http.StatusBadRequest, "company_name, email, and a password of at least 8 characters are required")
			return
		}
		userID, tenantID, err := s.SignUp(r.Context(), req.CompanyName, req.Email, req.Password)
		if err != nil {
			if err == store.ErrEmailTaken {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		token, err := s.CreateSession(r.Context(), userID, sessionTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		setSessionCookie(w, r, token)
		writeJSON(w, http.StatusCreated, map[string]string{"user_id": userID, "tenant_id": tenantID})
	}
}

func handleLogin(s *store.Store) http.HandlerFunc {
	type request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		userID, err := s.VerifyLogin(r.Context(), req.Email, req.Password)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		token, err := s.CreateSession(r.Context(), userID, sessionTTL)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		setSessionCookie(w, r, token)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func handleLogout(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			_ = s.DeleteSession(r.Context(), cookie.Value)
		}
		clearSessionCookie(w, r)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func handleMe(s *store.Store) func(http.ResponseWriter, *http.Request, store.User) {
	return func(w http.ResponseWriter, r *http.Request, user store.User) {
		memberships, err := s.Memberships(r.Context(), user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user":        user,
			"memberships": memberships,
		})
	}
}

func handleCreateAgent(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	type request struct {
		Name string `json:"name"`
	}
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		var req request
		if err := readJSON(r, &req); err != nil || req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		agentID, regToken, err := s.CreateAgent(r.Context(), tenantID, req.Name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{
			"agent_id":           agentID,
			"registration_token": regToken,
		})
	}
}

func handleListAgents(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		agents, err := s.ListAgents(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string][]store.Agent{"agents": agents})
	}
}

func handleListEvents(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		filter := store.EventFilter{
			AgentID:          r.URL.Query().Get("agent_id"),
			Actor:            r.URL.Query().Get("actor"),
			ActionType:       r.URL.Query().Get("action_type"),
			Decision:         r.URL.Query().Get("decision"),
			ResourceContains: r.URL.Query().Get("resource_contains"),
			RunID:            r.URL.Query().Get("run_id"),
			AgentVersion:     r.URL.Query().Get("agent_version"),
			Outcome:          r.URL.Query().Get("outcome"),
		}
		since, err := parseTimeParam(r, "since")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since: "+err.Error())
			return
		}
		filter.Since = since
		until, err := parseTimeParam(r, "until")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid until: "+err.Error())
			return
		}
		filter.Until = until
		if limit := r.URL.Query().Get("limit"); limit != "" {
			if n, err := strconv.Atoi(limit); err == nil {
				filter.Limit = n
			}
		}

		events, err := s.QueryEvents(r.Context(), tenantID, filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string][]store.AuditEvent{"events": events})
	}
}

func handleMetrics(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		since, sErr := parseTimeParam(r, "since")
		if sErr != nil {
			writeError(w, http.StatusBadRequest, "invalid since: "+sErr.Error())
			return
		}
		until, uErr := parseTimeParam(r, "until")
		if uErr != nil {
			writeError(w, http.StatusBadRequest, "invalid until: "+uErr.Error())
			return
		}
		filter := store.MetricsFilter{
			Since:        since,
			Until:        until,
			AgentID:      r.URL.Query().Get("agent_id"),
			AgentVersion: r.URL.Query().Get("agent_version"),
			RunID:        r.URL.Query().Get("run_id"),
		}
		metrics, err := s.Metrics(r.Context(), tenantID, filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, metrics)
	}
}

// handleListTools serves the tenant's tool catalog: every named tool its
// agents have called, with the description the SDK/proxy sent.
func handleListTools(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		tools, err := s.ListToolCatalog(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if tools == nil {
			tools = []store.ToolCatalogEntry{}
		}
		writeJSON(w, http.StatusOK, map[string][]store.ToolCatalogEntry{"tools": tools})
	}
}

// handleSetToolVerb lets an admin manually classify (or correct) one
// tool's verb; the classifier never overwrites a row set this way (see
// store.SetToolVerb / the classifier's verb_source == "" selection).
func handleSetToolVerb(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	type request struct {
		ActionType string `json:"action_type"`
		Resource   string `json:"resource"`
		Verb       string `json:"verb"`
	}
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		var req request
		if err := readJSON(r, &req); err != nil || req.ActionType == "" || req.Resource == "" {
			writeError(w, http.StatusBadRequest, "action_type and resource are required")
			return
		}
		if !validVerbs[req.Verb] {
			writeError(w, http.StatusBadRequest, "verb must be one of read, write, delete, permission, unknown")
			return
		}
		err := s.SetToolVerb(r.Context(), tenantID, req.ActionType, req.Resource, req.Verb, "user override", nil, "user")
		if err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, "no such tool in the catalog")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleListAnomalies serves the tenant's detected anomalies, most recent
// first, optionally scoped to one agent or unacknowledged-only.
func handleListAnomalies(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		since, err := parseTimeParam(r, "since")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since: "+err.Error())
			return
		}
		filter := store.AnomalyFilter{
			AgentID:        r.URL.Query().Get("agent_id"),
			Unacknowledged: r.URL.Query().Get("unacknowledged") == "true",
			Since:          since,
		}
		anomalies, err := s.ListAnomalies(r.Context(), tenantID, filter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if anomalies == nil {
			anomalies = []store.Anomaly{}
		}
		writeJSON(w, http.StatusOK, map[string][]store.Anomaly{"anomalies": anomalies})
	}
}

func handleAckAnomaly(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	type request struct {
		AnomalyID string `json:"anomaly_id"`
	}
	return func(w http.ResponseWriter, r *http.Request, user store.User, tenantID string) {
		var req request
		if err := readJSON(r, &req); err != nil || req.AnomalyID == "" {
			writeError(w, http.StatusBadRequest, "anomaly_id is required")
			return
		}
		if err := s.AckAnomaly(r.Context(), tenantID, req.AnomalyID, user.ID); err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, "no such anomaly")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// handleGetSettings serves the tenant's anomaly-detection thresholds
// (store.DefaultTenantSettings() if it has never saved any).
func handleGetSettings(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		settings, err := s.GetTenantSettings(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, settings)
	}
}

func handlePutSettings(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		var settings store.TenantSettings
		if err := readJSON(r, &settings); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		settings.TenantID = tenantID
		if err := settings.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.PutTenantSettings(r.Context(), settings); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func handleListPending(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	return func(w http.ResponseWriter, r *http.Request, _ store.User, tenantID string) {
		pending, err := s.ListPending(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string][]store.PendingApproval{"pending": pending})
	}
}

func handleResolvePending(s *store.Store) func(http.ResponseWriter, *http.Request, store.User, string) {
	type request struct {
		PendingID  string `json:"pending_id"`
		Resolution string `json:"resolution"`
	}
	return func(w http.ResponseWriter, r *http.Request, user store.User, tenantID string) {
		var req request
		if err := readJSON(r, &req); err != nil || req.PendingID == "" {
			writeError(w, http.StatusBadRequest, "pending_id and resolution are required")
			return
		}
		if err := s.RequestResolution(r.Context(), tenantID, req.PendingID, user.ID, req.Resolution); err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, "no such pending approval")
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

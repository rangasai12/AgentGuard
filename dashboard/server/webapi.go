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
	mux.HandleFunc("GET /api/pending", withTenantAuth(s, store.RoleViewer, handleListPending(s)))
	mux.HandleFunc("POST /api/pending/resolve", withTenantAuth(s, store.RoleAdmin, handleResolvePending(s)))
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
		metrics, err := s.Metrics(r.Context(), tenantID, since, until)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, metrics)
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

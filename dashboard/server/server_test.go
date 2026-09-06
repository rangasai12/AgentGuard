package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"agentguard/dashboard/store"
)

// testServer opens the real local Postgres test database (same one
// dashboard/store's own tests use) and returns a ready-to-use handler with
// every table truncated first, so HTTP-level tests exercise the real store
// and real SQL rather than a mock.
func testServer(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	dsn := os.Getenv("AGENTGUARD_DASHBOARD_TEST_DB")
	if dsn == "" {
		dsn = "postgres:///agentguard_dashboard_dev"
	}
	ctx := context.Background()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Skipf("no local postgres available at %q: %v", dsn, err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	if err := s.ResetForTests(ctx); err != nil {
		t.Fatalf("resetting database: %v", err)
	}
	t.Cleanup(s.Close)
	return New(s), s
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encoding request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decoding response body %q: %v", rec.Body.String(), err)
	}
	return v
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func TestSignupLoginAndMe(t *testing.T) {
	h, _ := testServer(t)

	rec := doJSON(t, h, "POST", "/api/signup", map[string]string{
		"company_name": "Acme Corp", "email": "admin@acme.example", "password": "hunter2hunter2",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signup: status %d body %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieFrom(rec)
	if cookie == nil {
		t.Fatal("signup did not set a session cookie")
	}

	me := doJSON(t, h, "GET", "/api/me", nil, []*http.Cookie{cookie})
	if me.Code != http.StatusOK {
		t.Fatalf("me: status %d body %s", me.Code, me.Body.String())
	}
	body := decodeBody[map[string]any](t, me)
	if body["user"].(map[string]any)["email"] != "admin@acme.example" {
		t.Fatalf("me returned unexpected user: %v", body)
	}

	unauth := doJSON(t, h, "GET", "/api/me", nil, nil)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a session cookie, got %d", unauth.Code)
	}

	loginRec := doJSON(t, h, "POST", "/api/auth/login", map[string]string{
		"email": "admin@acme.example", "password": "hunter2hunter2",
	}, nil)
	if loginRec.Code != http.StatusOK || sessionCookieFrom(loginRec) == nil {
		t.Fatalf("login: status %d body %s", loginRec.Code, loginRec.Body.String())
	}

	badLogin := doJSON(t, h, "POST", "/api/auth/login", map[string]string{
		"email": "admin@acme.example", "password": "wrong",
	}, nil)
	if badLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad password, got %d", badLogin.Code)
	}
}

func TestAgentRegistrationAndEventIngestionEndToEnd(t *testing.T) {
	h, _ := testServer(t)

	signup := doJSON(t, h, "POST", "/api/signup", map[string]string{
		"company_name": "Acme", "email": "u@acme.example", "password": "password123",
	}, nil)
	cookie := sessionCookieFrom(signup)
	tenantID := decodeBody[map[string]string](t, signup)["tenant_id"]

	createAgent := doJSON(t, h, "POST", "/api/agents?tenant_id="+tenantID, map[string]string{"name": "prod-agent"}, []*http.Cookie{cookie})
	if createAgent.Code != http.StatusCreated {
		t.Fatalf("create agent: status %d body %s", createAgent.Code, createAgent.Body.String())
	}
	agentResp := decodeBody[map[string]string](t, createAgent)
	regToken := agentResp["registration_token"]

	register := doJSON(t, h, "POST", "/v1/agents/register", map[string]string{"registration_token": regToken}, nil)
	if register.Code != http.StatusOK {
		t.Fatalf("register: status %d body %s", register.Code, register.Body.String())
	}
	apiKey := decodeBody[map[string]string](t, register)["api_key"]

	// unauthenticated ingestion is rejected
	noAuth := doJSON(t, h, "POST", "/v1/events", map[string]any{"events": []any{}}, nil)
	if noAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated ingestion, got %d", noAuth.Code)
	}

	req := httptest.NewRequest("POST", "/v1/events", bytes.NewBufferString(`{"events":[
		{"timestamp":"2026-09-05T00:00:00Z","action_type":"fs_write","resource":"/prod/x","decision":"deny","matched_rule":"no-prod-write"}
	]}`))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: status %d body %s", rec.Code, rec.Body.String())
	}

	events := doJSON(t, h, "GET", "/api/events?tenant_id="+tenantID, nil, []*http.Cookie{cookie})
	if events.Code != http.StatusOK {
		t.Fatalf("list events: status %d body %s", events.Code, events.Body.String())
	}
	evBody := decodeBody[map[string][]map[string]any](t, events)
	if len(evBody["events"]) != 1 || evBody["events"][0]["resource"] != "/prod/x" {
		t.Fatalf("unexpected events response: %v", evBody)
	}
}

func TestWebAPIRejectsAccessToForeignTenant(t *testing.T) {
	h, _ := testServer(t)

	signupA := doJSON(t, h, "POST", "/api/signup", map[string]string{
		"company_name": "Company A", "email": "a@a.example", "password": "passwordA1",
	}, nil)
	cookieA := sessionCookieFrom(signupA)

	signupB := doJSON(t, h, "POST", "/api/signup", map[string]string{
		"company_name": "Company B", "email": "b@b.example", "password": "passwordB1",
	}, nil)
	tenantB := decodeBody[map[string]string](t, signupB)["tenant_id"]

	// Company A's authenticated session tries to read Company B's events —
	// must be rejected regardless of what tenant_id it asks for.
	rec := doJSON(t, h, "GET", "/api/events?tenant_id="+tenantB, nil, []*http.Cookie{cookieA})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 reading a foreign tenant's events, got %d body %s", rec.Code, rec.Body.String())
	}

	rec2 := doJSON(t, h, "POST", "/api/agents?tenant_id="+tenantB, map[string]string{"name": "x"}, []*http.Cookie{cookieA})
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 creating an agent under a foreign tenant, got %d body %s", rec2.Code, rec2.Body.String())
	}
}

func TestPendingApprovalResolveEndToEnd(t *testing.T) {
	h, s := testServer(t)
	ctx := context.Background()

	signup := doJSON(t, h, "POST", "/api/signup", map[string]string{
		"company_name": "Acme", "email": "u@acme.example", "password": "password123",
	}, nil)
	cookie := sessionCookieFrom(signup)
	tenantID := decodeBody[map[string]string](t, signup)["tenant_id"]

	agentID, regToken, err := s.CreateAgent(ctx, tenantID, "agent-1")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	_, apiKey, err := s.RedeemRegistration(ctx, regToken)
	if err != nil {
		t.Fatalf("RedeemRegistration: %v", err)
	}

	syncReq := httptest.NewRequest("POST", "/v1/pending/sync", bytes.NewBufferString(`{"pending":[
		{"local_id":"abc123","action_type":"shell","resource":"rm -rf x","matched_rule":"destructive-delete"}
	]}`))
	syncReq.Header.Set("Authorization", "Bearer "+apiKey)
	syncRec := httptest.NewRecorder()
	h.ServeHTTP(syncRec, syncReq)
	if syncRec.Code != http.StatusOK {
		t.Fatalf("sync: status %d body %s", syncRec.Code, syncRec.Body.String())
	}

	list := doJSON(t, h, "GET", "/api/pending?tenant_id="+tenantID, nil, []*http.Cookie{cookie})
	pendingBody := decodeBody[map[string][]map[string]any](t, list)
	if len(pendingBody["pending"]) != 1 {
		t.Fatalf("expected 1 pending approval, got %v", pendingBody)
	}
	rowID := pendingBody["pending"][0]["id"].(string)

	resolve := doJSON(t, h, "POST", "/api/pending/resolve?tenant_id="+tenantID,
		map[string]string{"pending_id": rowID, "resolution": "approve"}, []*http.Cookie{cookie})
	if resolve.Code != http.StatusOK {
		t.Fatalf("resolve: status %d body %s", resolve.Code, resolve.Body.String())
	}

	req := httptest.NewRequest("GET", "/v1/pending/resolutions", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resBody := decodeBody[map[string][]map[string]any](t, rec)
	if len(resBody["resolutions"]) != 1 || resBody["resolutions"][0]["local_id"] != "abc123" || resBody["resolutions"][0]["resolution"] != "approve" {
		t.Fatalf("unexpected resolutions: %v", resBody)
	}

	ackReq := httptest.NewRequest("POST", "/v1/pending/ack", bytes.NewBufferString(`{"local_id":"abc123","resolution":"approve"}`))
	ackReq.Header.Set("Authorization", "Bearer "+apiKey)
	ackRec := httptest.NewRecorder()
	h.ServeHTTP(ackRec, ackReq)
	if ackRec.Code != http.StatusOK {
		t.Fatalf("ack: status %d body %s", ackRec.Code, ackRec.Body.String())
	}

	finalList := doJSON(t, h, "GET", "/api/pending?tenant_id="+tenantID, nil, []*http.Cookie{cookie})
	finalBody := decodeBody[map[string][]map[string]any](t, finalList)
	if len(finalBody["pending"]) != 0 {
		t.Fatalf("expected no pending approvals after ack, got %v", finalBody)
	}

	_ = agentID
}

package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// testStore opens a real local Postgres database and truncates every table
// so tests don't interfere with each other — no mocking of the database
// layer itself, consistent with this repo's practice of testing against
// real daemons/binaries rather than fakes wherever practical.
//
// AGENTGUARD_DASHBOARD_TEST_DB defaults to a local dev database created via
// `createdb agentguard_dashboard_dev && psql -d agentguard_dashboard_dev -f
// dashboard/store/schema.sql` (see CHANGELOG.md).
//
// IMPORTANT: dashboard/store and dashboard/server both point at this same
// database by default, and each test truncates every table up front. `go
// test ./...` runs different packages' tests concurrently, so running both
// packages together needs `go test -p 1 ./dashboard/...` — otherwise one
// package's truncation can race another's in-flight test and produce
// flaky, spurious failures that have nothing to do with the code under
// test. This is a property of sharing one real external database across
// packages, not a bug in either test suite.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("AGENTGUARD_DASHBOARD_TEST_DB")
	if dsn == "" {
		dsn = "postgres:///agentguard_dashboard_dev"
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
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
	return s
}

func TestSignUpAndLogin(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	userID, tenantID, err := s.SignUp(ctx, "Acme Corp", "admin@acme.example", "hunter2hunter2")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	if _, _, err := s.SignUp(ctx, "Acme Corp Duplicate", "admin@acme.example", "whatever"); err != ErrEmailTaken {
		t.Fatalf("expected ErrEmailTaken for duplicate email, got %v", err)
	}

	gotUserID, err := s.VerifyLogin(ctx, "admin@acme.example", "hunter2hunter2")
	if err != nil || gotUserID != userID {
		t.Fatalf("VerifyLogin: got (%q, %v), want (%q, nil)", gotUserID, err, userID)
	}

	if _, err := s.VerifyLogin(ctx, "admin@acme.example", "wrongpassword"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for wrong password, got %v", err)
	}

	role, err := s.MembershipRole(ctx, userID, tenantID)
	if err != nil || role != RoleAdmin {
		t.Fatalf("MembershipRole: got (%q, %v), want (admin, nil)", role, err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	userID, _, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	token, err := s.CreateSession(ctx, userID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	u, err := s.UserFromSession(ctx, token)
	if err != nil || u.ID != userID {
		t.Fatalf("UserFromSession: got (%+v, %v), want id=%q", u, err, userID)
	}

	if err := s.DeleteSession(ctx, token); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.UserFromSession(ctx, token); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after logout, got %v", err)
	}

	expiredToken, err := s.CreateSession(ctx, userID, -time.Hour)
	if err != nil {
		t.Fatalf("CreateSession (expired): %v", err)
	}
	if _, err := s.UserFromSession(ctx, expiredToken); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound for an already-expired session, got %v", err)
	}
}

func TestAgentRegistrationFlow(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	agentID, regToken, err := s.CreateAgent(ctx, tenantID, "prod-coding-agent")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	if _, err := s.AgentFromAPIKey(ctx, "not-yet-an-api-key"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound before redemption, got %v", err)
	}

	redeemedID, apiKey, err := s.RedeemRegistration(ctx, regToken)
	if err != nil {
		t.Fatalf("RedeemRegistration: %v", err)
	}
	if redeemedID != agentID {
		t.Fatalf("RedeemRegistration returned agent %q, want %q", redeemedID, agentID)
	}

	if _, _, err := s.RedeemRegistration(ctx, regToken); err == nil {
		t.Fatal("expected RedeemRegistration to fail on reuse of an already-redeemed token")
	}

	agent, err := s.AgentFromAPIKey(ctx, apiKey)
	if err != nil {
		t.Fatalf("AgentFromAPIKey: %v", err)
	}
	if agent.ID != agentID || agent.TenantID != tenantID || agent.Status != AgentActive {
		t.Fatalf("AgentFromAPIKey returned %+v, want id=%q tenant=%q status=active", agent, agentID, tenantID)
	}
}

// TestTenantIsolation is the single most important test in this package:
// it proves one tenant's events, pending approvals, and agents are never
// visible through another tenant's queries, no matter what.
func TestTenantIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, tenantA, err := s.SignUp(ctx, "Company A", "a@a.example", "passwordA1")
	if err != nil {
		t.Fatalf("SignUp A: %v", err)
	}
	_, tenantB, err := s.SignUp(ctx, "Company B", "b@b.example", "passwordB1")
	if err != nil {
		t.Fatalf("SignUp B: %v", err)
	}

	agentAID, regTokenA, err := s.CreateAgent(ctx, tenantA, "agent-a")
	if err != nil {
		t.Fatalf("CreateAgent A: %v", err)
	}
	_, apiKeyA, err := s.RedeemRegistration(ctx, regTokenA)
	if err != nil {
		t.Fatalf("RedeemRegistration A: %v", err)
	}

	agentBID, regTokenB, err := s.CreateAgent(ctx, tenantB, "agent-b")
	if err != nil {
		t.Fatalf("CreateAgent B: %v", err)
	}
	_, apiKeyB, err := s.RedeemRegistration(ctx, regTokenB)
	if err != nil {
		t.Fatalf("RedeemRegistration B: %v", err)
	}

	if err := s.InsertEvents(ctx, tenantA, agentAID, []IngestedEvent{
		{Timestamp: time.Now(), ActionType: "fs_write", Resource: "/tenant-a-secret", Decision: "deny", MatchedRule: "r1"},
	}); err != nil {
		t.Fatalf("InsertEvents A: %v", err)
	}
	if err := s.InsertEvents(ctx, tenantB, agentBID, []IngestedEvent{
		{Timestamp: time.Now(), ActionType: "fs_write", Resource: "/tenant-b-secret", Decision: "deny", MatchedRule: "r1"},
	}); err != nil {
		t.Fatalf("InsertEvents B: %v", err)
	}

	eventsA, err := s.QueryEvents(ctx, tenantA, EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents A: %v", err)
	}
	if len(eventsA) != 1 || eventsA[0].Resource != "/tenant-a-secret" {
		t.Fatalf("tenant A query returned %+v, want exactly its own /tenant-a-secret event", eventsA)
	}

	eventsB, err := s.QueryEvents(ctx, tenantB, EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents B: %v", err)
	}
	if len(eventsB) != 1 || eventsB[0].Resource != "/tenant-b-secret" {
		t.Fatalf("tenant B query returned %+v, want exactly its own /tenant-b-secret event", eventsB)
	}

	agentFromA, err := s.AgentFromAPIKey(ctx, apiKeyA)
	if err != nil || agentFromA.TenantID != tenantA {
		t.Fatalf("agent A's API key resolved to tenant %q, want %q (err=%v)", agentFromA.TenantID, tenantA, err)
	}
	agentFromB, err := s.AgentFromAPIKey(ctx, apiKeyB)
	if err != nil || agentFromB.TenantID != tenantB {
		t.Fatalf("agent B's API key resolved to tenant %q, want %q (err=%v)", agentFromB.TenantID, tenantB, err)
	}

	agentsA, err := s.ListAgents(ctx, tenantA)
	if err != nil || len(agentsA) != 1 || agentsA[0].ID != agentAID {
		t.Fatalf("ListAgents for tenant A returned %+v (err=%v), want exactly agent-a", agentsA, err)
	}

	// Pending-approval isolation: sync one pending approval per tenant, then
	// confirm each tenant's ListPending only ever sees its own.
	if err := s.SyncPending(ctx, tenantA, agentAID, []SyncedPending{
		{LocalID: "deadbeef", ActionType: "shell", Resource: "rm -rf /", MatchedRule: "danger"},
	}); err != nil {
		t.Fatalf("SyncPending A: %v", err)
	}
	if err := s.SyncPending(ctx, tenantB, agentBID, []SyncedPending{
		{LocalID: "deadbeef", ActionType: "shell", Resource: "rm -rf /tmp", MatchedRule: "danger"},
	}); err != nil {
		t.Fatalf("SyncPending B: %v", err)
	}

	pendingA, err := s.ListPending(ctx, tenantA)
	if err != nil || len(pendingA) != 1 || pendingA[0].Resource != "rm -rf /" {
		t.Fatalf("ListPending A returned %+v (err=%v), want exactly its own rm -rf / entry", pendingA, err)
	}
	pendingB, err := s.ListPending(ctx, tenantB)
	if err != nil || len(pendingB) != 1 || pendingB[0].Resource != "rm -rf /tmp" {
		t.Fatalf("ListPending B returned %+v (err=%v), want exactly its own rm -rf /tmp entry", pendingB, err)
	}

	// A request to resolve tenant B's pending approval using tenant A's id
	// must fail — this is the exact bug shape that would leak cross-tenant
	// control if the WHERE clause ever dropped its tenant_id check.
	if err := s.RequestResolution(ctx, tenantA, pendingB[0].ID, "someone", "approve"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound resolving tenant B's approval under tenant A, got %v", err)
	}
}

func TestPendingApprovalFullRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	userID, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	agentID, regToken, err := s.CreateAgent(ctx, tenantID, "agent-1")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if _, _, err := s.RedeemRegistration(ctx, regToken); err != nil {
		t.Fatalf("RedeemRegistration: %v", err)
	}

	if err := s.SyncPending(ctx, tenantID, agentID, []SyncedPending{
		{LocalID: "abc123", ActionType: "shell", Resource: "rm -rf workspace/tmp", MatchedRule: "destructive-delete"},
	}); err != nil {
		t.Fatalf("SyncPending: %v", err)
	}

	pending, err := s.ListPending(ctx, tenantID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPending: got %+v, err=%v", pending, err)
	}
	rowID := pending[0].ID

	// A browser click requests approval...
	if err := s.RequestResolution(ctx, tenantID, rowID, userID, "approve"); err != nil {
		t.Fatalf("RequestResolution: %v", err)
	}

	// ...it's still 'pending' (not yet relayed to the local daemon)...
	stillPending, err := s.ListPending(ctx, tenantID)
	if err != nil || len(stillPending) != 1 || stillPending[0].RequestedResolution != "approve" {
		t.Fatalf("expected still-pending with requested_resolution=approve, got %+v (err=%v)", stillPending, err)
	}

	// ...the forwarder polls for resolutions to relay...
	resolutions, err := s.PendingResolutions(ctx, agentID)
	if err != nil || len(resolutions) != 1 || resolutions[0].LocalID != "abc123" || resolutions[0].Resolution != "approve" {
		t.Fatalf("PendingResolutions: got %+v, err=%v", resolutions, err)
	}

	// ...relays it to the local daemon (simulated), then acks...
	if err := s.AckResolution(ctx, agentID, "abc123", "approve"); err != nil {
		t.Fatalf("AckResolution: %v", err)
	}

	// ...and it's now gone from the pending list.
	final, err := s.ListPending(ctx, tenantID)
	if err != nil || len(final) != 0 {
		t.Fatalf("expected no pending approvals after ack, got %+v (err=%v)", final, err)
	}

	// A second poll for resolutions finds nothing left to relay.
	resolutionsAfter, err := s.PendingResolutions(ctx, agentID)
	if err != nil || len(resolutionsAfter) != 0 {
		t.Fatalf("expected no resolutions left to relay, got %+v (err=%v)", resolutionsAfter, err)
	}
}

func TestSyncPendingReconcilesResolvedElsewhere(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	agentID, regToken, err := s.CreateAgent(ctx, tenantID, "agent-1")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if _, _, err := s.RedeemRegistration(ctx, regToken); err != nil {
		t.Fatalf("RedeemRegistration: %v", err)
	}

	if err := s.SyncPending(ctx, tenantID, agentID, []SyncedPending{
		{LocalID: "willresolvelocally", ActionType: "shell", Resource: "rm -rf x"},
	}); err != nil {
		t.Fatalf("SyncPending (first): %v", err)
	}

	// Simulate `agentctl approve` happening directly on the customer's
	// machine, invisible to the dashboard except via the next sync no
	// longer reporting that local_id as pending.
	if err := s.SyncPending(ctx, tenantID, agentID, []SyncedPending{}); err != nil {
		t.Fatalf("SyncPending (second, empty): %v", err)
	}

	pending, err := s.ListPending(ctx, tenantID)
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected the entry to no longer be pending after it dropped out of a sync, got %+v (err=%v)", pending, err)
	}
}

func TestMetrics(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	agentID, regToken, err := s.CreateAgent(ctx, tenantID, "agent-1")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if _, _, err := s.RedeemRegistration(ctx, regToken); err != nil {
		t.Fatalf("RedeemRegistration: %v", err)
	}

	events := []IngestedEvent{
		{Timestamp: time.Now(), ActionType: "fs_write", Resource: "/workspace/a", Decision: "allow", MatchedRule: "r1"},
		{Timestamp: time.Now(), ActionType: "fs_write", Resource: "/prod/a", Decision: "deny", MatchedRule: "no-prod-write"},
		{Timestamp: time.Now(), ActionType: "fs_write", Resource: "/prod/b", Decision: "deny", MatchedRule: "no-prod-write"},
		{Timestamp: time.Now(), ActionType: "shell", Resource: "rm -rf x", Decision: "require_approval", MatchedRule: "destructive-delete"},
	}
	if err := s.InsertEvents(ctx, tenantID, agentID, events); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	m, err := s.Metrics(ctx, tenantID, nil, nil)
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if m.AllowCount != 1 || m.DenyCount != 2 || m.RequireApprovalCount != 1 {
		t.Fatalf("Metrics counts = %+v, want allow=1 deny=2 require_approval=1", m)
	}
	if len(m.TopDeniedRules) != 1 || m.TopDeniedRules[0].Value != "no-prod-write" || m.TopDeniedRules[0].Count != 2 {
		t.Fatalf("TopDeniedRules = %+v, want [{no-prod-write 2}]", m.TopDeniedRules)
	}
}

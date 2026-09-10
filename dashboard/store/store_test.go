package store

import (
	"context"
	"encoding/json"
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

	// Both tenants' daemons happen to mint the same event id (ids are only
	// unique within one daemon), which is exactly the shape an outcome
	// patch must never be allowed to cross tenants on.
	const sharedEventID = "0011223344556677"
	if err := s.InsertEvents(ctx, tenantA, agentAID, []IngestedEvent{
		{Timestamp: time.Now(), ActionType: "fs_write", Resource: "/tenant-a-secret", Decision: "deny", MatchedRule: "r1", EventID: sharedEventID},
	}); err != nil {
		t.Fatalf("InsertEvents A: %v", err)
	}
	if err := s.InsertEvents(ctx, tenantB, agentBID, []IngestedEvent{
		{Timestamp: time.Now(), ActionType: "fs_write", Resource: "/tenant-b-secret", Decision: "deny", MatchedRule: "r1", EventID: sharedEventID},
	}); err != nil {
		t.Fatalf("InsertEvents B: %v", err)
	}
	// Tenant A reports an outcome for "its" event id: only A's row may change.
	if err := s.InsertEvents(ctx, tenantA, agentAID, []IngestedEvent{
		{Timestamp: time.Now(), Kind: IngestKindOutcome, EventID: sharedEventID, Outcome: &EventOutcome{Status: "success", ExecMS: 1, Output: "a-only"}},
	}); err != nil {
		t.Fatalf("InsertEvents A (outcome): %v", err)
	}

	eventsA, err := s.QueryEvents(ctx, tenantA, EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents A: %v", err)
	}
	if len(eventsA) != 1 || eventsA[0].Resource != "/tenant-a-secret" {
		t.Fatalf("tenant A query returned %+v, want exactly its own /tenant-a-secret event", eventsA)
	}
	if eventsA[0].Outcome == nil || eventsA[0].Outcome.Output != "a-only" {
		t.Fatalf("tenant A's outcome patch must have merged into A's row, got %+v", eventsA[0].Outcome)
	}

	eventsB, err := s.QueryEvents(ctx, tenantB, EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents B: %v", err)
	}
	if len(eventsB) != 1 || eventsB[0].Resource != "/tenant-b-secret" {
		t.Fatalf("tenant B query returned %+v, want exactly its own /tenant-b-secret event", eventsB)
	}
	if eventsB[0].Outcome != nil {
		t.Fatalf("tenant A's outcome patch leaked into tenant B's row with the same event id: %+v", eventsB[0].Outcome)
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

	// Tool catalog and metrics are tenant-scoped: the same tool name in two
	// tenants is two rows, and each tenant sees only its own.
	if err := s.InsertEvents(ctx, tenantB, agentBID, []IngestedEvent{
		{Timestamp: time.Now(), ActionType: "function", Resource: "shared_tool", Decision: "allow", MatchedRule: "r",
			Action: json.RawMessage(`{"type":"function","name":"shared_tool","description":"B's version"}`)},
	}); err != nil {
		t.Fatalf("InsertEvents B tool: %v", err)
	}
	toolsA, err := s.ListToolCatalog(ctx, tenantA)
	if err != nil || len(toolsA) != 0 {
		t.Fatalf("tenant A must not see tenant B's tools, got %+v (err %v)", toolsA, err)
	}
	mA, err := s.Metrics(ctx, tenantA, MetricsFilter{AgentID: agentBID})
	if err != nil || mA.TotalCount != 0 || len(mA.Versions) != 0 {
		t.Fatalf("tenant A asking for tenant B's agent must see nothing, got %+v (err %v)", mA, err)
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

	// Tenant settings and anomalies are tenant-scoped too.
	if err := s.PutTenantSettings(ctx, TenantSettings{
		TenantID: tenantA, WindowMinutes: 15, BaselineHours: 24, MinBaselineEvents: 50,
		VolumeRatio: 3, ShareShift: 0.3, DenyRateRatio: 3, ErrorRateRatio: 3, LatencyRatio: 3, BulkRatio: 5, MinEvents: 5,
	}); err != nil {
		t.Fatalf("PutTenantSettings A: %v", err)
	}
	settingsB, err := s.GetTenantSettings(ctx, tenantB)
	if err != nil {
		t.Fatalf("GetTenantSettings B: %v", err)
	}
	if settingsB.WindowMinutes != DefaultTenantSettings(tenantB).WindowMinutes {
		t.Fatalf("tenant B must see its own defaults, not tenant A's saved settings, got %+v", settingsB)
	}

	now := time.Now()
	if err := s.UpsertAnomaly(ctx, Anomaly{
		TenantID: tenantA, AgentID: agentAID, AgentVersion: "1.0", Kind: AnomalySystem, Key: "fs_read:/etc/",
		Score: 1, WindowStart: now, WindowEnd: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("UpsertAnomaly A: %v", err)
	}
	anomaliesB, err := s.ListAnomalies(ctx, tenantB, AnomalyFilter{})
	if err != nil || len(anomaliesB) != 0 {
		t.Fatalf("tenant B must not see tenant A's anomalies, got %+v (err %v)", anomaliesB, err)
	}
	anomaliesA, err := s.ListAnomalies(ctx, tenantA, AnomalyFilter{})
	if err != nil || len(anomaliesA) != 1 {
		t.Fatalf("ListAnomalies A = %+v (err %v), want exactly one", anomaliesA, err)
	}
	if err := s.AckAnomaly(ctx, tenantB, anomaliesA[0].ID, "someone"); err != ErrNotFound {
		t.Fatalf("acknowledging tenant A's anomaly under tenant B must be ErrNotFound, got %v", err)
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
	otherAgent, _, err := s.CreateAgent(ctx, tenantID, "agent-2")
	if err != nil {
		t.Fatalf("CreateAgent 2: %v", err)
	}

	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Hour) // version 1.1 starts two hours later
	v1 := []IngestedEvent{
		{Timestamp: t0, ActionType: "fs_write", Resource: "/workspace/a", Decision: "allow", MatchedRule: "r1", AgentVersion: "1.0", EventID: "aaaa000000000001"},
		{Timestamp: t0.Add(time.Minute), ActionType: "fs_write", Resource: "/workspace/b", Decision: "allow", MatchedRule: "r1", AgentVersion: "1.0", EventID: "aaaa000000000002"},
		{Timestamp: t0.Add(2 * time.Minute), ActionType: "fs_write", Resource: "/prod/a", Decision: "deny", MatchedRule: "no-prod-write", AgentVersion: "1.0"},
		{Timestamp: t0.Add(3 * time.Minute), ActionType: "fs_write", Resource: "/prod/b", Decision: "deny", MatchedRule: "no-prod-write", AgentVersion: "1.0"},
		{Timestamp: t0.Add(4 * time.Minute), ActionType: "shell", Resource: "rm -rf x", Decision: "require_approval", MatchedRule: "destructive-delete", AgentVersion: "1.0"},
		// outcomes for the two allowed writes: one success, one error
		{Timestamp: t0.Add(5 * time.Minute), Kind: IngestKindOutcome, EventID: "aaaa000000000001", Outcome: &EventOutcome{Status: "success", ExecMS: 100}},
		{Timestamp: t0.Add(5 * time.Minute), Kind: IngestKindOutcome, EventID: "aaaa000000000002", Outcome: &EventOutcome{Status: "error", ExecMS: 300, Error: "disk full"}},
	}
	v11 := []IngestedEvent{
		{Timestamp: t1, ActionType: "mcp_tool", Resource: "crm.lookup_customer", Decision: "allow", MatchedRule: "r2", AgentVersion: "1.1", EventID: "bbbb000000000001",
			Action: json.RawMessage(`{"type":"mcp_tool","server":"crm","tool":"lookup_customer","args":{"id":"c1"},"description":"Look up one CRM customer by id."}`)},
		{Timestamp: t1.Add(time.Minute), ActionType: "mcp_tool", Resource: "crm.lookup_customer", Decision: "allow", MatchedRule: "r2", AgentVersion: "1.1",
			Action: json.RawMessage(`{"type":"mcp_tool","server":"crm","tool":"lookup_customer","args":{"id":"c2","fields":["name"]}}`)},
		{Timestamp: t1.Add(2 * time.Minute), ActionType: "shell", Resource: "curl -s https://x", Decision: "allow", MatchedRule: "r3", AgentVersion: "1.1"},
		{Timestamp: t1.Add(3 * time.Minute), Kind: IngestKindOutcome, EventID: "bbbb000000000001", Outcome: &EventOutcome{Status: "success", ExecMS: 50}},
	}
	if err := s.InsertEvents(ctx, tenantID, agentID, v1); err != nil {
		t.Fatalf("InsertEvents v1: %v", err)
	}
	if err := s.InsertEvents(ctx, tenantID, agentID, v11); err != nil {
		t.Fatalf("InsertEvents v1.1: %v", err)
	}
	// Another agent in the same tenant: counted tenant-wide, excluded per agent.
	if err := s.InsertEvents(ctx, tenantID, otherAgent, []IngestedEvent{
		{Timestamp: t1, ActionType: "network", Resource: "GET api.example.com", Decision: "allow", MatchedRule: "r4", AgentVersion: "9.9"},
	}); err != nil {
		t.Fatalf("InsertEvents other: %v", err)
	}

	// Tenant-wide, no filter: the original overview contract still holds.
	m, err := s.Metrics(ctx, tenantID, MetricsFilter{})
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if m.AllowCount != 6 || m.DenyCount != 2 || m.RequireApprovalCount != 1 || m.TotalCount != 9 {
		t.Fatalf("tenant-wide counts = allow %d deny %d approval %d total %d, want 6/2/1/9", m.AllowCount, m.DenyCount, m.RequireApprovalCount, m.TotalCount)
	}
	if len(m.TopDeniedRules) != 1 || m.TopDeniedRules[0].Value != "no-prod-write" || m.TopDeniedRules[0].Count != 2 {
		t.Fatalf("TopDeniedRules = %+v, want [{no-prod-write 2}]", m.TopDeniedRules)
	}
	if m.Versions != nil {
		t.Fatalf("Versions must only be listed for a single agent, got %+v", m.Versions)
	}

	// Per agent: versions listed most recent first, ignoring the version filter.
	m, err = s.Metrics(ctx, tenantID, MetricsFilter{AgentID: agentID, AgentVersion: "1.0"})
	if err != nil {
		t.Fatalf("Metrics agent v1.0: %v", err)
	}
	if m.TotalCount != 5 || m.AllowCount != 2 || m.DenyCount != 2 || m.RequireApprovalCount != 1 {
		t.Fatalf("v1.0 counts = %+v", m)
	}
	if m.ReportedCount != 2 || m.ErrorCount != 1 || m.ExecSamples != 2 {
		t.Fatalf("v1.0 outcomes: reported %d error %d samples %d, want 2/1/2", m.ReportedCount, m.ErrorCount, m.ExecSamples)
	}
	if m.ExecP50MS == nil || *m.ExecP50MS != 200 || m.ExecP95MS == nil || *m.ExecP95MS < 290 {
		t.Fatalf("v1.0 exec percentiles p50=%v p95=%v, want 200 / ~290", m.ExecP50MS, m.ExecP95MS)
	}
	// Scope keys: /workspace/a and /workspace/b collapse to one directory,
	// /prod/a and /prod/b to another, rm -rf x to "rm".
	if m.DistinctResources != 3 {
		t.Fatalf("v1.0 DistinctResources = %d, want 3 (fs_write:/workspace/, fs_write:/prod/, shell:rm)", m.DistinctResources)
	}
	if len(m.TopResources) != 3 || m.TopResources[0].Count != 2 {
		t.Fatalf("v1.0 TopResources = %+v", m.TopResources)
	}
	wantTop := map[string]int64{"fs_write:/workspace/": 2, "fs_write:/prod/": 2, "shell:rm": 1}
	for _, rc := range m.TopResources {
		if wantTop[rc.Value] != rc.Count {
			t.Fatalf("TopResources entry %+v not in %v", rc, wantTop)
		}
	}
	if len(m.ByActionType) != 2 || m.ByActionType[0].Value != "fs_write" || m.ByActionType[0].Count != 4 {
		t.Fatalf("v1.0 ByActionType = %+v", m.ByActionType)
	}
	if len(m.Versions) != 2 || m.Versions[0].AgentVersion != "1.1" || m.Versions[1].AgentVersion != "1.0" || m.Versions[1].Count != 5 {
		t.Fatalf("Versions = %+v, want [1.1, 1.0(5)]", m.Versions)
	}
	if m.Versions[0].FirstSeen.Before(m.Versions[1].LastSeen) {
		t.Fatalf("version 1.1 must start after 1.0 ended: %+v", m.Versions)
	}
	// Open bounds: rate over the observed span, never less than an hour.
	if m.EventsPerHour != 5 {
		t.Fatalf("v1.0 EventsPerHour = %v, want 5 (5 events in a <1h span)", m.EventsPerHour)
	}

	// The other version, and an explicit two-hour range.
	m, err = s.Metrics(ctx, tenantID, MetricsFilter{AgentID: agentID, AgentVersion: "1.1"})
	if err != nil {
		t.Fatalf("Metrics agent v1.1: %v", err)
	}
	if m.TotalCount != 3 || m.ErrorCount != 0 || m.ExecSamples != 1 || m.DistinctResources != 2 {
		t.Fatalf("v1.1 = %+v", m)
	}
	until := t1.Add(2 * time.Hour)
	m, err = s.Metrics(ctx, tenantID, MetricsFilter{AgentID: agentID, Since: &t1, Until: &until})
	if err != nil {
		t.Fatalf("Metrics ranged: %v", err)
	}
	if m.TotalCount != 3 || m.EventsPerHour != 1.5 {
		t.Fatalf("ranged: total %d per hour %v, want 3 / 1.5", m.TotalCount, m.EventsPerHour)
	}

	// Metrics with no matching events is all zeros and nil percentiles.
	m, err = s.Metrics(ctx, tenantID, MetricsFilter{AgentID: agentID, AgentVersion: "nope"})
	if err != nil || m.TotalCount != 0 || m.ExecP50MS != nil || m.EventsPerHour != 0 || m.FirstSeen != nil {
		t.Fatalf("empty Metrics = %+v (err %v)", m, err)
	}
}

func TestToolCatalogUpsert(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	agentID, _, err := s.CreateAgent(ctx, tenantID, "agent-1")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	// First batch: a described tool and an undescribed one; fs events are
	// never cataloged.
	if err := s.InsertEvents(ctx, tenantID, agentID, []IngestedEvent{
		{Timestamp: t0, ActionType: "function", Resource: "send_email", Decision: "allow", MatchedRule: "r",
			Action: json.RawMessage(`{"type":"function","name":"send_email","args":{"to":"a","body":"b"},"description":"Send an email."}`)},
		{Timestamp: t0, ActionType: "function", Resource: "search", Decision: "allow", MatchedRule: "r",
			Action: json.RawMessage(`{"type":"function","name":"search","args":{"q":"x"}}`)},
		{Timestamp: t0, ActionType: "fs_read", Resource: "/etc/hosts", Decision: "allow", MatchedRule: "r"},
	}); err != nil {
		t.Fatalf("InsertEvents 1: %v", err)
	}
	tools, err := s.ListToolCatalog(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListToolCatalog: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 cataloged tools (no fs_read), got %+v", tools)
	}
	byName := map[string]ToolCatalogEntry{}
	for _, tl := range tools {
		byName[tl.Resource] = tl
	}
	if byName["send_email"].Description != "Send an email." || len(byName["send_email"].ArgKeys) != 2 {
		t.Fatalf("send_email = %+v", byName["send_email"])
	}
	if byName["search"].Description != "" || len(byName["search"].ArgKeys) != 1 {
		t.Fatalf("search = %+v", byName["search"])
	}

	// Second batch: a later call without a description keeps the existing
	// one, adds a new argument name, and advances last_seen_at; the
	// undescribed tool gains its description.
	t2 := t0.Add(time.Hour)
	if err := s.InsertEvents(ctx, tenantID, agentID, []IngestedEvent{
		{Timestamp: t2, ActionType: "function", Resource: "send_email", Decision: "allow", MatchedRule: "r",
			Action: json.RawMessage(`{"type":"function","name":"send_email","args":{"to":"a","cc":"c"}}`)},
		{Timestamp: t2, ActionType: "function", Resource: "search", Decision: "allow", MatchedRule: "r",
			Action: json.RawMessage(`{"type":"function","name":"search","description":"Full-text search."}`)},
	}); err != nil {
		t.Fatalf("InsertEvents 2: %v", err)
	}
	tools, _ = s.ListToolCatalog(ctx, tenantID)
	byName = map[string]ToolCatalogEntry{}
	for _, tl := range tools {
		byName[tl.Resource] = tl
	}
	se := byName["send_email"]
	if se.Description != "Send an email." || !se.LastSeenAt.Equal(t2) || !se.FirstSeenAt.Equal(t0) {
		t.Fatalf("send_email after 2nd batch = %+v", se)
	}
	if len(se.ArgKeys) != 3 || se.ArgKeys[0] != "body" || se.ArgKeys[1] != "cc" || se.ArgKeys[2] != "to" {
		t.Fatalf("send_email arg keys = %v, want [body cc to]", se.ArgKeys)
	}
	if byName["search"].Description != "Full-text search." {
		t.Fatalf("search should have gained its description, got %+v", byName["search"])
	}
}

func TestTenantSettingsDefaultsAndRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}

	// No row saved yet: the named defaults.
	got, err := s.GetTenantSettings(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantSettings (defaults): %v", err)
	}
	want := DefaultTenantSettings(tenantID)
	if got != want {
		t.Fatalf("GetTenantSettings with no saved row = %+v, want defaults %+v", got, want)
	}
	if err := want.Validate(); err != nil {
		t.Fatalf("the defaults must themselves be valid: %v", err)
	}

	// Save custom thresholds, read them back exactly.
	custom := TenantSettings{
		TenantID: tenantID, WindowMinutes: 30, BaselineHours: 12, MinBaselineEvents: 20,
		VolumeRatio: 2.5, ShareShift: 0.2, DenyRateRatio: 4, ErrorRateRatio: 4, LatencyRatio: 2, BulkRatio: 8, MinEvents: 3,
	}
	if err := s.PutTenantSettings(ctx, custom); err != nil {
		t.Fatalf("PutTenantSettings: %v", err)
	}
	got, err = s.GetTenantSettings(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantSettings (after save): %v", err)
	}
	got.UpdatedAt = time.Time{} // set by the database; not part of the comparison
	custom.UpdatedAt = time.Time{}
	if got != custom {
		t.Fatalf("GetTenantSettings after save = %+v, want %+v", got, custom)
	}

	// A second save updates the same row rather than erroring or adding one.
	custom.WindowMinutes = 45
	if err := s.PutTenantSettings(ctx, custom); err != nil {
		t.Fatalf("PutTenantSettings (update): %v", err)
	}
	got, err = s.GetTenantSettings(ctx, tenantID)
	if err != nil || got.WindowMinutes != 45 {
		t.Fatalf("GetTenantSettings after update = %+v (err %v), want window_minutes 45", got, err)
	}

	invalid := []TenantSettings{
		{TenantID: tenantID, WindowMinutes: 0, BaselineHours: 24, MinBaselineEvents: 50, VolumeRatio: 3, ShareShift: 0.3, DenyRateRatio: 3, ErrorRateRatio: 3, LatencyRatio: 3, BulkRatio: 5, MinEvents: 5},
		{TenantID: tenantID, WindowMinutes: 60, BaselineHours: 24, MinBaselineEvents: 50, VolumeRatio: 3, ShareShift: 1.5, DenyRateRatio: 3, ErrorRateRatio: 3, LatencyRatio: 3, BulkRatio: 5, MinEvents: 5},
		{TenantID: tenantID, WindowMinutes: 60, BaselineHours: 24, MinBaselineEvents: 50, VolumeRatio: 1, ShareShift: 0.3, DenyRateRatio: 3, ErrorRateRatio: 3, LatencyRatio: 3, BulkRatio: 5, MinEvents: 5},
	}
	for _, bad := range invalid {
		if err := bad.Validate(); err == nil {
			t.Fatalf("expected Validate to reject %+v", bad)
		}
	}
}

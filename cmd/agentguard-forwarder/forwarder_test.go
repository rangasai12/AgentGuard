package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agentguard/cli"
	"agentguard/daemon"
	"agentguard/dashboard/server"
	"agentguard/dashboard/store"
	"agentguard/engine"
)

// This test drives the real local daemon over a real Unix socket, a real
// JSONL audit log file, and a real (in-process, httptest) Control API
// backed by the real Postgres test database — the same "test against the
// real thing" standard the rest of this repo holds itself to, applied to
// the one new local component (agentguard-forwarder) this feature adds.
const forwarderTestPolicy = `
version: 1
filesystem:
  - allow: read_write
    paths: ["/workspace/**"]
  - deny: write
    paths: ["**"]
shell:
  default: deny
  deny:
    - pattern: "rm -rf *"
      require_approval: true
escalation:
  approval_timeout_seconds: 30
  on_timeout: deny
`

func newTestDaemonOnSocket(t *testing.T) (d *daemon.Daemon, socketPath, auditLogPath string) {
	t.Helper()
	policy, err := engine.ParsePolicy([]byte(forwarderTestPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	// Deliberately not t.TempDir(): on macOS that nests under a long
	// $TMPDIR path (/var/folders/.../TestName.../001), which blows past
	// the ~104-byte AF_UNIX sun_path limit and fails with a confusing
	// "connect: invalid argument". /tmp itself stays short enough.
	dir, err := os.MkdirTemp("/tmp", "agfwd")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	auditLogPath = filepath.Join(dir, "audit.log")
	audit, err := daemon.NewAuditLogger(auditLogPath)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })

	d = daemon.New(policy, audit)
	socketPath = filepath.Join(dir, "agentguard.sock")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = daemon.Serve(ctx, socketPath, d) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return d, socketPath, auditLogPath
}

func newTestControlAPI(t *testing.T) (baseURL string, s *store.Store) {
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

	srv := httptest.NewServer(server.New(s))
	t.Cleanup(srv.Close)
	return srv.URL, s
}

func TestForwarderShipsNewAuditEvents(t *testing.T) {
	_, socketPath, auditLogPath := newTestDaemonOnSocket(t)
	baseURL, s := newTestControlAPI(t)
	ctx := context.Background()

	_, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	agentID, regToken, err := s.CreateAgent(ctx, tenantID, "test-agent")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	_, apiKey, err := s.RedeemRegistration(ctx, regToken)
	if err != nil {
		t.Fatalf("RedeemRegistration: %v", err)
	}

	// Drive a real decision through the real daemon over the real socket,
	// via cli.Dial, exactly as the SDK/CLI would.
	c, err := cli.Dial(socketPath)
	if err != nil {
		t.Fatalf("dialing daemon: %v", err)
	}
	evalResp, err := c.Call(daemon.Request{
		Cmd:    "evaluate",
		Actor:  "test-actor",
		Action: engine.Action{Type: engine.ActionFSWrite, Path: "/prod/config.txt"},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if evalResp.Decision == nil || evalResp.Decision.Result != engine.Deny {
		t.Fatalf("expected deny for a write outside /workspace, got %+v", evalResp.Decision)
	}
	c.Close()

	f := &forwarder{
		client:       &httpClient{base: baseURL, apiKey: apiKey, http: &http.Client{Timeout: 10 * time.Second}},
		socketPath:   socketPath,
		auditLogPath: auditLogPath,
		statePath:    filepath.Join(t.TempDir(), "state.json"),
	}
	f.tick()

	events, err := s.QueryEvents(ctx, tenantID, store.EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(events) != 1 || events[0].Resource != "/prod/config.txt" || events[0].Decision != "deny" {
		t.Fatalf("expected the denied write to have been shipped, got %+v", events)
	}
	if events[0].AgentID != agentID {
		t.Fatalf("event shipped under agent %q, want %q", events[0].AgentID, agentID)
	}

	// A second tick with no new log lines should ship nothing new.
	f.tick()
	eventsAfter, err := s.QueryEvents(ctx, tenantID, store.EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents (second): %v", err)
	}
	if len(eventsAfter) != 1 {
		t.Fatalf("expected no duplicate shipping on a tick with no new lines, got %d events", len(eventsAfter))
	}
}

func TestForwarderRelaysBrowserApprovalToLocalDaemon(t *testing.T) {
	d, socketPath, auditLogPath := newTestDaemonOnSocket(t)
	baseURL, s := newTestControlAPI(t)
	ctx := context.Background()

	_, tenantID, err := s.SignUp(ctx, "Acme", "u@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	adminUserID, _, err := s.SignUp(ctx, "unused", "admin2@acme.example", "password123")
	if err != nil {
		t.Fatalf("SignUp (resolver user): %v", err)
	}
	_, regToken, err := s.CreateAgent(ctx, tenantID, "test-agent")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	_, apiKey, err := s.RedeemRegistration(ctx, regToken)
	if err != nil {
		t.Fatalf("RedeemRegistration: %v", err)
	}

	f := &forwarder{
		client:       &httpClient{base: baseURL, apiKey: apiKey, http: &http.Client{Timeout: 10 * time.Second}},
		socketPath:   socketPath,
		auditLogPath: auditLogPath,
		statePath:    filepath.Join(t.TempDir(), "state.json"),
	}

	// Kick off a real blocking Evaluate for an action that requires
	// approval, exactly like a real agent's tool call would.
	resultCh := make(chan engine.Result, 1)
	go func() {
		res := d.Evaluate("test-actor", engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"})
		resultCh <- res.Decision.Result
	}()

	// Wait for it to actually be pending locally, then have the forwarder
	// sync it upstream (step 1 of the round trip).
	deadline := time.Now().Add(2 * time.Second)
	for len(d.Approvals.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(d.Approvals.List()) != 1 {
		t.Fatal("approval never appeared locally")
	}
	if err := f.syncPending(); err != nil {
		t.Fatalf("syncPending: %v", err)
	}

	pending, err := s.ListPending(ctx, tenantID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPending: %+v, err=%v", pending, err)
	}

	// Simulate the browser click (step 2): a dashboard user requests
	// approval directly through the store, exactly as the Web API handler
	// would.
	if err := s.RequestResolution(ctx, tenantID, pending[0].ID, adminUserID, "approve"); err != nil {
		t.Fatalf("RequestResolution: %v", err)
	}

	// The forwarder's next tick should discover and relay it (step 3).
	if err := f.relayResolutions(); err != nil {
		t.Fatalf("relayResolutions: %v", err)
	}

	select {
	case result := <-resultCh:
		if result != engine.Allow {
			t.Fatalf("expected the browser-approved action to resolve Allow, got %s", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Evaluate never returned after the forwarder relayed the approval")
	}

	final, err := s.ListPending(ctx, tenantID)
	if err != nil || len(final) != 0 {
		t.Fatalf("expected the approval to be fully resolved after relay+ack, got %+v (err=%v)", final, err)
	}
}

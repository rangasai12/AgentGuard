package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"agentguard/engine"
)

func TestWebhookNotifierPostsExpectedPayload(t *testing.T) {
	var mu sync.Mutex
	var received WebhookPayload
	var gotContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decoding webhook body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notify := WebhookNotifier(server.URL, nil, nil)
	pending := PendingApproval{
		ID:          "abc123",
		Actor:       "agent-1",
		Action:      engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"},
		MatchedRule: "shell.deny[0]",
		Reason:      "destructive",
		CreatedAt:   time.Now(),
	}

	// WebhookNotifier itself is synchronous (the async guarantee is
	// ApprovalBroker.Await's job); call it directly and wait for the POST.
	notify(pending)

	mu.Lock()
	defer mu.Unlock()
	if gotContentType != "application/json" {
		t.Errorf("expected application/json content type, got %q", gotContentType)
	}
	if received.ApprovalID != "abc123" {
		t.Errorf("expected approval_id abc123, got %q", received.ApprovalID)
	}
	if received.Actor != "agent-1" {
		t.Errorf("expected actor agent-1, got %q", received.Actor)
	}
	if received.ActionType != string(engine.ActionShell) {
		t.Errorf("expected action_type shell, got %q", received.ActionType)
	}
	if received.Resource != "rm -rf /workspace/build" {
		t.Errorf("expected resource to be the command, got %q", received.Resource)
	}
	if received.Text == "" {
		t.Error("expected a non-empty text field (required for Slack Incoming Webhooks)")
	}
}

func TestWebhookNotifierUnreachableURLDoesNotPanic(t *testing.T) {
	var loggedErr error
	notify := WebhookNotifier("http://127.0.0.1:1/nowhere", nil, func(err error) { loggedErr = err })

	// Must not panic, block indefinitely, or otherwise misbehave — a broken
	// webhook is a missed notification, nothing more.
	done := make(chan struct{})
	go func() {
		notify(PendingApproval{ID: "x"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("notify against an unreachable URL did not return in time")
	}
	if loggedErr == nil {
		t.Error("expected the connection failure to be reported via errLog")
	}
}

func TestWebhookNotifierNonSuccessStatusIsLogged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	var loggedErr error
	notify := WebhookNotifier(server.URL, nil, func(err error) { loggedErr = err })
	notify(PendingApproval{ID: "x"})

	if loggedErr == nil {
		t.Error("expected a 500 response to be reported via errLog")
	}
}

func TestWebhookNotifierIntegratesWithApprovalBroker(t *testing.T) {
	// End-to-end within this package: a real ApprovalBroker.Await call,
	// backed by a real WebhookNotifier, posting to a real local HTTP
	// server — proves the two pieces actually fit together, not just each
	// in isolation.
	notifiedCh := make(chan WebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p WebhookPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		notifiedCh <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	broker := NewApprovalBroker()
	notify := WebhookNotifier(server.URL, nil, nil)

	go broker.Await("agent-1", engine.Action{Type: engine.ActionMCPTool, Server: "payments", Tool: "charge"}, engine.Decision{MatchedRule: "r"}, 2*time.Second, engine.Deny, notify)

	select {
	case payload := <-notifiedCh:
		if payload.Resource != "payments.charge" {
			t.Errorf("expected resource payments.charge, got %q", payload.Resource)
		}
		if err := broker.Resolve(payload.ApprovalID, engine.Allow); err != nil {
			t.Errorf("expected the ID from the webhook payload to be resolvable: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

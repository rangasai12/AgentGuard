package daemon

import (
	"testing"
	"time"

	"agentguard/engine"
)

func TestApprovalBrokerResolveApprove(t *testing.T) {
	b := NewApprovalBroker()
	resultCh := make(chan engine.Result, 1)

	go func() {
		r, _ := b.Await("agent-1", engine.Action{Type: engine.ActionShell, Command: "rm -rf /"}, engine.Decision{Result: engine.RequireApproval}, 2*time.Second, engine.Deny, nil)
		resultCh <- r
	}()

	// Wait for the approval to be registered before resolving it.
	deadline := time.After(time.Second)
	for {
		if len(b.List()) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared in pending list")
		case <-time.After(time.Millisecond):
		}
	}

	pending := b.List()
	if err := b.Resolve(pending[0].ID, engine.Allow); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	select {
	case r := <-resultCh:
		if r != engine.Allow {
			t.Errorf("expected Allow, got %s", r)
		}
	case <-time.After(time.Second):
		t.Fatal("Await did not return after Resolve")
	}

	if len(b.List()) != 0 {
		t.Errorf("expected pending list to be empty after resolution, got %d", len(b.List()))
	}
}

func TestApprovalBrokerTimeoutFallsBackToOnTimeout(t *testing.T) {
	b := NewApprovalBroker()
	r, id := b.Await("agent-1", engine.Action{Type: engine.ActionShell, Command: "rm -rf /"}, engine.Decision{Result: engine.RequireApproval}, 20*time.Millisecond, engine.Deny, nil)
	if r != engine.Deny {
		t.Errorf("expected timeout to fall back to Deny, got %s", r)
	}
	if id == "" {
		t.Error("expected a non-empty approval id even on timeout")
	}
}

func TestApprovalBrokerResolveUnknownID(t *testing.T) {
	b := NewApprovalBroker()
	if err := b.Resolve("nonexistent", engine.Allow); err == nil {
		t.Fatal("expected error resolving unknown approval id")
	}
}

func TestApprovalBrokerNotifiesWithTheRegisteredID(t *testing.T) {
	b := NewApprovalBroker()
	notified := make(chan PendingApproval, 1)
	notify := func(p PendingApproval) { notified <- p }

	go func() {
		b.Await("agent-1", engine.Action{Type: engine.ActionShell, Command: "rm -rf /"}, engine.Decision{MatchedRule: "r1", Reason: "destructive"}, 2*time.Second, engine.Deny, notify)
	}()

	var got PendingApproval
	select {
	case got = <-notified:
	case <-time.After(time.Second):
		t.Fatal("notify was never called")
	}

	if got.Actor != "agent-1" || got.MatchedRule != "r1" || got.Reason != "destructive" {
		t.Errorf("notify received wrong data: %+v", got)
	}
	// The ID notify was given must already be resolvable — i.e. notify fires
	// after registration, not before — otherwise a human clicking "approve"
	// the instant they see the notification could hit a not-yet-registered ID.
	if err := b.Resolve(got.ID, engine.Allow); err != nil {
		t.Errorf("expected the notified ID to already be resolvable, got error: %v", err)
	}
}

func TestApprovalBrokerSlowNotifyDoesNotDelayResolution(t *testing.T) {
	b := NewApprovalBroker()
	notifyStarted := make(chan struct{})
	notify := func(p PendingApproval) {
		close(notifyStarted)
		time.Sleep(500 * time.Millisecond) // slower than the assertions below allow
	}

	resultCh := make(chan engine.Result, 1)
	go func() {
		r, _ := b.Await("agent-1", engine.Action{Type: engine.ActionShell}, engine.Decision{}, 2*time.Second, engine.Deny, notify)
		resultCh <- r
	}()

	<-notifyStarted // notify is now blocked sleeping
	var id string
	deadline := time.After(time.Second)
	for id == "" {
		if p := b.List(); len(p) == 1 {
			id = p[0].ID
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared")
		case <-time.After(time.Millisecond):
		}
	}

	start := time.Now()
	if err := b.Resolve(id, engine.Allow); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	select {
	case r := <-resultCh:
		if r != engine.Allow {
			t.Errorf("expected Allow, got %s", r)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Await did not return promptly — a slow notify function blocked the approval flow")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("Resolve took %s to take effect; notify's 500ms sleep must not have blocked it", elapsed)
	}
}

func TestApprovalBrokerResolveTwiceErrors(t *testing.T) {
	b := NewApprovalBroker()
	resultCh := make(chan engine.Result, 1)
	go func() {
		r, _ := b.Await("agent-1", engine.Action{Type: engine.ActionShell}, engine.Decision{}, time.Second, engine.Deny, nil)
		resultCh <- r
	}()

	var id string
	deadline := time.After(time.Second)
	for id == "" {
		if p := b.List(); len(p) == 1 {
			id = p[0].ID
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared")
		case <-time.After(time.Millisecond):
		}
	}

	if err := b.Resolve(id, engine.Allow); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	<-resultCh // ensure Await has consumed it and the entry is cleaned up
	time.Sleep(10 * time.Millisecond)
	if err := b.Resolve(id, engine.Allow); err == nil {
		t.Fatal("expected error resolving an already-consumed/removed approval id")
	}
}

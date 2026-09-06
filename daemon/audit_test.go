package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentguard/engine"
)

func newTestAuditLogger(t *testing.T) *AuditLogger {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestAuditLogTailAndQuery(t *testing.T) {
	l := newTestAuditLogger(t)

	events := []AuditEvent{
		{Actor: "agent-1", ActionType: engine.ActionFSWrite, Resource: "/workspace/a", Decision: engine.Allow, MatchedRule: "r1"},
		{Actor: "agent-1", ActionType: engine.ActionShell, Resource: "rm -rf /", Decision: engine.Deny, MatchedRule: "r2"},
		{Actor: "agent-2", ActionType: engine.ActionNetwork, Resource: "GET evil.com", Decision: engine.Deny, MatchedRule: "r3"},
	}
	for _, ev := range events {
		if err := l.Log(ev); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	tail := l.Tail(2)
	if len(tail) != 2 {
		t.Fatalf("expected 2 tail events, got %d", len(tail))
	}
	if tail[0].Resource != "rm -rf /" || tail[1].Resource != "GET evil.com" {
		t.Errorf("tail returned wrong events: %+v", tail)
	}

	denies := l.Query(AuditFilter{Decision: engine.Deny})
	if len(denies) != 2 {
		t.Fatalf("expected 2 deny events, got %d", len(denies))
	}
	// Query returns most-recent-first.
	if denies[0].Resource != "GET evil.com" {
		t.Errorf("expected most recent deny first, got %+v", denies[0])
	}

	byActor := l.Query(AuditFilter{Actor: "agent-2"})
	if len(byActor) != 1 || byActor[0].Actor != "agent-2" {
		t.Errorf("actor filter returned wrong events: %+v", byActor)
	}
}

func TestAuditLogPersistsToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	if err := l.Log(AuditEvent{Resource: "/x", Decision: engine.Allow}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening should append, not truncate; the file should contain the prior line.
	l2, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("reopening audit log: %v", err)
	}
	defer l2.Close()
	if err := l2.Log(AuditEvent{Resource: "/y", Decision: engine.Deny}); err != nil {
		t.Fatalf("Log after reopen: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log file: %v", err)
	}
	if got := strings.Count(strings.TrimRight(string(data), "\n"), "\n") + 1; got != 2 {
		t.Errorf("expected 2 lines in audit log file, got %d:\n%s", got, data)
	}
}

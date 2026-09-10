package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

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

	// Reporting an outcome appends a patch line to the file but merges into
	// the single decision in the ring, so Tail sees one event with an outcome.
	const id = "0123456789abcdef"
	if err := l2.Log(AuditEvent{EventID: id, Resource: "/z", Decision: engine.Allow}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l2.Report(id, Outcome{Status: OutcomeSuccess, ExecMS: 42, Output: "hello"}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	data, _ = os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines (3 decisions + 1 outcome patch), got %d:\n%s", len(lines), data)
	}
	var patch AuditEvent
	if err := json.Unmarshal([]byte(lines[3]), &patch); err != nil {
		t.Fatalf("unmarshal patch line: %v", err)
	}
	if patch.Kind != KindOutcome || patch.EventID != id || patch.Outcome == nil || patch.Outcome.ExecMS != 42 {
		t.Errorf("unexpected patch line: %+v", patch)
	}
	if patch.Outcome.OutputBytes != 5 || patch.Outcome.OutputSHA256 == "" {
		t.Errorf("expected Report to fill output_bytes/sha256 from the full output, got %+v", patch.Outcome)
	}
	tail := l2.Tail(10)
	if len(tail) != 2 {
		t.Fatalf("expected the ring to hold 2 merged decisions (no separate patch entry), got %d: %+v", len(tail), tail)
	}
	if tail[1].EventID != id || tail[1].Outcome == nil || tail[1].Outcome.Output != "hello" {
		t.Errorf("expected the ring entry to be patched in place with the outcome, got %+v", tail[1])
	}
	if q := l2.Query(AuditFilter{EventID: id}); len(q) != 1 || q[0].Outcome == nil {
		t.Errorf("expected Query by event id to return the merged event, got %+v", q)
	}
}

func TestAuditReportUnknownEventStillAppendsPatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer l.Close()

	// Simulates a daemon restart between evaluate and report: the ring is
	// empty, but downstream (the cloud) can still merge the patch by id.
	if err := l.Report("feedfacefeedface", Outcome{Status: OutcomeError, Error: "boom"}); err != nil {
		t.Fatalf("Report against an unknown event must not fail: %v", err)
	}
	if len(l.Tail(10)) != 0 {
		t.Errorf("an orphan patch must not appear as a ring entry")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"kind":"outcome"`) || !strings.Contains(string(data), `"feedfacefeedface"`) {
		t.Errorf("expected an outcome patch line in the file, got %s", data)
	}
}

func TestAuditReportTruncatesOversizedOutput(t *testing.T) {
	l := newTestAuditLogger(t)
	const id = "00000000deadbeef"
	if err := l.Log(AuditEvent{EventID: id, Decision: engine.Allow}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	big := strings.Repeat("é", MaxOutputPreviewBytes) // 2 bytes each: twice the hard cap
	if err := l.Report(id, Outcome{Status: OutcomeSuccess, Output: big}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	got := l.Tail(1)[0].Outcome
	if len(got.Output) > DefaultOutputPreviewBytes {
		t.Errorf("expected the stored preview to be at most %d bytes, got %d", DefaultOutputPreviewBytes, len(got.Output))
	}
	if !utf8.ValidString(got.Output) {
		t.Error("truncation must not split a multi-byte rune")
	}
	if got.OutputBytes != int64(len(big)) {
		t.Errorf("output_bytes must describe the full output (%d), got %d", len(big), got.OutputBytes)
	}

	// Configured preview above the hard cap is clamped to it.
	l.SetOutputPreviewBytes(10 * MaxOutputPreviewBytes)
	if err := l.Report(id, Outcome{Status: OutcomeSuccess, Output: big}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if got := l.Tail(1)[0].Outcome; len(got.Output) > MaxOutputPreviewBytes {
		t.Errorf("expected the hard cap %d to bind, got %d bytes", MaxOutputPreviewBytes, len(got.Output))
	}

	// Malformed ids and statuses are rejected before anything is written.
	if err := l.Report("not-hex!", Outcome{Status: OutcomeSuccess}); err == nil {
		t.Error("expected an error for a non-hex event id")
	}
	if err := l.Report(id, Outcome{Status: "meh"}); err == nil {
		t.Error("expected an error for an invalid status")
	}
}

package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rangasai12/AgentGuard/engine"
)

func writeEvents(t *testing.T, l *AuditLogger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Log(AuditEvent{Timestamp: time.Now(), ActionType: engine.ActionShell, Resource: "ls", Decision: engine.Allow, EventID: newHexID(8)}); err != nil {
			t.Fatal(err)
		}
	}
}

func verifyFile(t *testing.T, path string) AuditVerifyReport {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := VerifyAuditLog(f)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestAuditChainVerifiesAndDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, l, 3)
	if err := l.Report(l.Tail(1)[0].EventID, Outcome{Status: OutcomeSuccess, Output: "ok"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	rep := verifyFile(t, path)
	if rep.BrokenAt != 0 || rep.Lines != 4 || rep.Unchained != 0 || rep.Head == "" {
		t.Fatalf("fresh log should verify, got %+v", rep)
	}

	orig, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(orig, []byte("\n"))[:4]
	cases := map[string][]byte{
		"edited line":   bytes.Replace(orig, []byte(`"decision":"allow"`), []byte(`"decision":"deny"`), 1),
		"deleted line":  bytes.Join([][]byte{lines[0], lines[2], lines[3]}, nil),
		"reordered":     bytes.Join([][]byte{lines[1], lines[0], lines[2], lines[3]}, nil),
		"inserted line": bytes.Join([][]byte{lines[0], []byte("{\"decision\":\"allow\"}\n"), lines[1], lines[2], lines[3]}, nil),
		"torn write":    orig[:len(orig)-5],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if rep := verifyFile(t, path); rep.BrokenAt == 0 {
				t.Errorf("tampering not detected: %+v", rep)
			}
		})
	}
}

func TestAuditChainAnchorsOntoAPreChainLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	legacy := "{\"decision\":\"allow\",\"resource\":\"a\"}\n{\"decision\":\"deny\",\"resource\":\"b\"}\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	writeEvents(t, l, 2)
	_ = l.Close()

	rep := verifyFile(t, path)
	if rep.BrokenAt != 0 || rep.Lines != 4 || rep.Unchained != 2 {
		t.Fatalf("want 4 lines, 2 unchained, intact; got %+v", rep)
	}
	// The last pre-chain line is anchored: changing it breaks the chain.
	data, _ := os.ReadFile(path)
	_ = os.WriteFile(path, bytes.Replace(data, []byte(`"resource":"b"`), []byte(`"resource":"c"`), 1), 0o600)
	if rep := verifyFile(t, path); rep.BrokenAt != 3 {
		t.Errorf("want break at the first chained line, got %+v", rep)
	}
}

// The daemon and the standalone proxies open the same policy-scoped log
// independently; their lines must form one chain, not two interleaved ones.
func TestAuditChainSurvivesTwoWritersOnOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { writeEvents(t, a, 50); close(done) }()
	writeEvents(t, b, 50)
	<-done
	_ = a.Close()
	_ = b.Close()

	rep := verifyFile(t, path)
	if rep.BrokenAt != 0 || rep.Lines != 100 {
		t.Fatalf("interleaved writers should still form one chain, got %+v", rep)
	}
}

func TestAuditChainHandlesLinesLongerThanOneReadChunk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 200<<10)
	for i := 0; i < 3; i++ {
		if err := l.Log(AuditEvent{Timestamp: time.Now(), Resource: big, Decision: engine.Allow}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	if rep := verifyFile(t, path); rep.BrokenAt != 0 || rep.Lines != 3 {
		t.Fatalf("got %+v", rep)
	}
}

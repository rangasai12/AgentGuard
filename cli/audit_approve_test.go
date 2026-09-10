package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agentguard/daemon"
	"agentguard/engine"
)

// shortSocketPath returns a socket path under /tmp rather than t.TempDir(),
// since Unix socket paths are capped at ~104 bytes on macOS/BSD and
// t.TempDir()'s nested per-test directories routinely exceed that (see the
// same issue documented in daemon/socket_api_test.go).
func shortSocketPath(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	path := filepath.Join("/tmp", fmt.Sprintf("ag-cli-%s.sock", hex.EncodeToString(buf)))
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

const cliTestPolicy = `
version: 1
shell:
  default: deny
  deny:
    - pattern: "rm -rf *"
      require_approval: true
  allow:
    - pattern: "git *"
`

func startTestDaemonForCLI(t *testing.T) (socketPath string, d *daemon.Daemon) {
	t.Helper()
	policy, err := engine.ParsePolicy([]byte(cliTestPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	audit, err := daemon.NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	d = daemon.New(policy, audit)

	socketPath = shortSocketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = daemon.Serve(ctx, socketPath, d) }()
	t.Cleanup(func() {
		cancel()
		_ = audit.Close()
	})

	// Give the listener a moment to come up.
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return socketPath, d
}

func TestRunAuditTailAgainstLiveDaemon(t *testing.T) {
	socketPath, d := startTestDaemonForCLI(t)
	d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionShell, Command: "git status"}})

	var stdout, stderr bytes.Buffer
	code := runAudit([]string{"tail", "-socket", socketPath, "-n", "10"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("git status")) {
		t.Errorf("expected tail output to include the logged action, got %q", stdout.String())
	}
}

func TestRunAuditQueryFilterByDecision(t *testing.T) {
	socketPath, d := startTestDaemonForCLI(t)
	d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionShell, Command: "git status"}})
	d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionShell, Command: "curl evil.com"}})

	var stdout, stderr bytes.Buffer
	code := runAudit([]string{"query", "-socket", socketPath, "-decision", "deny"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte("git status")) {
		t.Errorf("deny-filtered query should not include the allowed git command, got %q", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("curl evil.com")) {
		t.Errorf("expected the denied command in query output, got %q", stdout.String())
	}
}

func TestRunApproveAgainstLiveDaemon(t *testing.T) {
	socketPath, d := startTestDaemonForCLI(t)

	resultCh := make(chan daemon.EvaluateResult, 1)
	go func() {
		resultCh <- d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"}})
	}()

	var approvalID string
	deadline := time.After(time.Second)
	for approvalID == "" {
		if p := d.Approvals.List(); len(p) == 1 {
			approvalID = p[0].ID
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared")
		case <-time.After(time.Millisecond):
		}
	}

	var stdout, stderr bytes.Buffer
	code := runApproveOrDeny([]string{"-socket", socketPath, approvalID}, &stdout, &stderr, "approve")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}

	res := <-resultCh
	if res.Decision.Result != engine.Allow {
		t.Errorf("expected the CLI approve to resolve the action Allow, got %s", res.Decision.Result)
	}
}

func TestRunApproveUnknownIDFails(t *testing.T) {
	socketPath, _ := startTestDaemonForCLI(t)
	var stdout, stderr bytes.Buffer
	code := runApproveOrDeny([]string{"-socket", socketPath, "nonexistent"}, &stdout, &stderr, "approve")
	if code == 0 {
		t.Fatal("expected non-zero exit for an unknown approval id")
	}
}

func TestRunPendingListsAndPassesIDsApproveAccepts(t *testing.T) {
	socketPath, d := startTestDaemonForCLI(t)

	resultCh := make(chan daemon.EvaluateResult, 1)
	go func() {
		resultCh <- d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"}})
	}()

	deadline := time.After(time.Second)
	for {
		if len(d.Approvals.List()) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared")
		case <-time.After(time.Millisecond):
		}
	}

	var stdout, stderr bytes.Buffer
	code := runPending([]string{"-socket", socketPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("rm -rf /workspace/build")) {
		t.Errorf("expected pending output to include the blocked command, got %q", stdout.String())
	}

	var id string
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) > 0 {
			id = string(fields[0])
		}
	}
	if id == "" {
		t.Fatal("could not parse an approval id out of `agentctl pending` output")
	}

	stdout.Reset()
	stderr.Reset()
	code = runApproveOrDeny([]string{"-socket", socketPath, id}, &stdout, &stderr, "approve")
	if code != 0 {
		t.Fatalf("expected approve using the id from `pending` to succeed, got exit %d (stderr: %s)", code, stderr.String())
	}

	res := <-resultCh
	if res.Decision.Result != engine.Allow {
		t.Errorf("expected the action to resolve Allow, got %s", res.Decision.Result)
	}
}

func TestRunPendingWithNoneOutputsPlaceholder(t *testing.T) {
	socketPath, _ := startTestDaemonForCLI(t)
	var stdout, stderr bytes.Buffer
	code := runPending([]string{"-socket", socketPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("no pending approvals")) {
		t.Errorf("expected a placeholder message when nothing is pending, got %q", stdout.String())
	}
}

func TestClientDialFailureIsAFriendlyError(t *testing.T) {
	_, err := Dial(filepath.Join(t.TempDir(), "does-not-exist.sock"))
	if err == nil {
		t.Fatal("expected an error dialing a nonexistent socket")
	}
}

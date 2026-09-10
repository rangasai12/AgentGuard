package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agentguard/daemon"
	"agentguard/engine"
)

const policyTestSamplePolicy = `
version: 1
filesystem:
  - allow: read_write
    paths: ["/workspace/**"]
  - deny: write
    paths: ["**"]
`

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func TestRunPolicyTestAllPass(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", policyTestSamplePolicy)
	tracesPath := writeTempFile(t, "traces.yaml", `
version: 1
cases:
  - name: "write inside workspace"
    action: {type: fs_write, path: /workspace/x}
    want: allow
  - name: "write outside workspace"
    action: {type: fs_write, path: /etc/passwd}
    want: deny
`)

	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"test", policyPath, tracesPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("2 passed, 0 failed")) {
		t.Errorf("expected summary line, got:\n%s", stdout.String())
	}
}

func TestRunPolicyTestWithFailure(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", policyTestSamplePolicy)
	tracesPath := writeTempFile(t, "traces.yaml", `
version: 1
cases:
  - name: "wrong expectation"
    action: {type: fs_write, path: /etc/passwd}
    want: allow
`)

	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"test", policyPath, tracesPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 for a failing case, got %d", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("FAIL")) {
		t.Errorf("expected a FAIL line, got:\n%s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("0 passed, 1 failed")) {
		t.Errorf("expected summary line, got:\n%s", stdout.String())
	}
}

func TestRunPolicyTestBadArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"test", "onlyone.yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected usage exit code 2, got %d", code)
	}
}

func TestRunPolicyTestMissingTraceFile(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", policyTestSamplePolicy)
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"test", policyPath, "/nonexistent/traces.yaml"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 for a missing trace file, got %d", code)
	}
}

// TestRunPolicyRecordProducesSuiteThatPasses drives real decisions through
// a live daemon, records them, and feeds the recording straight back into
// `policy test` against the same policy: the recorded expectations must be
// exactly what the engine decides, so every case passes.
func TestRunPolicyRecordProducesSuiteThatPasses(t *testing.T) {
	socketPath, d := startTestDaemonForCLI(t)
	d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", RunID: "run-rec", Action: engine.Action{Type: engine.ActionShell, Command: "git status"}})
	d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", RunID: "run-rec", Action: engine.Action{Type: engine.ActionShell, Command: "curl evil.com"}})
	d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", RunID: "other", Action: engine.Action{Type: engine.ActionFunction, Name: "f", Args: map[string]any{"n": 1}}})
	// An approval-gated action must be recorded as the engine's own decision
	// (require_approval), not the human's resolution of it. Resolve it here
	// rather than waiting out the policy's default 300s approval timeout.
	done := make(chan daemon.EvaluateResult, 1)
	go func() {
		done <- d.Evaluate(daemon.DecisionRequest{Actor: "agent-1", RunID: "run-rec", Action: engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"}})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(d.Approvals.List()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	pending := d.Approvals.List()
	if len(pending) != 1 {
		t.Fatal("the rm -rf evaluation never became pending")
	}
	if err := d.Deny(pending[0].ID); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if res := <-done; res.Decision.Result != engine.Deny || res.ApprovalID == "" {
		t.Fatalf("expected the denied approval to resolve Deny with an approval id, got %+v", res)
	}

	tracesPath := filepath.Join(t.TempDir(), "recorded.traces.yaml")
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"record", "-socket", socketPath, "-output", tracesPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("record: exit %d\nstderr: %s", code, stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("recorded 4 case(s)")) {
		t.Errorf("expected 4 recorded cases, got: %s", stderr.String())
	}
	suite, err := engine.LoadTestSuite(tracesPath)
	if err != nil {
		t.Fatalf("the recorded file must be a valid trace file: %v", err)
	}
	if got := suite.Cases[3]; got.Want != engine.RequireApproval || got.Action.Command != "rm -rf /workspace/build" {
		t.Errorf("expected the approval-gated command recorded as want: require_approval, got %+v", got)
	}
	if got := suite.Cases[2]; got.Action.Args["n"] != 1 {
		t.Errorf("expected function args to be recorded, got %+v", got.Action.Args)
	}

	// Replaying against the same policy passes every case.
	policyPath := writeTempFile(t, "policy.yaml", cliTestPolicy)
	stdout.Reset()
	stderr.Reset()
	if code := runPolicy([]string{"test", policyPath, tracesPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("replaying the recording must pass, exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("4 passed, 0 failed")) {
		t.Errorf("expected all recorded cases to pass, got:\n%s", stdout.String())
	}

	// Filters narrow what is recorded, using the same flags as `audit query`.
	stdout.Reset()
	stderr.Reset()
	if code := runPolicy([]string{"record", "-socket", socketPath, "-run", "run-rec", "-decision", "deny"}, &stdout, &stderr); code != 0 {
		t.Fatalf("record with filters: exit %d\n%s", code, stderr.String())
	}
	filtered, err := engine.ParseTestSuite(stdout.Bytes())
	if err != nil {
		t.Fatalf("filtered recording on stdout must parse: %v\n%s", err, stdout.String())
	}
	if len(filtered.Cases) != 2 {
		t.Errorf("expected the two denied commands in run-rec (curl, timed-out rm), got %+v", filtered.Cases)
	}
}

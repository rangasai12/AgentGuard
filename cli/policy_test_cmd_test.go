package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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

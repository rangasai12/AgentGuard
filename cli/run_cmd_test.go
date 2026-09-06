//go:build darwin

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRunCmdRestrictsFilesystemWrites(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	policyPath := writeTempFile(t, "policy.yaml", `
version: 1
filesystem:
  - allow: read_write
    paths: ["`+workspace+`/**"]
`)

	var stdout, stderr bytes.Buffer
	code := runRunCmd([]string{"--policy", policyPath, "--", "sh", "-c", "echo ok > '" + filepath.Join(workspace, "ok.txt") + "'"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 for an allowed write, got %d (stderr: %s)", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workspace, "ok.txt")); err != nil {
		t.Errorf("expected the write to succeed: %v", err)
	}

	blocked := filepath.Join(dir, "blocked.txt")
	code = runRunCmd([]string{"--policy", policyPath, "--", "sh", "-c", "echo no > '" + blocked + "'"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected a non-zero exit for a write outside the allowed workspace")
	}
	if _, err := os.Stat(blocked); err == nil {
		t.Error("expected the write outside the workspace to be blocked")
	}
}

func TestRunRunCmdMissingCommand(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", "version: 1\n")
	var stdout, stderr bytes.Buffer
	code := runRunCmd([]string{"--policy", policyPath}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected usage exit code 2, got %d", code)
	}
}

func TestRunRunCmdWarnsWithoutProxyAddr(t *testing.T) {
	policyPath := writeTempFile(t, "policy.yaml", "version: 1\nnetwork:\n  default: deny\n")
	var stdout, stderr bytes.Buffer
	code := runRunCmd([]string{"--policy", policyPath, "--", "true"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("warning")) {
		t.Errorf("expected a warning about missing --proxy-addr, got stderr: %s", stderr.String())
	}
}

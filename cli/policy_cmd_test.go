package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunPolicyValidateAcceptsGoodPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nname: test\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"validate", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("OK")) {
		t.Errorf("expected OK message, got %q", stdout.String())
	}
}

func TestRunPolicyValidateRejectsBadPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("version: 99\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"validate", path}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit for an invalid policy")
	}
	if stderr.Len() == 0 {
		t.Error("expected an error message on stderr")
	}
}

func TestRunPolicyValidateMissingArgs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runPolicy([]string{"validate"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected usage exit code 2, got %d", code)
	}
}

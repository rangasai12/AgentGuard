package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"agentguard/engine"
)

func TestRunInitWritesValidPolicy(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "policy.yaml")

	var stdout, stderr bytes.Buffer
	code := runInit([]string{"--output", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}

	if _, err := engine.LoadPolicy(out); err != nil {
		t.Fatalf("generated starter policy does not parse: %v", err)
	}
}

func TestRunInitRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(out, []byte("existing"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runInit([]string{"--output", out}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit when the output file already exists")
	}
	data, _ := os.ReadFile(out)
	if string(data) != "existing" {
		t.Error("existing file must not be overwritten")
	}
}

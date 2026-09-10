package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# a comment\n\nOPENAI_API_KEY=sk-test-123\nQUOTED=\"hello world\"\nSINGLE_QUOTED='hi'\nno_equals_sign\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test .env: %v", err)
	}

	for _, key := range []string{"OPENAI_API_KEY", "QUOTED", "SINGLE_QUOTED", "ALREADY_SET"} {
		os.Unsetenv(key)
		t.Cleanup(func() { os.Unsetenv(key) })
	}
	t.Setenv("ALREADY_SET", "from-real-env")

	loadDotEnv(path)

	if got := os.Getenv("OPENAI_API_KEY"); got != "sk-test-123" {
		t.Errorf("OPENAI_API_KEY = %q, want sk-test-123", got)
	}
	if got := os.Getenv("QUOTED"); got != "hello world" {
		t.Errorf("QUOTED = %q, want unquoted \"hello world\"", got)
	}
	if got := os.Getenv("SINGLE_QUOTED"); got != "hi" {
		t.Errorf("SINGLE_QUOTED = %q, want hi", got)
	}
}

func TestLoadDotEnvNeverOverridesARealEnvVar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("ALREADY_SET=from-file\n"), 0o600); err != nil {
		t.Fatalf("writing test .env: %v", err)
	}
	t.Setenv("ALREADY_SET", "from-real-env")

	loadDotEnv(path)

	if got := os.Getenv("ALREADY_SET"); got != "from-real-env" {
		t.Errorf("ALREADY_SET = %q, a real env var must win over the .env file", got)
	}
}

func TestLoadDotEnvMissingFileIsANoOp(t *testing.T) {
	loadDotEnv(filepath.Join(t.TempDir(), "does-not-exist.env")) // must not panic or error out
}

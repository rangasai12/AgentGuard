//go:build !darwin

package hardened

import (
	"context"
	"errors"
	"testing"

	"agentguard/engine"
)

// These run only when actually compiled for a non-darwin GOOS. In this
// project's development environment (macOS), they are exercised only via
// cross-compilation (`GOOS=linux go build ./...`), which proves the stub
// compiles and satisfies the same signatures as darwin.go, but does not
// execute them — there is no CI or Linux host running this file's tests
// today. Documented as a real, acknowledged verification gap in CHANGELOG.md.

func TestCompileProfileFailsClearly(t *testing.T) {
	p, _ := engine.ParsePolicy([]byte("version: 1\n"))
	_, err := CompileProfile(p, "")
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("expected ErrUnsupportedPlatform, got %v", err)
	}
}

func TestRunFailsClearly(t *testing.T) {
	p, _ := engine.ParsePolicy([]byte("version: 1\n"))
	err := Run(context.Background(), p, "", "true", nil, nil, nil, nil)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("expected ErrUnsupportedPlatform, got %v", err)
	}
}

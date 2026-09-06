package approval

import (
	"testing"
	"time"

	"agentguard/engine"
)

func TestPromptTTYDoesNotHangAndFailsSafeWithNoAnswer(t *testing.T) {
	// Whether /dev/tty is unavailable (no controlling terminal, e.g. under a
	// test runner or CI) or available but nobody types an answer within the
	// timeout, PromptTTY must return "" — never block past the timeout —
	// so callers reliably fall back to the policy's on_timeout setting.
	timeout := 50 * time.Millisecond
	start := time.Now()
	result := PromptTTY(engine.Action{Type: engine.ActionShell, Command: "rm -rf /"}, engine.Decision{MatchedRule: "test"}, timeout)
	elapsed := time.Since(start)

	if result != "" {
		t.Errorf("expected no answer to yield \"\", got %q", result)
	}
	if elapsed > 2*time.Second {
		t.Errorf("PromptTTY took %s, expected it to return at or shortly after the %s timeout", elapsed, timeout)
	}
}

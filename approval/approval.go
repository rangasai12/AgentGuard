// Package approval provides the "ask a human" primitive shared by every
// standalone enforcement point that can block on a REQUIRE_APPROVAL decision
// without a central daemon coordinating it (the MCP proxy, the network
// proxy): prompting directly on the controlling terminal, independent of
// whatever stdio the enforcement point itself is relaying.
package approval

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"agentguard/engine"
)

// Func is called for an action that requires approval. It returns
// engine.Allow or engine.Deny, or "" if no decision could be reached (e.g.
// no interactive terminal is available), in which case callers should fall
// back to the policy's on_timeout setting.
type Func func(action engine.Action, decision engine.Decision, timeout time.Duration) engine.Result

// PromptTTY prompts on /dev/tty, independent of the caller's own
// stdin/stdout (typically dedicated to relaying a proxied protocol and
// unusable as an approval prompt). Returns "" if no controlling terminal is
// available. Async approval (Slack/webhook, or delegating to a shared
// daemon) is planned for v0.2; this is deliberately the only mechanism in
// v0.1.
func PromptTTY(action engine.Action, decision engine.Decision, timeout time.Duration) engine.Result {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return ""
	}
	defer tty.Close()

	fmt.Fprintf(tty, "\n[agentguard] approval required: %s %s\n  matched rule: %s\n", action.Type, action.Resource(), decision.MatchedRule)
	if decision.Reason != "" {
		fmt.Fprintf(tty, "  reason: %s\n", decision.Reason)
	}
	fmt.Fprintf(tty, "allow this action? [y/N] (times out in %s): ", timeout)

	answered := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(tty).ReadString('\n')
		answered <- strings.TrimSpace(strings.ToLower(line))
	}()

	select {
	case ans := <-answered:
		if ans == "y" || ans == "yes" {
			return engine.Allow
		}
		return engine.Deny
	case <-time.After(timeout):
		fmt.Fprintln(tty, "\n[agentguard] approval timed out")
		return ""
	}
}

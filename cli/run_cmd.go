package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"agentguard/engine"
	"agentguard/hardened"
)

// runRunCmd implements `agentctl run`: OS-level hardened mode, running an
// agent's own process under a kernel/OS sandbox derived from policy.yaml —
// defense-in-depth for code that bypasses the SDK/MCP/proxy layers entirely
// (writes files directly, opens raw sockets). See hardened.CompileProfile
// for the (deliberately narrow) scope: filesystem writes and network only,
// macOS only in this version.
func runRunCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "policy.yaml", "path to the policy file")
	proxyAddr := fs.String("proxy-addr", "", "address of a running `agentctl proxy start` instance; if set, only outbound connections to it are allowed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: agentctl run --policy policy.yaml [--proxy-addr 127.0.0.1:8080] -- <command> [args...]")
		return 2
	}

	policy, err := engine.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl run: loading policy: %v\n", err)
		return 1
	}

	if policy.HasNetworkRules() && *proxyAddr == "" {
		fmt.Fprintln(stderr, "agentctl run: warning: policy configures network rules but no --proxy-addr was given — all network access will be denied for this process")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := hardened.Run(ctx, policy, *proxyAddr, rest[0], rest[1:], os.Stdin, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "agentctl run: %v\n", err)
		return 1
	}
	return 0
}

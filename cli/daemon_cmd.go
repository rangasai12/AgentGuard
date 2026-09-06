package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"syscall"

	"agentguard/daemon"
	"agentguard/engine"
)

func runDaemonCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "start" {
		fmt.Fprintln(stderr, "usage: agentctl daemon start [--policy policy.yaml] [--socket path] [--audit path]")
		return 2
	}

	fs := flag.NewFlagSet("daemon start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "policy.yaml", "path to the policy file")
	socketPath := fs.String("socket", DefaultSocketPath(), "unix socket path to listen on")
	auditPath := fs.String("audit", DefaultAuditLogPath(), "path to the JSONL audit log")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	policy, err := engine.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl daemon: loading policy: %v\n", err)
		return 1
	}
	if err := EnsureParentDir(*socketPath); err != nil {
		fmt.Fprintf(stderr, "agentctl daemon: preparing socket directory: %v\n", err)
		return 1
	}
	if err := EnsureParentDir(*auditPath); err != nil {
		fmt.Fprintf(stderr, "agentctl daemon: preparing audit log directory: %v\n", err)
		return 1
	}
	audit, err := daemon.NewAuditLogger(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl daemon: opening audit log: %v\n", err)
		return 1
	}
	defer audit.Close()

	d := daemon.New(policy, audit)
	if url := policy.Escalation.WebhookURL; url != "" {
		d.Notify = daemon.WebhookNotifier(url, nil, func(err error) {
			fmt.Fprintf(stderr, "agentguard daemon: webhook notification failed: %v\n", err)
		})
		fmt.Fprintf(stdout, "approval notifications will be posted to %s\n", url)
	}

	fmt.Fprintf(stdout, "agentguard daemon listening on %s (policy: %s, audit: %s)\n", *socketPath, *policyPath, *auditPath)
	fmt.Fprintln(stdout, "press Ctrl-C to stop")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := daemon.Serve(ctx, *socketPath, d); err != nil {
		fmt.Fprintf(stderr, "agentctl daemon: %v\n", err)
		return 1
	}
	return 0
}

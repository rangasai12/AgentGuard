package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"agentguard/daemon"
	"agentguard/engine"
	mcpproxy "agentguard/proxy/mcp"
)

func runMCPProxy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "policy.yaml", "path to the policy file")
	serverName := fs.String("server", "", "logical MCP server name for policy matching (defaults to the command's base name)")
	auditPath := fs.String("audit", DefaultAuditLogPath(), "path to the JSONL audit log")
	actor := fs.String("actor", "", "actor name recorded in audit events")
	runID := fs.String("run-id", os.Getenv("AGENTGUARD_RUN_ID"), "run id recorded in audit events (default $AGENTGUARD_RUN_ID, as set by an SDK-wrapped parent process)")
	agentVersion := fs.String("agent-version", os.Getenv("AGENTGUARD_AGENT_VERSION"), "agent version recorded in audit events (default $AGENTGUARD_AGENT_VERSION)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: agentctl mcp-proxy --policy policy.yaml [--server name] -- <mcp-server-command> [args...]")
		return 2
	}

	policy, err := engine.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl mcp-proxy: loading policy: %v\n", err)
		return 1
	}

	name := *serverName
	if name == "" {
		name = filepath.Base(rest[0])
	}

	if err := EnsureParentDir(*auditPath); err != nil {
		fmt.Fprintf(stderr, "agentctl mcp-proxy: preparing audit log directory: %v\n", err)
		return 1
	}
	audit, err := daemon.NewAuditLogger(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl mcp-proxy: opening audit log: %v\n", err)
		return 1
	}
	defer audit.Close()

	proxy := mcpproxy.New(policy, audit, name, *actor)
	proxy.RunID, proxy.AgentVersion = *runID, *agentVersion

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := proxy.RunCommand(ctx, rest[0], rest[1:], os.Stdin, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "agentctl mcp-proxy: %v\n", err)
		return 1
	}
	return 0
}

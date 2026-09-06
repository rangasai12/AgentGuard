// Package cli implements the agentctl command-line tool: policy validation,
// running the local daemon, inspecting/resolving audit and approval state,
// and the MCP proxy entry point. cmd/agentctl/main.go is a thin wrapper
// around Run so the actual logic stays testable without spawning processes.
package cli

import (
	"fmt"
	"io"
)

// Run dispatches args[0] to a subcommand and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return runInit(rest, stdout, stderr)
	case "policy":
		return runPolicy(rest, stdout, stderr)
	case "daemon":
		return runDaemonCmd(rest, stdout, stderr)
	case "audit":
		return runAudit(rest, stdout, stderr)
	case "approve":
		return runApproveOrDeny(rest, stdout, stderr, "approve")
	case "deny":
		return runApproveOrDeny(rest, stdout, stderr, "deny")
	case "pending":
		return runPending(rest, stdout, stderr)
	case "mcp-proxy":
		return runMCPProxy(rest, stdout, stderr)
	case "proxy":
		return runProxy(rest, stdout, stderr)
	case "run":
		return runRunCmd(rest, stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "agentctl: unknown command %q\n\n", cmd)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `agentctl — developer-first policy-as-code enforcement for AI agents

Usage:
  agentctl init [--output policy.yaml]
  agentctl policy validate <file>
  agentctl policy test <policy.yaml> <traces.yaml>
  agentctl daemon start [--policy policy.yaml] [--socket path] [--audit path]
  agentctl audit tail [-n 20] [--socket path]
  agentctl audit query [--type TYPE] [--decision allow|deny|require_approval] [--actor NAME] [--socket path]
  agentctl approve <id> [--socket path]
  agentctl deny <id> [--socket path]
  agentctl pending [--socket path]
  agentctl mcp-proxy --policy policy.yaml [--server name] [--audit path] -- <mcp-server-command> [args...]
  agentctl proxy start [--policy policy.yaml] [--addr 127.0.0.1:8080] [--ca-cert path] [--ca-key path]
  agentctl proxy ca [--export path]
  agentctl run --policy policy.yaml [--proxy-addr 127.0.0.1:8080] -- <command> [args...]
`)
}

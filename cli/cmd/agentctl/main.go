// Command agentctl is the AgentGuard CLI: policy validation, the local
// daemon, audit inspection, approval resolution, and the MCP proxy.
package main

import (
	"os"

	"github.com/rangasai12/AgentGuard/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}

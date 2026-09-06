package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"agentguard/daemon"
)

// runPending lists actions currently blocked awaiting a human decision, so a
// human knows which id to pass to `agentctl approve`/`deny`. Without this,
// the only way to discover a pending approval's id is the webhook/Slack
// notifier path (daemon/webhook.go) — this covers the plain CLI-only case.
func runPending(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pending", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", DefaultSocketPath(), "unix socket path")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	client, err := Dial(*socketPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()

	resp, err := client.Call(daemon.Request{Cmd: "pending_approvals"})
	if err != nil {
		fmt.Fprintf(stderr, "agentctl pending: %v\n", err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintf(stderr, "agentctl pending: daemon error: %s\n", resp.Error)
		return 1
	}
	if len(resp.Pending) == 0 {
		fmt.Fprintln(stdout, "(no pending approvals)")
		return 0
	}
	for _, p := range resp.Pending {
		reason := p.Reason
		if reason == "" {
			reason = p.MatchedRule
		}
		fmt.Fprintf(stdout, "%s  %-16s  %-12s  %-30s  age=%-8s  %s\n",
			p.ID, p.Action.Type, p.Actor, p.Action.Resource(), time.Since(p.CreatedAt).Round(time.Second), reason)
	}
	return 0
}

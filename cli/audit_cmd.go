package cli

import (
	"flag"
	"fmt"
	"io"
	"time"

	"agentguard/daemon"
	"agentguard/engine"
)

func runAudit(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: agentctl audit <tail|query> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet("audit "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", DefaultSocketPath(), "unix socket path")
	n := fs.Int("n", 20, "number of events to show (tail)")
	actionType := fs.String("type", "", "filter by action type (query)")
	decision := fs.String("decision", "", "filter by decision: allow|deny|require_approval (query)")
	actor := fs.String("actor", "", "filter by actor (query)")

	var req daemon.Request
	switch sub {
	case "tail":
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		req = daemon.Request{Cmd: "audit_tail", N: *n}
	case "query":
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		req = daemon.Request{Cmd: "audit_query", Filter: daemon.AuditFilter{
			ActionType: engine.ActionType(*actionType),
			Decision:   engine.Result(*decision),
			Actor:      *actor,
		}}
	default:
		fmt.Fprintln(stderr, "usage: agentctl audit <tail|query> [flags]")
		return 2
	}

	client, err := Dial(*socketPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()

	resp, err := client.Call(req)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl audit: %v\n", err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintf(stderr, "agentctl audit: daemon error: %s\n", resp.Error)
		return 1
	}
	if len(resp.Events) == 0 {
		fmt.Fprintln(stdout, "(no events)")
		return 0
	}
	for _, ev := range resp.Events {
		fmt.Fprintf(stdout, "%s  %-16s  %-9s  %-30s  %s\n",
			ev.Timestamp.Format(time.RFC3339), ev.ActionType, ev.Decision, ev.Resource, ev.MatchedRule)
	}
	return 0
}

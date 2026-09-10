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
	filter := addAuditFilterFlags(fs, "(query)")

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
		req = daemon.Request{Cmd: "audit_query", Filter: filter()}
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
		outcome := "-"
		if ev.Outcome != nil {
			outcome = fmt.Sprintf("%s/%dms", ev.Outcome.Status, ev.Outcome.ExecMS)
		}
		fmt.Fprintf(stdout, "%s  %-16s  %-9s  %-30s  %-14s  %s\n",
			ev.Timestamp.Format(time.RFC3339), ev.ActionType, ev.Decision, ev.Resource, outcome, ev.MatchedRule)
	}
	return 0
}

// addAuditFilterFlags registers the flags that narrow an audit_query
// (--type, --decision, --actor, --run) on fs and returns a function that
// builds the daemon.AuditFilter from them once fs is parsed. Shared by
// `agentctl audit query` and `agentctl policy record` so both commands
// accept exactly the same filters.
func addAuditFilterFlags(fs *flag.FlagSet, suffix string) func() daemon.AuditFilter {
	actionType := fs.String("type", "", "filter by action type "+suffix)
	decision := fs.String("decision", "", "filter by decision: allow|deny|require_approval "+suffix)
	actor := fs.String("actor", "", "filter by actor "+suffix)
	runID := fs.String("run", "", "filter by run id "+suffix)
	return func() daemon.AuditFilter {
		return daemon.AuditFilter{
			ActionType: engine.ActionType(*actionType),
			Decision:   engine.Result(*decision),
			Actor:      *actor,
			RunID:      *runID,
		}
	}
}

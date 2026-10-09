package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rangasai12/AgentGuard/daemon"
	"github.com/rangasai12/AgentGuard/engine"
)

func runAudit(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: agentctl audit <tail|query|verify> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	if sub == "verify" {
		return runAuditVerify(rest, stdout, stderr)
	}

	fs := flag.NewFlagSet("audit "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", DefaultSocketPath("policy.yaml"), "unix socket path (default: derived from ./policy.yaml, matching `daemon start`'s default)")
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
		fmt.Fprintln(stderr, "usage: agentctl audit <tail|query|verify> [flags]")
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
		decision := string(ev.Decision)
		if ev.ShadowDecision != "" {
			decision += " (shadow: would " + string(ev.ShadowDecision) + ")"
		}
		fmt.Fprintf(stdout, "%s  %-16s  %-9s  %-30s  %-14s  %s\n",
			ev.Timestamp.Format(time.RFC3339), ev.ActionType, decision, ev.Resource, outcome, ev.MatchedRule)
	}
	return 0
}

// runAuditVerify implements `agentctl audit verify`: it reads the audit log
// file directly (no daemon needed — the point is to check the file, not what
// a running process says about it) and checks its hash chain.
func runAuditVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "policy.yaml", "policy file whose default audit log to check")
	auditPath := fs.String("audit", "", "path to the JSONL audit log (default: derived from --policy)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" {
		*auditPath = DefaultAuditLogPath(*policyPath)
	}
	f, err := os.Open(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl audit verify: %v\n", err)
		return 1
	}
	defer f.Close()
	rep, err := daemon.VerifyAuditLog(f)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl audit verify: reading %s: %v\n", *auditPath, err)
		return 1
	}
	if rep.BrokenAt > 0 {
		fmt.Fprintf(stdout, "BROKEN  %s line %d: %s\n", *auditPath, rep.BrokenAt, rep.Problem)
		return 1
	}
	fmt.Fprintf(stdout, "OK  %s: %d line(s), chain intact\n", *auditPath, rep.Lines)
	if rep.Unchained > 0 {
		fmt.Fprintf(stdout, "    %d line(s) at the start predate chaining and are not tamper-evident\n", rep.Unchained)
	}
	if rep.Head != "" {
		fmt.Fprintf(stdout, "    head %s (record it elsewhere; a later verify with a different history means lines were removed from the end)\n", rep.Head)
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

package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"agentguard/daemon"
	"agentguard/engine"

	"gopkg.in/yaml.v3"
)

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: agentctl policy <validate|test|record> [args]")
		return 2
	}
	switch args[0] {
	case "validate":
		return runPolicyValidate(args[1:], stdout, stderr)
	case "test":
		return runPolicyTest(args[1:], stdout, stderr)
	case "record":
		return runPolicyRecord(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: agentctl policy <validate|test|record> [args]")
		return 2
	}
}

func runPolicyValidate(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: agentctl policy validate <file>")
		return 2
	}
	path := args[0]

	p, err := engine.LoadPolicy(path)
	if err != nil {
		fmt.Fprintf(stderr, "policy invalid: %v\n", err)
		return 1
	}

	name := p.Name
	if name == "" {
		name = "(unnamed)"
	}
	fmt.Fprintf(stdout, "OK: %s is a valid policy — %s\n", path, name)
	return 0
}

// runPolicyTest implements `agentctl policy test <policy.yaml> <traces.yaml>`:
// a dry-run harness that evaluates a trace file's cases against a policy and
// reports pass/fail per case, exiting non-zero if any fail — so a policy
// change can be regression-tested in CI the same way any other code is,
// instead of the first sign of a mistake being a real agent hitting it.
func runPolicyTest(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: agentctl policy test <policy.yaml> <traces.yaml>")
		return 2
	}
	policyPath, tracesPath := args[0], args[1]

	policy, err := engine.LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl policy test: loading policy: %v\n", err)
		return 1
	}
	suite, err := engine.LoadTestSuite(tracesPath)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl policy test: loading trace file: %v\n", err)
		return 1
	}

	results := engine.RunTestSuite(policy, suite)
	failed := 0
	for _, r := range results {
		if r.Pass {
			fmt.Fprintf(stdout, "PASS  %s\n", r.Case.Name)
			continue
		}
		failed++
		fmt.Fprintf(stdout, "FAIL  %s (want %s, got %s — %s)\n", r.Case.Name, r.Case.Want, r.Got.Result, r.Got.MatchedRule)
	}

	fmt.Fprintf(stdout, "\n%d passed, %d failed, %d total\n", len(results)-failed, failed, len(results))
	if failed > 0 {
		return 1
	}
	return 0
}

// runPolicyRecord implements `agentctl policy record`: it turns recent
// audit events — real decisions the daemon actually made — into a
// `policy test` trace file, so a policy can be regression-tested against
// what the agent really did rather than against hand-written guesses.
// The typical loop: run the agent, `policy record --output traces.yaml`,
// review the recorded expectations, commit them, and every later policy
// change is checked against them in CI.
//
// Only events that carry a structured action are recordable (older log
// lines and outcome patch lines are skipped and counted). The expected
// decision is the engine's own: an event that went through an approval is
// recorded as `want: require_approval`, since that is what the engine
// decided before a human resolved it. Arguments appear as they were
// logged, so anything redacted by audit.redact_args replays as
// "[redacted]" — a condition on such an argument will not reproduce.
func runPolicyRecord(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy record", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socketPath := fs.String("socket", DefaultSocketPath(), "unix socket path")
	output := fs.String("output", "", "write the trace file here (default: stdout)")
	limit := fs.Int("n", 100, "maximum number of events to record (most recent first)")
	filter := addAuditFilterFlags(fs, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	client, err := Dial(*socketPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()

	f := filter()
	f.Limit = *limit
	resp, err := client.Call(daemon.Request{Cmd: "audit_query", Filter: f})
	if err != nil {
		fmt.Fprintf(stderr, "agentctl policy record: %v\n", err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintf(stderr, "agentctl policy record: daemon error: %s\n", resp.Error)
		return 1
	}

	suite := engine.TestSuite{Version: 1}
	skipped := 0
	seen := map[string]bool{}
	for i := len(resp.Events) - 1; i >= 0; i-- { // oldest first reads naturally in the file
		ev := resp.Events[i]
		if ev.Action == nil || ev.Kind != "" {
			skipped++
			continue
		}
		want := ev.Decision
		if ev.ApprovalID != "" {
			want = engine.RequireApproval
		}
		name := ev.Timestamp.UTC().Format("2006-01-02T15:04:05Z") + " " + ev.EventID
		if seen[name] {
			skipped++
			continue
		}
		seen[name] = true
		suite.Cases = append(suite.Cases, engine.TestCase{Name: name, Action: *ev.Action, Want: want})
	}

	data, err := yaml.Marshal(suite)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl policy record: encoding trace file: %v\n", err)
		return 1
	}
	header := "# Recorded by `agentctl policy record` from the daemon's audit log.\n# Review the `want:` values, then keep this file under version control and run\n# `agentctl policy test policy.yaml <this file>` in CI.\n"
	if *output == "" {
		fmt.Fprint(stdout, header+string(data))
	} else if err := os.WriteFile(*output, []byte(header+string(data)), 0o644); err != nil {
		fmt.Fprintf(stderr, "agentctl policy record: writing %s: %v\n", *output, err)
		return 1
	}
	fmt.Fprintf(stderr, "recorded %d case(s)", len(suite.Cases))
	if skipped > 0 {
		fmt.Fprintf(stderr, " (skipped %d event(s) without a structured action)", skipped)
	}
	if *output != "" {
		fmt.Fprintf(stderr, " to %s", *output)
	}
	fmt.Fprintln(stderr)
	return 0
}

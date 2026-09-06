package cli

import (
	"fmt"
	"io"

	"agentguard/engine"
)

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: agentctl policy <validate|test> [args]")
		return 2
	}
	switch args[0] {
	case "validate":
		return runPolicyValidate(args[1:], stdout, stderr)
	case "test":
		return runPolicyTest(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: agentctl policy <validate|test> [args]")
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

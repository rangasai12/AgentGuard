package engine

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// TestCase is one action-to-expected-decision assertion against a policy,
// as parsed from a trace file. This is what `agentctl policy test` runs —
// letting a team regression-test their policy.yaml in CI the same way they
// test any other code, instead of discovering a policy mistake in
// production the first time an agent hits it.
type TestCase struct {
	Name   string `yaml:"name"`
	Action Action `yaml:"action"`
	Want   Result `yaml:"want"`
}

// TestSuite is a parsed trace file: a named list of TestCases to run
// against a policy.
type TestSuite struct {
	Version int        `yaml:"version"`
	Cases   []TestCase `yaml:"cases"`
}

// ParseTestSuite parses a trace file from YAML bytes and validates it.
func ParseTestSuite(data []byte) (*TestSuite, error) {
	var s TestSuite
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing test suite YAML: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("unsupported test suite version %d (expected 1)", s.Version)
	}
	seen := make(map[string]bool, len(s.Cases))
	for i, c := range s.Cases {
		if c.Name == "" {
			return nil, fmt.Errorf("case %d: name is required", i)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("case %q: duplicate name", c.Name)
		}
		seen[c.Name] = true
		switch c.Want {
		case Allow, Deny, RequireApproval:
		default:
			return nil, fmt.Errorf("case %q: invalid want %q (expected allow, deny, or require_approval)", c.Name, c.Want)
		}
		if c.Action.Type == "" {
			return nil, fmt.Errorf("case %q: action.type is required", c.Name)
		}
	}
	return &s, nil
}

// LoadTestSuite reads and parses a trace file from disk.
func LoadTestSuite(path string) (*TestSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading test suite file %s: %w", path, err)
	}
	return ParseTestSuite(data)
}

// TestResult is the outcome of running one TestCase against a Policy.
type TestResult struct {
	Case TestCase
	Got  Decision
	Pass bool
}

// RunTestSuite evaluates every case in suite against policy, in order.
func RunTestSuite(policy *Policy, suite *TestSuite) []TestResult {
	results := make([]TestResult, 0, len(suite.Cases))
	for _, c := range suite.Cases {
		got := Evaluate(policy, c.Action)
		results = append(results, TestResult{Case: c, Got: got, Pass: got.Result == c.Want})
	}
	return results
}

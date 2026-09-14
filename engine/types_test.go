package engine

import (
	"strings"
	"testing"
)

func TestActionResource(t *testing.T) {
	cases := []struct {
		action Action
		want   string
	}{
		{Action{Type: ActionFSRead, Path: "/workspace/x"}, "/workspace/x"},
		{Action{Type: ActionNetwork, Method: "GET", Domain: "api.github.com"}, "GET api.github.com"},
		{Action{Type: ActionNetwork, Domain: "api.github.com"}, "api.github.com"},
		{Action{Type: ActionShell, Command: "git status"}, "git status"},
		{Action{Type: ActionMCPTool, Server: "payments-mcp", Tool: "charge_customer"}, "payments-mcp.charge_customer"},
		{Action{Type: ActionSecretEnv, EnvVar: "HOME"}, "HOME"},
		{Action{Type: ActionFunction, Name: "charge_customer", Args: map[string]any{"amount": 1500}}, "charge_customer"},
	}
	for _, c := range cases {
		if got := c.action.Resource(); got != c.want {
			t.Errorf("Resource() = %q, want %q", got, c.want)
		}
	}
}

// TestActionValidateRequiresFieldPerType covers every action type's required
// field(s) — the same "empty action field is silently unmatchable" shape
// found for network's Method generalizes to every type (see decision.go's
// Evaluate, which now calls Validate before any type-specific evaluator).
func TestActionValidateRequiresFieldPerType(t *testing.T) {
	cases := []struct {
		name      string
		action    Action
		wantValid bool
	}{
		{"fs_write with path is valid", Action{Type: ActionFSWrite, Path: "/workspace/x"}, true},
		{"fs_read with empty path is invalid", Action{Type: ActionFSRead}, false},
		{"network with domain and method is valid", Action{Type: ActionNetwork, Domain: "api.github.com", Method: "GET"}, true},
		{"network with empty method is invalid", Action{Type: ActionNetwork, Domain: "api.github.com"}, false},
		{"network with empty domain is invalid", Action{Type: ActionNetwork, Method: "GET"}, false},
		{"shell with command is valid", Action{Type: ActionShell, Command: "git status"}, true},
		{"shell with empty command is invalid", Action{Type: ActionShell}, false},
		{"mcp_tool with server and tool is valid", Action{Type: ActionMCPTool, Server: "s", Tool: "t"}, true},
		{"mcp_tool with empty tool is invalid", Action{Type: ActionMCPTool, Server: "s"}, false},
		{"mcp_tool with empty server is invalid", Action{Type: ActionMCPTool, Tool: "t"}, false},
		{"function with name is valid", Action{Type: ActionFunction, Name: "charge"}, true},
		{"function with empty name is invalid", Action{Type: ActionFunction}, false},
		{"secret_env with env_var is valid", Action{Type: ActionSecretEnv, EnvVar: "HOME"}, true},
		{"secret_env with empty env_var is invalid", Action{Type: ActionSecretEnv}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.action.Validate()
			if c.wantValid && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
			if !c.wantValid && err == nil {
				t.Error("Validate() = nil, want an error naming the missing field")
			}
		})
	}
}

// TestActionValidateRejectsEmptySecretEnvVar is the security-relevant case:
// evaluateSecret is default-*allow*, so an unvalidated empty EnvVar would be
// a silent bypass, not just a confusing error. Evaluate must deny it before
// evaluateSecret ever runs.
func TestActionValidateRejectsEmptySecretEnvVar(t *testing.T) {
	p := &Policy{Version: 1}
	got := Evaluate(p, Action{Type: ActionSecretEnv})
	if got.Result != Deny {
		t.Fatalf("expected an empty EnvVar to be denied, not %s (secret_env is default-allow for well-formed actions)", got.Result)
	}
	if !strings.Contains(got.Reason, "env_var") {
		t.Errorf("expected the deny reason to name the missing field, got %q", got.Reason)
	}
}

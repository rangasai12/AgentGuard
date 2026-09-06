package engine

import "testing"

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

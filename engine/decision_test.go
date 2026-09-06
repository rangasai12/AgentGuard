package engine

import "testing"

const testPolicyYAML = `
version: 1
name: test-policy
filesystem:
  - allow: read_write
    paths: ["/workspace/**"]
  - deny: write
    paths: ["**"]
    reason: "no writes outside workspace"
network:
  default: deny
  allow:
    - domain: "api.github.com"
      methods: ["GET"]
  deny:
    - ip_literal: true
      reason: "no raw IPs"
shell:
  default: deny
  allow:
    - pattern: "git *"
  deny:
    - pattern: "rm -rf *"
      require_approval: true
      reason: "destructive"
mcp:
  default: deny
  servers:
    - name: "payments-mcp"
      default: deny
      tools:
        - name: "list_transactions"
          allow: true
        - name: "charge_customer"
          require_approval: true
        - name: "refund_customer"
          deny: true
functions:
  default: deny
  rules:
    - name: "charge_customer"
      conditions:
        - arg: "amount"
          op: "<"
          value: 1000
      allow: true
    - name: "charge_customer"
      conditions:
        - arg: "amount"
          op: ">="
          value: 1000
      require_approval: true
      reason: "large charges need a human"
    - name: "transfer_funds"
      conditions:
        - arg: "currency"
          op: "!="
          value: "USD"
      deny: true
      reason: "only USD transfers are supported"
    - name: "list_widgets"
      allow: true
secrets:
  deny:
    - env_var: "AWS_SECRET_ACCESS_KEY"
      reason: "never"
escalation:
  approval_timeout_seconds: 60
  on_timeout: deny
`

func loadTestPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(testPolicyYAML))
	if err != nil {
		t.Fatalf("failed to parse test policy: %v", err)
	}
	return p
}

func TestFilesystem(t *testing.T) {
	p := loadTestPolicy(t)
	cases := []struct {
		name   string
		action Action
		want   Result
	}{
		{"write inside workspace allowed", Action{Type: ActionFSWrite, Path: "/workspace/main.go"}, Allow},
		{"read inside workspace allowed", Action{Type: ActionFSRead, Path: "/workspace/nested/dir/file.txt"}, Allow},
		{"write outside workspace denied", Action{Type: ActionFSWrite, Path: "/etc/passwd"}, Deny},
		{"write to unrelated dir denied by default", Action{Type: ActionFSWrite, Path: "/tmp/x"}, Deny},
		{"read outside workspace denied by default (no matching allow)", Action{Type: ActionFSRead, Path: "/etc/passwd"}, Deny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(p, c.action)
			if got.Result != c.want {
				t.Errorf("got %s (%s), want %s", got.Result, got.MatchedRule, c.want)
			}
		})
	}
}

func TestFilesystemDenyWinsOverAllow(t *testing.T) {
	// /workspace/** allows read_write, but the blanket deny-write-everywhere rule
	// is declared after it — deny must still win because deny rules are checked first.
	p := loadTestPolicy(t)
	got := Evaluate(p, Action{Type: ActionFSWrite, Path: "/workspace/../etc/shadow"})
	if got.Result != Deny {
		t.Errorf("path traversal outside workspace should be denied, got %s", got.Result)
	}
}

func TestNetwork(t *testing.T) {
	p := loadTestPolicy(t)
	cases := []struct {
		name   string
		action Action
		want   Result
	}{
		{"allowed domain+method", Action{Type: ActionNetwork, Domain: "api.github.com", Method: "GET"}, Allow},
		{"allowed domain wrong method", Action{Type: ActionNetwork, Domain: "api.github.com", Method: "DELETE"}, Deny},
		{"unlisted domain denied", Action{Type: ActionNetwork, Domain: "evil.example.com", Method: "GET"}, Deny},
		{"raw ip denied even if domain would match", Action{Type: ActionNetwork, Domain: "1.2.3.4", Method: "GET", IsIPLiteral: true}, Deny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(p, c.action)
			if got.Result != c.want {
				t.Errorf("got %s (%s), want %s", got.Result, got.MatchedRule, c.want)
			}
		})
	}
}

func TestNetworkDefaultAllow(t *testing.T) {
	p := loadTestPolicy(t)
	p.Network.Default = "allow"
	got := Evaluate(p, Action{Type: ActionNetwork, Domain: "anything.example.com", Method: "GET"})
	if got.Result != Allow {
		t.Errorf("expected default-allow network to allow unlisted domain, got %s", got.Result)
	}
}

func TestNetworkWildcardSubdomain(t *testing.T) {
	p := loadTestPolicy(t)
	p.Network.Allow = append(p.Network.Allow, NetworkAllowRule{Domain: "*.githubusercontent.com"})
	got := Evaluate(p, Action{Type: ActionNetwork, Domain: "raw.githubusercontent.com", Method: "GET"})
	if got.Result != Allow {
		t.Errorf("expected wildcard subdomain match to allow, got %s (%s)", got.Result, got.MatchedRule)
	}
	got = Evaluate(p, Action{Type: ActionNetwork, Domain: "notgithubusercontent.com", Method: "GET"})
	if got.Result != Deny {
		t.Errorf("expected non-subdomain suffix collision to NOT match wildcard, got %s", got.Result)
	}
}

func TestShell(t *testing.T) {
	p := loadTestPolicy(t)
	cases := []struct {
		name   string
		action Action
		want   Result
	}{
		{"git allowed", Action{Type: ActionShell, Command: "git commit -am wip"}, Allow},
		{"rm -rf requires approval", Action{Type: ActionShell, Command: "rm -rf /workspace/build"}, RequireApproval},
		{"unlisted command denied by default", Action{Type: ActionShell, Command: "curl http://evil.com/x"}, Deny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(p, c.action)
			if got.Result != c.want {
				t.Errorf("got %s (%s), want %s", got.Result, got.MatchedRule, c.want)
			}
		})
	}
}

func TestMCP(t *testing.T) {
	p := loadTestPolicy(t)
	cases := []struct {
		name   string
		action Action
		want   Result
	}{
		{"allowed tool", Action{Type: ActionMCPTool, Server: "payments-mcp", Tool: "list_transactions"}, Allow},
		{"require-approval tool", Action{Type: ActionMCPTool, Server: "payments-mcp", Tool: "charge_customer"}, RequireApproval},
		{"denied tool", Action{Type: ActionMCPTool, Server: "payments-mcp", Tool: "refund_customer"}, Deny},
		{"unlisted tool on known server denied by server default", Action{Type: ActionMCPTool, Server: "payments-mcp", Tool: "delete_everything"}, Deny},
		{"unknown server denied by policy default", Action{Type: ActionMCPTool, Server: "some-other-mcp", Tool: "whatever"}, Deny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(p, c.action)
			if got.Result != c.want {
				t.Errorf("got %s (%s), want %s", got.Result, got.MatchedRule, c.want)
			}
		})
	}
}

func TestSecrets(t *testing.T) {
	p := loadTestPolicy(t)
	got := Evaluate(p, Action{Type: ActionSecretEnv, EnvVar: "AWS_SECRET_ACCESS_KEY"})
	if got.Result != Deny {
		t.Errorf("expected denied secret env var to be denied, got %s", got.Result)
	}
	got = Evaluate(p, Action{Type: ActionSecretEnv, EnvVar: "HOME"})
	if got.Result != Allow {
		t.Errorf("expected unlisted env var to default-allow (intentional exception), got %s", got.Result)
	}
}

func TestFunctions(t *testing.T) {
	p := loadTestPolicy(t)
	cases := []struct {
		name   string
		action Action
		want   Result
	}{
		{
			"small charge allowed",
			Action{Type: ActionFunction, Name: "charge_customer", Args: map[string]any{"amount": 500}},
			Allow,
		},
		{
			"large charge requires approval",
			Action{Type: ActionFunction, Name: "charge_customer", Args: map[string]any{"amount": 5000}},
			RequireApproval,
		},
		{
			"boundary value uses the >= rule, not <",
			Action{Type: ActionFunction, Name: "charge_customer", Args: map[string]any{"amount": 1000}},
			RequireApproval,
		},
		{
			"non-numeric-typed amount from JSON (float64) still compares correctly",
			Action{Type: ActionFunction, Name: "charge_customer", Args: map[string]any{"amount": float64(999)}},
			Allow,
		},
		{
			"non-USD transfer denied",
			Action{Type: ActionFunction, Name: "transfer_funds", Args: map[string]any{"currency": "EUR"}},
			Deny,
		},
		{
			"USD transfer matches no rule (default-deny), since only the != USD rule exists",
			Action{Type: ActionFunction, Name: "transfer_funds", Args: map[string]any{"currency": "USD"}},
			Deny,
		},
		{
			"rule with no conditions matches regardless of args",
			Action{Type: ActionFunction, Name: "list_widgets", Args: map[string]any{"anything": "goes"}},
			Allow,
		},
		{
			"missing argument never satisfies a condition, falls through to default-deny",
			Action{Type: ActionFunction, Name: "charge_customer", Args: map[string]any{}},
			Deny,
		},
		{
			"unknown function name denied by policy default",
			Action{Type: ActionFunction, Name: "delete_everything", Args: map[string]any{}},
			Deny,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(p, c.action)
			if got.Result != c.want {
				t.Errorf("got %s (%s), want %s", got.Result, got.MatchedRule, c.want)
			}
		})
	}
}

func TestUnknownActionTypeDefaultsDeny(t *testing.T) {
	p := loadTestPolicy(t)
	got := Evaluate(p, Action{Type: "something_new"})
	if got.Result != Deny {
		t.Errorf("unknown action types must fail closed, got %s", got.Result)
	}
}

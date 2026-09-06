package engine

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// FSRule is one filesystem policy entry. Exactly one of Allow/Deny is set.
type FSRule struct {
	Allow           string   `yaml:"allow,omitempty"` // "read" | "write" | "read_write"
	Deny            string   `yaml:"deny,omitempty"`
	Paths           []string `yaml:"paths"`
	RequireApproval bool     `yaml:"require_approval,omitempty"`
	Reason          string   `yaml:"reason,omitempty"`
}

// NetworkAllowRule permits requests to Domain, optionally restricted to Methods.
type NetworkAllowRule struct {
	Domain          string   `yaml:"domain"`
	Methods         []string `yaml:"methods,omitempty"`
	RequireApproval bool     `yaml:"require_approval,omitempty"`
	Reason          string   `yaml:"reason,omitempty"`
}

// NetworkDenyRule blocks requests matching Domain and/or raw IP literals.
type NetworkDenyRule struct {
	Domain          string `yaml:"domain,omitempty"`
	IPLiteral       bool   `yaml:"ip_literal,omitempty"`
	RequireApproval bool   `yaml:"require_approval,omitempty"`
	Reason          string `yaml:"reason,omitempty"`
}

// NetworkPolicy governs `network` actions.
type NetworkPolicy struct {
	Default string             `yaml:"default,omitempty"` // "allow" | "deny", defaults to deny
	Allow   []NetworkAllowRule `yaml:"allow,omitempty"`
	Deny    []NetworkDenyRule  `yaml:"deny,omitempty"`
}

// ShellRule matches a full command string via glob Pattern.
type ShellRule struct {
	Pattern         string `yaml:"pattern"`
	RequireApproval bool   `yaml:"require_approval,omitempty"`
	Reason          string `yaml:"reason,omitempty"`
}

// ShellPolicy governs `shell` actions.
type ShellPolicy struct {
	Default string      `yaml:"default,omitempty"`
	Allow   []ShellRule `yaml:"allow,omitempty"`
	Deny    []ShellRule `yaml:"deny,omitempty"`
}

// MCPToolRule governs one named tool on one MCP server.
type MCPToolRule struct {
	Name            string `yaml:"name"`
	Allow           bool   `yaml:"allow,omitempty"`
	Deny            bool   `yaml:"deny,omitempty"`
	RequireApproval bool   `yaml:"require_approval,omitempty"`
	Reason          string `yaml:"reason,omitempty"`
}

// MCPServerRule governs one named MCP server.
type MCPServerRule struct {
	Name    string        `yaml:"name"`
	Default string        `yaml:"default,omitempty"` // overrides MCPPolicy.Default for this server
	Tools   []MCPToolRule `yaml:"tools,omitempty"`
}

// MCPPolicy governs `mcp_tool` actions.
type MCPPolicy struct {
	Default string          `yaml:"default,omitempty"`
	Servers []MCPServerRule `yaml:"servers,omitempty"`
}

// ArgCondition tests one named argument of a `function` action against Value
// using Op. Op is one of "<", "<=", ">", ">=", "=" (or "=="), "!=". Ordering
// operators ("<" etc.) require both the argument and Value to be numbers;
// equality operators compare numbers numerically and everything else
// (strings, bools) by exact match after normalizing to the same type. If the
// named Arg is absent from the action's Args, the condition is false — a
// missing argument can never satisfy a condition, it just falls through to
// the next rule/default like anything else that doesn't match.
type ArgCondition struct {
	Arg   string `yaml:"arg"`
	Op    string `yaml:"op"`
	Value any    `yaml:"value"`
}

// FunctionRule governs one named `function` action. If Conditions is empty
// it matches any call to Name regardless of arguments (pure name-based, like
// an mcp_tool rule); if non-empty, every condition must hold (AND) for the
// rule to match. Exactly one of Allow/Deny/RequireApproval should be the
// rule's primary effect (RequireApproval may also be layered onto Allow/Deny
// the way every other section does).
type FunctionRule struct {
	Name            string         `yaml:"name"`
	Conditions      []ArgCondition `yaml:"conditions,omitempty"`
	Allow           bool           `yaml:"allow,omitempty"`
	Deny            bool           `yaml:"deny,omitempty"`
	RequireApproval bool           `yaml:"require_approval,omitempty"`
	Reason          string         `yaml:"reason,omitempty"`
}

// FunctionsPolicy governs `function` actions: a generalization of `mcp_tool`
// for any named call an SDK wraps (see agentguard.Guard.function() on the
// Python side) where policy also needs to see the actual argument values,
// not just the function's name. Rules are a single ordered list, like
// `filesystem` — first matching rule wins — because argument conditions are
// typically written as partitioning ranges ("< 1000" then ">= 1000") where
// declaration order is exactly how you express which one takes priority.
type FunctionsPolicy struct {
	Default string         `yaml:"default,omitempty"` // "allow" | "deny", defaults to deny
	Rules   []FunctionRule `yaml:"rules,omitempty"`
}

// SecretRule blocks reads of one environment variable. Only deny rules exist by
// design — see the note in policy-spec/schema.yaml.
type SecretRule struct {
	EnvVar          string `yaml:"env_var"`
	RequireApproval bool   `yaml:"require_approval,omitempty"`
	Reason          string `yaml:"reason,omitempty"`
}

// SecretsPolicy governs `secret_env` actions. Unlisted env vars are allowed.
type SecretsPolicy struct {
	Deny []SecretRule `yaml:"deny,omitempty"`
}

// EscalationPolicy configures how REQUIRE_APPROVAL actions time out and,
// optionally, where a human is notified that one is pending.
type EscalationPolicy struct {
	ApprovalTimeoutSeconds int    `yaml:"approval_timeout_seconds,omitempty"`
	OnTimeout              string `yaml:"on_timeout,omitempty"` // "allow" | "deny"

	// WebhookURL, if set, receives a JSON POST (see daemon.WebhookNotifier)
	// whenever an action starts requiring approval — compatible with a
	// Slack Incoming Webhook URL as-is. This is a notification channel, not
	// a remote-approval mechanism: resolving the approval still happens via
	// `agentctl approve`/`deny` against the daemon's (local-only) socket.
	WebhookURL string `yaml:"webhook_url,omitempty"`
}

// Policy is the fully-parsed form of a policy.yaml document.
type Policy struct {
	Version    int              `yaml:"version"`
	Name       string           `yaml:"name,omitempty"`
	Filesystem []FSRule         `yaml:"filesystem,omitempty"`
	Network    NetworkPolicy    `yaml:"network,omitempty"`
	Shell      ShellPolicy      `yaml:"shell,omitempty"`
	MCP        MCPPolicy        `yaml:"mcp,omitempty"`
	Functions  FunctionsPolicy  `yaml:"functions,omitempty"`
	Secrets    SecretsPolicy    `yaml:"secrets,omitempty"`
	Escalation EscalationPolicy `yaml:"escalation,omitempty"`
}

// HasNetworkRules reports whether the policy expresses any intent to govern
// network actions at all (a default, or at least one allow/deny rule) — as
// opposed to the zero value, where the user hasn't opted into network
// policy. Used by hardened mode to decide whether to restrict network
// access at the OS level at all, not just what to allow.
func (p *Policy) HasNetworkRules() bool {
	return p.Network.Default != "" || len(p.Network.Allow) > 0 || len(p.Network.Deny) > 0
}

// ApprovalTimeoutSeconds returns the configured timeout, defaulting to 300s.
func (p *Policy) ApprovalTimeoutSeconds() int {
	if p.Escalation.ApprovalTimeoutSeconds > 0 {
		return p.Escalation.ApprovalTimeoutSeconds
	}
	return 300
}

// OnTimeoutResult returns the configured on-timeout behavior, defaulting to Deny.
func (p *Policy) OnTimeoutResult() Result {
	if p.Escalation.OnTimeout == "allow" {
		return Allow
	}
	return Deny
}

// ParsePolicy parses a policy document from raw YAML bytes and validates it.
func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadPolicy reads and parses a policy document from disk.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
	}
	return ParsePolicy(data)
}

// Validate checks structural invariants beyond what YAML unmarshaling enforces:
// required fields, enum values, and that each rule is well-formed. It does not
// mutate the policy; callers that need normalized defaults should use the
// Policy accessor methods (ApprovalTimeoutSeconds, OnTimeoutResult, etc).
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d (expected 1)", p.Version)
	}
	for i, r := range p.Filesystem {
		if (r.Allow == "") == (r.Deny == "") {
			return fmt.Errorf("filesystem rule %d: exactly one of allow/deny must be set", i)
		}
		access := r.Allow
		if access == "" {
			access = r.Deny
		}
		switch access {
		case "read", "write", "read_write":
		default:
			return fmt.Errorf("filesystem rule %d: invalid access mode %q", i, access)
		}
		if len(r.Paths) == 0 {
			return fmt.Errorf("filesystem rule %d: paths must not be empty", i)
		}
	}
	if err := validateDefault(p.Network.Default, "network"); err != nil {
		return err
	}
	for i, r := range p.Network.Allow {
		if r.Domain == "" {
			return fmt.Errorf("network.allow rule %d: domain is required", i)
		}
	}
	if err := validateDefault(p.Shell.Default, "shell"); err != nil {
		return err
	}
	for i, r := range p.Shell.Allow {
		if r.Pattern == "" {
			return fmt.Errorf("shell.allow rule %d: pattern is required", i)
		}
	}
	for i, r := range p.Shell.Deny {
		if r.Pattern == "" {
			return fmt.Errorf("shell.deny rule %d: pattern is required", i)
		}
	}
	if err := validateDefault(p.MCP.Default, "mcp"); err != nil {
		return err
	}
	for si, s := range p.MCP.Servers {
		if s.Name == "" {
			return fmt.Errorf("mcp.servers %d: name is required", si)
		}
		if err := validateDefault(s.Default, fmt.Sprintf("mcp.servers[%s]", s.Name)); err != nil {
			return err
		}
		for ti, t := range s.Tools {
			if t.Name == "" {
				return fmt.Errorf("mcp.servers[%s].tools %d: name is required", s.Name, ti)
			}
			set := 0
			if t.Allow {
				set++
			}
			if t.Deny {
				set++
			}
			if t.RequireApproval {
				set++
			}
			if set == 0 {
				return fmt.Errorf("mcp.servers[%s].tools[%s]: one of allow/deny/require_approval must be true", s.Name, t.Name)
			}
		}
	}
	if err := validateDefault(p.Functions.Default, "functions"); err != nil {
		return err
	}
	for i, r := range p.Functions.Rules {
		if r.Name == "" {
			return fmt.Errorf("functions.rules %d: name is required", i)
		}
		set := 0
		if r.Allow {
			set++
		}
		if r.Deny {
			set++
		}
		if r.RequireApproval {
			set++
		}
		if set == 0 {
			return fmt.Errorf("functions.rules[%s]: one of allow/deny/require_approval must be true", r.Name)
		}
		for ci, c := range r.Conditions {
			if c.Arg == "" {
				return fmt.Errorf("functions.rules[%s].conditions %d: arg is required", r.Name, ci)
			}
			switch c.Op {
			case "<", "<=", ">", ">=", "=", "==", "!=":
			default:
				return fmt.Errorf("functions.rules[%s].conditions %d: invalid op %q (expected one of < <= > >= = == !=)", r.Name, ci, c.Op)
			}
		}
	}
	for i, r := range p.Secrets.Deny {
		if r.EnvVar == "" {
			return fmt.Errorf("secrets.deny rule %d: env_var is required", i)
		}
	}
	if p.Escalation.OnTimeout != "" && p.Escalation.OnTimeout != "allow" && p.Escalation.OnTimeout != "deny" {
		return fmt.Errorf("escalation.on_timeout: invalid value %q", p.Escalation.OnTimeout)
	}
	if p.Escalation.ApprovalTimeoutSeconds < 0 {
		return fmt.Errorf("escalation.approval_timeout_seconds must not be negative")
	}
	if u := p.Escalation.WebhookURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("escalation.webhook_url: must start with http:// or https://, got %q", u)
	}
	return nil
}

func validateDefault(v, section string) error {
	if v != "" && v != "allow" && v != "deny" {
		return fmt.Errorf("%s.default: invalid value %q (expected allow or deny)", section, v)
	}
	return nil
}

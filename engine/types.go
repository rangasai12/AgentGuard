// Package engine implements AgentGuard's policy decision point (PDP): it loads a
// policy document and evaluates individual agent actions against it, returning
// ALLOW, DENY, or REQUIRE_APPROVAL. It has no knowledge of how an action was
// intercepted (SDK wrapper, MCP proxy, network proxy) — every enforcement point
// calls the same Evaluate function so policy is defined once and enforced everywhere.
package engine

// ActionType identifies the category of action being evaluated.
type ActionType string

const (
	ActionFSRead    ActionType = "fs_read"
	ActionFSWrite   ActionType = "fs_write"
	ActionNetwork   ActionType = "network"
	ActionShell     ActionType = "shell"
	ActionMCPTool   ActionType = "mcp_tool"
	ActionSecretEnv ActionType = "secret_env"
	ActionFunction  ActionType = "function"
)

// Action describes a single thing an agent is attempting to do, in the shape every
// enforcement point (PEP) must translate its own domain into before calling Evaluate.
//
// Field names carry both json and yaml tags with identical snake_case
// naming, since Action is serialized in two places that need to agree: the
// daemon's socket protocol (JSON, consumed by the Python/TS SDKs) and
// policy test-suite trace files (YAML, see LoadTestSuite) — a developer
// writing a trace file should be able to use the exact field names they
// already see in audit logs and SDK code, not a second dialect.
type Action struct {
	// Actor identifies the agent/session performing the action (free-form, used for audit).
	Actor string `json:"actor,omitempty" yaml:"actor,omitempty"`
	// Type selects which policy section governs this action.
	Type ActionType `json:"type" yaml:"type"`

	// Path is the filesystem path for fs_read / fs_write actions.
	Path string `json:"path,omitempty" yaml:"path,omitempty"`

	// Domain, Method, IsIPLiteral describe a network action.
	Domain      string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Method      string `json:"method,omitempty" yaml:"method,omitempty"`
	IsIPLiteral bool   `json:"is_ip_literal,omitempty" yaml:"is_ip_literal,omitempty"`

	// Command is the full shell command string for shell actions.
	Command string `json:"command,omitempty" yaml:"command,omitempty"`

	// Server and Tool identify an MCP tool call.
	Server string `json:"server,omitempty" yaml:"server,omitempty"`
	Tool   string `json:"tool,omitempty" yaml:"tool,omitempty"`

	// EnvVar is the environment variable name for secret_env actions.
	EnvVar string `json:"env_var,omitempty" yaml:"env_var,omitempty"`

	// Name is the function name for `function` actions — a generalization of
	// mcp_tool for any named call an SDK wraps (not only real MCP tools),
	// where the caller also wants the actual argument values checked, not
	// just the name. See the `functions` policy section.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Args holds the function's call arguments by parameter name, checked
	// against `functions[].conditions`. Values are whatever JSON/YAML
	// scalar the caller passed (string, number, bool) — see
	// conditionHolds for how they're compared.
	Args map[string]any `json:"args,omitempty" yaml:"args,omitempty"`

	// Description is the tool's own one-line description (a docstring, a
	// LangChain tool's .description, an MCP server's tools/list entry),
	// sent by an enforcement point on the *first* call to each tool it
	// sees so the cloud can catalog and classify tools without a second
	// channel. The evaluator ignores it; it is audit metadata only.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Result is the outcome of a policy decision.
type Result string

const (
	Allow           Result = "allow"
	Deny            Result = "deny"
	RequireApproval Result = "require_approval"
)

// Decision is the PDP's answer for one Action.
type Decision struct {
	Result      Result `json:"result"`
	MatchedRule string `json:"matched_rule"` // human-readable description of the rule that decided this, or "default-deny"/"default-allow"
	Reason      string `json:"reason,omitempty"`
}

// Resource returns a short human-readable description of the thing this action
// targets, for audit logs and approval prompts (e.g. "/workspace/main.go",
// "GET api.github.com", "payments-mcp.charge_customer").
func (a Action) Resource() string {
	switch a.Type {
	case ActionFSRead, ActionFSWrite:
		return a.Path
	case ActionNetwork:
		if a.Method != "" {
			return a.Method + " " + a.Domain
		}
		return a.Domain
	case ActionShell:
		return a.Command
	case ActionMCPTool:
		return a.Server + "." + a.Tool
	case ActionSecretEnv:
		return a.EnvVar
	case ActionFunction:
		return a.Name
	default:
		return ""
	}
}

package engine

import (
	"fmt"
	"path"
)

// Evaluate is the single decision function every enforcement point calls. It is
// pure and side-effect free: same Policy + Action always yields the same Decision.
func Evaluate(policy *Policy, action Action) Decision {
	if err := action.Validate(); err != nil {
		return Decision{Result: Deny, MatchedRule: "invalid-action", Reason: err.Error()}
	}
	switch action.Type {
	case ActionFSRead, ActionFSWrite:
		return evaluateFS(policy, action)
	case ActionNetwork:
		return evaluateNetwork(policy, action)
	case ActionShell:
		return evaluateShell(policy, action)
	case ActionMCPTool:
		return evaluateMCP(policy, action)
	case ActionSecretEnv:
		return evaluateSecret(policy, action)
	case ActionFunction:
		return evaluateFunction(policy, action)
	default:
		return Decision{Result: Deny, MatchedRule: "unknown-action-type", Reason: fmt.Sprintf("no policy section handles action type %q", action.Type)}
	}
}

func withApproval(d Decision, requireApproval bool) Decision {
	if requireApproval {
		d.Result = RequireApproval
	}
	return d
}

func evaluateFS(policy *Policy, action Action) Decision {
	// Filesystem rules are a single ordered list (unlike network/shell, which
	// split allow/deny into separate lists) precisely so hierarchical carve-outs
	// work: "/workspace/** allow" declared before a "** deny" catch-all lets the
	// catch-all apply to everything the earlier, more specific rule didn't claim.
	// First matching rule in declaration order wins.
	//
	// The path is cleaned (".." segments resolved) before matching so a rule
	// scoped to a directory can't be bypassed with a traversal string like
	// "/workspace/../etc/shadow". This is a logical-layer mitigation, not a
	// filesystem-level guarantee — real symlink-based escapes require the
	// kernel-level hardened mode (Landlock/seccomp) planned for v0.2.
	cleanPath := path.Clean(action.Path)
	coveredRules := 0
	for i, r := range policy.Filesystem {
		access, isAllow := r.Allow, true
		if access == "" {
			access, isAllow = r.Deny, false
		}
		if !fsAccessCovers(access, action.Type) {
			continue
		}
		coveredRules++
		for _, pat := range r.Paths {
			if !matchPathGlob(pat, cleanPath) {
				continue
			}
			result := Deny
			verb := "deny"
			if isAllow {
				result, verb = Allow, "allow"
			}
			d := Decision{Result: result, MatchedRule: fmt.Sprintf("filesystem[%d] %s %s %s", i, verb, access, pat), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		}
	}
	if coveredRules > 0 {
		return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("no filesystem rule's paths matched %s (%d rule(s) cover this access type)", cleanPath, coveredRules)}
	}
	return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("no filesystem rule covers %s access to %s", action.Type, cleanPath)}
}

func evaluateNetwork(policy *Policy, action Action) Decision {
	np := policy.Network
	for i, r := range np.Deny {
		matched := false
		reasonBits := ""
		if r.IPLiteral && action.IsIPLiteral {
			matched = true
			reasonBits = "ip-literal"
		}
		if r.Domain != "" && matchDomain(r.Domain, action.Domain) {
			matched = true
			reasonBits = "domain:" + r.Domain
		}
		if matched {
			d := Decision{Result: Deny, MatchedRule: fmt.Sprintf("network.deny[%d] %s", i, reasonBits), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		}
	}
	domainMatchedWrongMethod := ""
	for i, r := range np.Allow {
		if !matchDomain(r.Domain, action.Domain) {
			continue
		}
		if methodAllowed(r.Methods, action.Method) {
			d := Decision{Result: Allow, MatchedRule: fmt.Sprintf("network.allow[%d] domain:%s", i, r.Domain), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		}
		// The domain matched but the method didn't — remember it so the
		// eventual deny names the actual mismatch (an empty or wrong
		// action.Method used to fall all the way through to a flat "no
		// network rule matched", with nothing pointing at the fix).
		domainMatchedWrongMethod = fmt.Sprintf("network.allow[%d] domain:%s allows methods %v, not %q", i, r.Domain, r.Methods, action.Method)
	}
	if np.Default == "allow" {
		return Decision{Result: Allow, MatchedRule: "network.default", Reason: "network.default is allow"}
	}
	if domainMatchedWrongMethod != "" {
		return Decision{Result: Deny, MatchedRule: "default-deny", Reason: domainMatchedWrongMethod}
	}
	return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("no network rule matched domain %s", action.Domain)}
}

func evaluateShell(policy *Policy, action Action) Decision {
	sp := policy.Shell
	for i, r := range sp.Deny {
		if matchAnyGlob(r.Pattern, action.Command) {
			d := Decision{Result: Deny, MatchedRule: fmt.Sprintf("shell.deny[%d] %q", i, r.Pattern), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		}
	}
	for i, r := range sp.Allow {
		if matchAnyGlob(r.Pattern, action.Command) {
			d := Decision{Result: Allow, MatchedRule: fmt.Sprintf("shell.allow[%d] %q", i, r.Pattern), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		}
	}
	if sp.Default == "allow" {
		return Decision{Result: Allow, MatchedRule: "shell.default", Reason: "shell.default is allow"}
	}
	return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("command %q matched none of %d allow pattern(s)", action.Command, len(sp.Allow))}
}

func evaluateMCP(policy *Policy, action Action) Decision {
	mp := policy.MCP
	for _, s := range mp.Servers {
		if s.Name != action.Server {
			continue
		}
		for _, t := range s.Tools {
			if t.Name != action.Tool {
				continue
			}
			switch {
			case t.Deny:
				d := Decision{Result: Deny, MatchedRule: fmt.Sprintf("mcp.servers[%s].tools[%s] deny", s.Name, t.Name), Reason: t.Reason}
				return withApproval(d, t.RequireApproval)
			case t.RequireApproval:
				return Decision{Result: RequireApproval, MatchedRule: fmt.Sprintf("mcp.servers[%s].tools[%s] require_approval", s.Name, t.Name), Reason: t.Reason}
			case t.Allow:
				d := Decision{Result: Allow, MatchedRule: fmt.Sprintf("mcp.servers[%s].tools[%s] allow", s.Name, t.Name)}
				return withApproval(d, t.RequireApproval)
			}
		}
		// Server matched but no tool rule did: fall back to the server's own
		// default, then the policy-wide mcp default.
		if s.Default == "allow" {
			return Decision{Result: Allow, MatchedRule: fmt.Sprintf("mcp.servers[%s].default", s.Name), Reason: "server default is allow"}
		}
		if s.Default == "deny" {
			return Decision{Result: Deny, MatchedRule: fmt.Sprintf("mcp.servers[%s].default", s.Name), Reason: "server default is deny"}
		}
		if mp.Default == "allow" {
			return Decision{Result: Allow, MatchedRule: "mcp.default", Reason: "mcp.default is allow"}
		}
		return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("server %q matched but has no rule or default for tool %q", s.Name, action.Tool)}
	}
	if mp.Default == "allow" {
		return Decision{Result: Allow, MatchedRule: "mcp.default", Reason: "mcp.default is allow"}
	}
	return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("no mcp.servers entry named %q", action.Server)}
}

func evaluateFunction(policy *Policy, action Action) Decision {
	// A single ordered list, like filesystem: first matching rule wins.
	// Argument conditions are naturally written as partitioning ranges
	// ("amount < 1000" then "amount >= 1000"), and declaration order is how
	// you say which takes priority if ranges ever overlap.
	nameMatched := 0
	for i, r := range policy.Functions.Rules {
		if r.Name != action.Name {
			continue
		}
		nameMatched++
		matched := true
		for _, c := range r.Conditions {
			if !conditionHolds(c, action.Args) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		switch {
		case r.Deny:
			d := Decision{Result: Deny, MatchedRule: fmt.Sprintf("functions.rules[%d] %s deny", i, r.Name), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		case r.RequireApproval:
			return Decision{Result: RequireApproval, MatchedRule: fmt.Sprintf("functions.rules[%d] %s require_approval", i, r.Name), Reason: r.Reason}
		case r.Allow:
			d := Decision{Result: Allow, MatchedRule: fmt.Sprintf("functions.rules[%d] %s allow", i, r.Name), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		}
	}
	if policy.Functions.Default == "allow" {
		return Decision{Result: Allow, MatchedRule: "functions.default", Reason: "functions.default is allow"}
	}
	if nameMatched > 0 {
		return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("function %q matched %d rule(s) by name but no condition set held", action.Name, nameMatched)}
	}
	return Decision{Result: Deny, MatchedRule: "default-deny", Reason: fmt.Sprintf("no functions rule named %q", action.Name)}
}

func evaluateSecret(policy *Policy, action Action) Decision {
	for i, r := range policy.Secrets.Deny {
		if r.EnvVar == action.EnvVar {
			d := Decision{Result: Deny, MatchedRule: fmt.Sprintf("secrets.deny[%d] %s", i, r.EnvVar), Reason: r.Reason}
			return withApproval(d, r.RequireApproval)
		}
	}
	// Intentional exception to default-deny: see policy-spec/schema.yaml.
	return Decision{Result: Allow, MatchedRule: "default-allow", Reason: "env var not in secrets.deny"}
}

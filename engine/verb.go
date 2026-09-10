package engine

import "strings"

// Verb is the coarse class a tool call falls into for the anomaly
// detector's "operation" kind: what fraction of an agent's calls read vs.
// write vs. delete vs. touch permissions has a much smaller, more stable
// baseline than the raw set of tools/resources, which grows every time a
// new tool is added.
type Verb string

const (
	VerbRead       Verb = "read"
	VerbWrite      Verb = "write"
	VerbDelete     Verb = "delete"
	VerbPermission Verb = "permission"
	VerbUnknown    Verb = "unknown"
)

// HeuristicVerb classifies an action without any lookup: built-in action
// types (fs, network, secrets) have implied semantics, and shell/mcp_tool/
// function names are scored by keyword. It is the fallback used when no
// LLM classifier is configured or the call fails, and the only
// classification built-in action types ever get (they are never cataloged,
// so there is nothing for an LLM to classify).
func HeuristicVerb(actionType ActionType, resource string) Verb {
	switch actionType {
	case ActionFSRead:
		return VerbRead
	case ActionFSWrite:
		return VerbWrite
	case ActionSecretEnv:
		return VerbPermission
	case ActionNetwork:
		return verbFromHTTPMethod(resource)
	case ActionShell:
		return verbFromShellCommand(resource)
	case ActionMCPTool, ActionFunction:
		return verbFromName(resource)
	default:
		return VerbUnknown
	}
}

// verbFromHTTPMethod reads the leading "METHOD " a network action's
// Resource() carries (e.g. "GET api.example.com"); a bare domain with no
// method prefix is treated as unknown rather than guessed.
func verbFromHTTPMethod(resource string) Verb {
	method, _, found := strings.Cut(resource, " ")
	if !found {
		return VerbUnknown
	}
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return VerbRead
	case "DELETE":
		return VerbDelete
	case "POST", "PUT", "PATCH":
		return VerbWrite
	default:
		return VerbUnknown
	}
}

// verbFromShellCommand looks at the first token of a shell command line
// (the same token engine.ScopeKey groups shell actions by) against a short
// list of common program names. Anything else is unknown rather than
// guessed — a shell command's effect cannot be inferred from its name alone
// in general.
func verbFromShellCommand(command string) Verb {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return VerbUnknown
	}
	switch fields[0] {
	case "rm", "rmdir", "unlink":
		return VerbDelete
	case "cat", "ls", "grep", "find", "head", "tail", "less", "more", "diff", "file", "stat", "wc":
		return VerbRead
	case "mkdir", "touch", "cp", "mv", "tee", "sed", "npm", "pip", "make", "git":
		return VerbWrite
	case "chmod", "chown", "chgrp", "sudo", "su":
		return VerbPermission
	default:
		return VerbUnknown
	}
}

// verbFromName scores an mcp_tool/function name (e.g. "crm.lookup_customer",
// "delete_user") by keyword. Order matters: delete/permission keywords are
// checked before write/read ones so e.g. "revoke_access" (permission) isn't
// caught by a looser "access" read-ish match.
func verbFromName(name string) Verb {
	lower := strings.ToLower(name)
	switch {
	case containsAny(lower, "delete", "remove", "destroy", "drop", "purge", "cancel", "terminate"):
		return VerbDelete
	case containsAny(lower, "grant", "permission", "role", "access", "auth", "scope", "policy", "invite", "share"):
		return VerbPermission
	case containsAny(lower, "write", "create", "update", "set", "put", "insert", "modify", "edit", "save", "scale", "deploy", "send", "post", "upload", "add"):
		return VerbWrite
	case containsAny(lower, "read", "get", "list", "fetch", "lookup", "query", "search", "describe", "show", "download"):
		return VerbRead
	default:
		return VerbUnknown
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

package engine

import (
	"path"
	"strings"
)

// ScopeKey normalizes an action's resource into the key the dashboard
// groups on when it builds an agent's footprint ("which things does this
// agent touch") and when it looks for new footprint in a window.
//
// It is deliberately coarser than Action.Resource, which stays the exact,
// human-readable identity on every audit event:
//
//   - fs_read / fs_write: the parent directory with a trailing slash, so
//     an agent that reads a different file under /workspace/docs/ each
//     hour has one stable key rather than a new one per file. A path that
//     is itself a directory root ("/") stays "/".
//   - shell: the first whitespace-separated token (the program), so
//     `curl -X POST …` and `curl -s …` are both "curl".
//   - network: unchanged (method + domain already has small cardinality).
//   - mcp_tool, function, secret_env: unchanged (a stable name).
//
// The result is prefixed with the action type ("fs_read:/workspace/docs/")
// so the same string in two action types never collides.
func ScopeKey(actionType ActionType, resource string) string {
	key := resource
	switch actionType {
	case ActionFSRead, ActionFSWrite:
		if resource != "" {
			dir := path.Dir(path.Clean(resource))
			if dir == "/" || dir == "." {
				key = dir
			} else {
				key = dir + "/"
			}
		}
	case ActionShell:
		fields := strings.Fields(resource)
		if len(fields) > 0 {
			key = fields[0]
		}
	}
	return string(actionType) + ":" + key
}

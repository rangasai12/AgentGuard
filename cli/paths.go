package cli

import (
	"os"
	"path/filepath"
)

// DefaultSocketPath returns the Unix domain socket the daemon listens on and
// clients dial by default, overridable via AGENTGUARD_SOCKET.
func DefaultSocketPath() string {
	if v := os.Getenv("AGENTGUARD_SOCKET"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".agentguard", "agentguard.sock")
	}
	return filepath.Join(os.TempDir(), "agentguard.sock")
}

// DefaultAuditLogPath returns the default JSONL audit log path, overridable
// via AGENTGUARD_AUDIT_LOG.
func DefaultAuditLogPath() string {
	if v := os.Getenv("AGENTGUARD_AUDIT_LOG"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".agentguard", "audit.log")
	}
	return filepath.Join(os.TempDir(), "agentguard-audit.log")
}

// EnsureParentDir creates the parent directory of path (mode 0700) if needed.
func EnsureParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// DefaultSocketPath returns the Unix domain socket the daemon listens on
// and clients dial by default, overridable via AGENTGUARD_SOCKET.
//
// policyPath scopes the default so two agents on one machine running two
// different policy files get two different, non-colliding daemons with no
// flags to remember — pass the same policy path a Guard()/`daemon start`
// was given so both sides land on the same socket. Pass "" for the one
// caller with no policy of its own (agentguard-forwarder, which only ever
// tails whatever socket/audit-log it's pointed at) to get the single
// pre-scoping global path.
func DefaultSocketPath(policyPath string) string {
	if v := os.Getenv("AGENTGUARD_SOCKET"); v != "" {
		return v
	}
	return defaultPath(policyPath, "agentguard.sock")
}

// DefaultAuditLogPath returns the default JSONL audit log path,
// overridable via AGENTGUARD_AUDIT_LOG. See DefaultSocketPath for
// policyPath's meaning — the two are scoped identically so a policy's
// daemon and its own audit log always move together (a daemon and an
// unrelated policy's log must never mix events under one forwarder).
func DefaultAuditLogPath(policyPath string) string {
	if v := os.Getenv("AGENTGUARD_AUDIT_LOG"); v != "" {
		return v
	}
	return defaultPath(policyPath, "audit.log")
}

// DefaultProxyAddr returns the network proxy's default listen address,
// overridable via AGENTGUARD_PROXY_ADDR — the one default in this package
// that used to skip the env-var check every other one already has, so two
// `agentctl proxy start` instances on one machine collided on 127.0.0.1:8080
// with no way to separate them short of an explicit --addr on each.
func DefaultProxyAddr() string {
	if v := os.Getenv("AGENTGUARD_PROXY_ADDR"); v != "" {
		return v
	}
	return "127.0.0.1:8080"
}

// defaultPath is the shared base-directory logic behind DefaultSocketPath
// and DefaultAuditLogPath: under the user's home directory when one
// exists, else a flat name in the OS temp dir. When policyPath is
// non-empty, the path is additionally scoped under
// daemons/<policyScope(policyPath)> so two agents pointed at two different
// policy files never share a daemon or audit log by accident.
func defaultPath(policyPath, name string) string {
	base, dir := os.TempDir(), ""
	if home, err := os.UserHomeDir(); err == nil {
		base, dir = home, ".agentguard"
	}
	if policyPath == "" {
		return filepath.Join(base, dir, name)
	}
	return filepath.Join(base, dir, "daemons", policyScope(policyPath), name)
}

// policyScope is the first 12 hex characters of sha256(absolute policy
// path) — the same length as engine.Policy.Hash, though this hashes the
// *path*, not the file's contents, purely to pick a stable, collision-safe
// directory name. A stale-content check (the same policy path, edited
// since its daemon started) is a separate concern — see
// Response.PolicyHash/PolicyPath in daemon/socket_api.go and
// Guard._ensure_daemon, which compare the file's actual contents.
//
// Must produce byte-identical output to the mirrors of this function in
// sdk-python/agentguard/client.py and sdk-ts/src/client.ts, so that a plain
// `agentctl daemon start --policy foo.yaml` and a plain
// `Guard(policy="foo.yaml")`, run with no explicit --socket/socket_path,
// land on the same socket without either one telling the other where it is.
func policyScope(policyPath string) string {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		abs = policyPath
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:12]
}

// EnsureParentDir creates the parent directory of path (mode 0700) if needed.
func EnsureParentDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}

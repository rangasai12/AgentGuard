package cli

import (
	"path/filepath"
	"testing"
)

// TestDefaultSocketPathVariesByPolicy is the core guarantee behind Fix 1:
// two agents on one machine pointed at two different policy files must get
// two different sockets with no flags to remember.
func TestDefaultSocketPathVariesByPolicy(t *testing.T) {
	t.Setenv("AGENTGUARD_SOCKET", "")
	a := DefaultSocketPath("policy-a.yaml")
	b := DefaultSocketPath("policy-b.yaml")
	if a == b {
		t.Fatalf("expected different policies to get different sockets, both got %q", a)
	}
}

// TestDefaultSocketPathStableForSamePolicy is the other half: repeated runs
// against the same policy file (e.g. two invocations of the same agent)
// must keep landing on the same socket, so the singleton-daemon convenience
// this project relies on elsewhere still works.
func TestDefaultSocketPathStableForSamePolicy(t *testing.T) {
	t.Setenv("AGENTGUARD_SOCKET", "")
	a := DefaultSocketPath("policy.yaml")
	b := DefaultSocketPath("policy.yaml")
	if a != b {
		t.Fatalf("expected the same policy path to get a stable socket, got %q then %q", a, b)
	}
}

// TestDefaultSocketPathAndAuditLogPathScopeTogether: the audit log must
// move with the socket, not stay on the old global path — a daemon and an
// unrelated policy's log must never mix events under one forwarder.
func TestDefaultSocketPathAndAuditLogPathScopeTogether(t *testing.T) {
	t.Setenv("AGENTGUARD_SOCKET", "")
	t.Setenv("AGENTGUARD_AUDIT_LOG", "")
	sockA, sockB := DefaultSocketPath("policy-a.yaml"), DefaultSocketPath("policy-b.yaml")
	auditA, auditB := DefaultAuditLogPath("policy-a.yaml"), DefaultAuditLogPath("policy-b.yaml")
	if filepath.Dir(sockA) != filepath.Dir(auditA) {
		t.Fatalf("expected policy-a's socket and audit log to share a scope directory, got %q and %q", sockA, auditA)
	}
	if filepath.Dir(sockA) == filepath.Dir(sockB) {
		t.Fatalf("expected policy-a and policy-b to land in different scope directories, both got %q", filepath.Dir(sockA))
	}
	_ = auditB
}

// TestDefaultSocketPathEnvOverride: AGENTGUARD_SOCKET still wins outright,
// regardless of policy scoping — unchanged from before Fix 1.
func TestDefaultSocketPathEnvOverride(t *testing.T) {
	t.Setenv("AGENTGUARD_SOCKET", "/tmp/explicit.sock")
	if got := DefaultSocketPath("policy.yaml"); got != "/tmp/explicit.sock" {
		t.Fatalf("expected env override to win, got %q", got)
	}
}

// TestDefaultSocketPathEmptyPolicyKeepsGlobalPath is the one caller with no
// policy of its own (agentguard-forwarder): "" must keep resolving to the
// single pre-scoping global path, not a scoped one keyed on an empty string.
func TestDefaultSocketPathEmptyPolicyKeepsGlobalPath(t *testing.T) {
	t.Setenv("AGENTGUARD_SOCKET", "")
	got := DefaultSocketPath("")
	if filepath.Base(got) != "agentguard.sock" || filepath.Base(filepath.Dir(got)) == "daemons" {
		t.Fatalf("expected the unscoped global socket path, got %q", got)
	}
}

func TestDefaultProxyAddrEnvOverride(t *testing.T) {
	t.Setenv("AGENTGUARD_PROXY_ADDR", "")
	if got := DefaultProxyAddr(); got != "127.0.0.1:8080" {
		t.Fatalf("expected the default proxy addr, got %q", got)
	}
	t.Setenv("AGENTGUARD_PROXY_ADDR", "127.0.0.1:9999")
	if got := DefaultProxyAddr(); got != "127.0.0.1:9999" {
		t.Fatalf("expected the env override, got %q", got)
	}
}

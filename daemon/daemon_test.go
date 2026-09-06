package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"agentguard/engine"
)

const daemonTestPolicy = `
version: 1
filesystem:
  - allow: read_write
    paths: ["/workspace/**"]
  - deny: write
    paths: ["**"]
shell:
  default: deny
  deny:
    - pattern: "rm -rf *"
      require_approval: true
escalation:
  approval_timeout_seconds: 1
  on_timeout: deny
`

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	policy, err := engine.ParsePolicy([]byte(daemonTestPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	audit, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	return New(policy, audit)
}

func TestDaemonEvaluateAllowIsLogged(t *testing.T) {
	d := newTestDaemon(t)
	res := d.Evaluate("agent-1", engine.Action{Type: engine.ActionFSWrite, Path: "/workspace/main.go"})
	if res.Decision.Result != engine.Allow {
		t.Fatalf("expected Allow, got %s", res.Decision.Result)
	}
	events := d.Audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Allow || events[0].Resource != "/workspace/main.go" {
		t.Errorf("expected one Allow audit event for the write, got %+v", events)
	}
}

func TestDaemonEvaluateRequireApprovalThenApprove(t *testing.T) {
	d := newTestDaemon(t)
	action := engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"}

	resultCh := make(chan EvaluateResult, 1)
	go func() { resultCh <- d.Evaluate("agent-1", action) }()

	var approvalID string
	deadline := time.After(time.Second)
	for approvalID == "" {
		if p := d.Approvals.List(); len(p) == 1 {
			approvalID = p[0].ID
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared in pending list")
		case <-time.After(time.Millisecond):
		}
	}

	if err := d.Approve(approvalID); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	select {
	case res := <-resultCh:
		if res.Decision.Result != engine.Allow {
			t.Errorf("expected approved action to resolve Allow, got %s", res.Decision.Result)
		}
		if res.ApprovalID != approvalID {
			t.Errorf("expected EvaluateResult.ApprovalID %q, got %q", approvalID, res.ApprovalID)
		}
	case <-time.After(time.Second):
		t.Fatal("Evaluate did not return after Approve")
	}

	events := d.Audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Allow || events[0].ApprovalID != approvalID {
		t.Errorf("expected audit log to record the final approved decision, got %+v", events)
	}
}

func TestDaemonEvaluateRequireApprovalTimesOutToDeny(t *testing.T) {
	d := newTestDaemon(t)
	action := engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"}

	res := d.Evaluate("agent-1", action) // policy's approval_timeout_seconds is 1
	if res.Decision.Result != engine.Deny {
		t.Fatalf("expected timeout to fall back to Deny, got %s", res.Decision.Result)
	}
	events := d.Audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Deny {
		t.Errorf("expected audit log to record the timed-out Deny, got %+v", events)
	}
}

func TestDaemonDenyApproval(t *testing.T) {
	d := newTestDaemon(t)
	action := engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"}

	resultCh := make(chan EvaluateResult, 1)
	go func() { resultCh <- d.Evaluate("agent-1", action) }()

	var approvalID string
	deadline := time.After(time.Second)
	for approvalID == "" {
		if p := d.Approvals.List(); len(p) == 1 {
			approvalID = p[0].ID
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared")
		case <-time.After(time.Millisecond):
		}
	}

	if err := d.Deny(approvalID); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	res := <-resultCh
	if res.Decision.Result != engine.Deny {
		t.Errorf("expected explicitly denied action to resolve Deny, got %s", res.Decision.Result)
	}
}

func TestDaemonSetPolicyTakesEffectImmediately(t *testing.T) {
	d := newTestDaemon(t)
	before := d.Evaluate("agent-1", engine.Action{Type: engine.ActionFSWrite, Path: "/etc/passwd"})
	if before.Decision.Result != engine.Deny {
		t.Fatalf("expected initial policy to deny, got %s", before.Decision.Result)
	}

	newPolicy, err := engine.ParsePolicy([]byte("version: 1\nfilesystem:\n  - allow: read_write\n    paths: [\"**\"]\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	d.SetPolicy(newPolicy)

	after := d.Evaluate("agent-1", engine.Action{Type: engine.ActionFSWrite, Path: "/etc/passwd"})
	if after.Decision.Result != engine.Allow {
		t.Fatalf("expected updated policy to allow, got %s", after.Decision.Result)
	}
}

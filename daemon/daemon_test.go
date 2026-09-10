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
	res := d.Evaluate(DecisionRequest{Actor: "agent-1", RunID: "run-abc", AgentVersion: "1.2.3", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/workspace/main.go"}})
	if res.Decision.Result != engine.Allow {
		t.Fatalf("expected Allow, got %s", res.Decision.Result)
	}
	events := d.Audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Allow || events[0].Resource != "/workspace/main.go" {
		t.Errorf("expected one Allow audit event for the write, got %+v", events)
	}
	ev := events[0]
	if ev.EventID == "" || ev.EventID != res.EventID {
		t.Errorf("expected the audit event to carry the same EventID Evaluate returned (%q), got %q", res.EventID, ev.EventID)
	}
	if ev.RunID != "run-abc" || ev.AgentVersion != "1.2.3" {
		t.Errorf("expected run/version identity on the audit event, got run=%q version=%q", ev.RunID, ev.AgentVersion)
	}
	if ev.PolicyHash == "" || ev.PolicyHash != d.Policy().Hash {
		t.Errorf("expected the audit event to carry the policy hash %q, got %q", d.Policy().Hash, ev.PolicyHash)
	}
	if ev.Action == nil || ev.Action.Path != "/workspace/main.go" || ev.Action.Type != engine.ActionFSWrite {
		t.Errorf("expected the structured action on the audit event, got %+v", ev.Action)
	}
	if ev.Outcome != nil {
		t.Errorf("a fresh decision must have no outcome yet, got %+v", ev.Outcome)
	}
}

func TestRedactArgsAppliedBeforeAudit(t *testing.T) {
	policy, err := engine.ParsePolicy([]byte(`
version: 1
functions:
  default: deny
  rules:
    - name: login
      allow: true
      conditions:
        - { arg: password, op: "=", value: "hunter2" }
audit:
  redact_args: [password]
`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	audit := newTestAuditLogger(t)
	d := New(policy, audit)

	args := map[string]any{"user": "alice", "password": "hunter2"}
	res := d.Evaluate(DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionFunction, Name: "login", Args: args}})
	// The condition must have seen the real password to allow the call...
	if res.Decision.Result != engine.Allow {
		t.Fatalf("expected the condition on the real argument value to allow, got %+v", res.Decision)
	}
	// ...while the audit log must not.
	events := audit.Tail(1)
	if len(events) != 1 || events[0].Action == nil {
		t.Fatalf("expected one audit event with a structured action, got %+v", events)
	}
	if got := events[0].Action.Args["password"]; got != "[redacted]" {
		t.Errorf("expected password to be redacted in the audit log, got %v", got)
	}
	if got := events[0].Action.Args["user"]; got != "alice" {
		t.Errorf("expected non-listed args to be kept, got %v", got)
	}
	if args["password"] != "hunter2" {
		t.Errorf("redaction must not mutate the caller's map, got %v", args["password"])
	}
}

func TestDaemonEvaluateRequireApprovalThenApprove(t *testing.T) {
	d := newTestDaemon(t)
	action := engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"}

	resultCh := make(chan EvaluateResult, 1)
	go func() { resultCh <- d.Evaluate(DecisionRequest{Actor: "agent-1", Action: action}) }()

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

	res := d.Evaluate(DecisionRequest{Actor: "agent-1", Action: action}) // policy's approval_timeout_seconds is 1
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
	go func() { resultCh <- d.Evaluate(DecisionRequest{Actor: "agent-1", Action: action}) }()

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
	before := d.Evaluate(DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/etc/passwd"}})
	if before.Decision.Result != engine.Deny {
		t.Fatalf("expected initial policy to deny, got %s", before.Decision.Result)
	}

	newPolicy, err := engine.ParsePolicy([]byte("version: 1\nfilesystem:\n  - allow: read_write\n    paths: [\"**\"]\n"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	d.SetPolicy(newPolicy)

	after := d.Evaluate(DecisionRequest{Actor: "agent-1", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/etc/passwd"}})
	if after.Decision.Result != engine.Allow {
		t.Fatalf("expected updated policy to allow, got %s", after.Decision.Result)
	}
}

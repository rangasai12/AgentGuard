// Package daemon implements AgentGuard's local sidecar process: it hosts the
// policy engine (engine.Evaluate), an audit logger, and an approval broker
// behind a small request/response API (see socket_api.go) so every enforcement
// point — the Python SDK, the MCP proxy, the network proxy, the CLI — shares one
// decision-making process and one audit trail, regardless of language.
package daemon

import (
	"fmt"
	"sync"
	"time"

	"agentguard/engine"
)

// Daemon evaluates actions against a policy, logging every decision and
// blocking on human approval when a rule requires it.
type Daemon struct {
	mu        sync.RWMutex
	policy    *engine.Policy
	Audit     *AuditLogger
	Approvals *ApprovalBroker

	// Notify, if set, is invoked whenever an action starts requiring
	// approval (see ApprovalBroker.Notifier) — e.g. WebhookNotifier, to
	// alert a human via Slack/webhook rather than requiring them to poll
	// `agentctl audit tail`/`pending_approvals`.
	Notify Notifier
}

// New constructs a Daemon over an already-loaded policy and audit logger.
func New(policy *engine.Policy, audit *AuditLogger) *Daemon {
	return &Daemon{policy: policy, Audit: audit, Approvals: NewApprovalBroker()}
}

// Policy returns the currently active policy.
func (d *Daemon) Policy() *engine.Policy {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.policy
}

// SetPolicy replaces the active policy (used by `agentctl policy reload`-style
// flows). Approvals already in flight are unaffected.
func (d *Daemon) SetPolicy(p *engine.Policy) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.policy = p
}

// EvaluateResult is what the daemon returns for one evaluate request: the final
// decision (after any approval wait) plus bookkeeping for the caller/CLI.
type EvaluateResult struct {
	Decision   engine.Decision
	ApprovalID string
	LatencyMS  int64
}

// Evaluate runs the policy engine against action and, if the result is
// REQUIRE_APPROVAL, blocks until a human resolves it (or the policy's
// approval timeout elapses). Every call is recorded to the audit log exactly
// once, with the final (post-approval) decision.
func (d *Daemon) Evaluate(actor string, action engine.Action) EvaluateResult {
	start := time.Now()
	policy := d.Policy()

	decision := engine.Evaluate(policy, action)
	final := decision
	approvalID := ""

	if decision.Result == engine.RequireApproval {
		timeout := time.Duration(policy.ApprovalTimeoutSeconds()) * time.Second
		result, id := d.Approvals.Await(actor, action, decision, timeout, policy.OnTimeoutResult(), d.Notify)
		approvalID = id
		final = engine.Decision{Result: result, MatchedRule: decision.MatchedRule, Reason: decision.Reason}
	}

	latency := time.Since(start)
	_ = d.Audit.Log(AuditEvent{
		Timestamp:   start,
		Actor:       actor,
		ActionType:  action.Type,
		Resource:    action.Resource(),
		Decision:    final.Result,
		MatchedRule: final.MatchedRule,
		Reason:      final.Reason,
		ApprovalID:  approvalID,
		LatencyMS:   latency.Milliseconds(),
	})

	return EvaluateResult{Decision: final, ApprovalID: approvalID, LatencyMS: latency.Milliseconds()}
}

// Approve resolves a pending approval as ALLOW.
func (d *Daemon) Approve(id string) error {
	return d.resolveApproval(id, engine.Allow)
}

// Deny resolves a pending approval as DENY.
func (d *Daemon) Deny(id string) error {
	return d.resolveApproval(id, engine.Deny)
}

func (d *Daemon) resolveApproval(id string, result engine.Result) error {
	if err := d.Approvals.Resolve(id, result); err != nil {
		return fmt.Errorf("resolving approval: %w", err)
	}
	return nil
}

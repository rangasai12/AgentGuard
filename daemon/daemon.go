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

// DecisionRequest is everything an enforcement point knows about one action
// it wants judged: who is acting (Actor), which execution it belongs to
// (RunID), which build of the agent is running (AgentVersion), and the
// action itself. Actor falls back to Action.Actor when empty.
type DecisionRequest struct {
	Actor        string
	RunID        string
	AgentVersion string
	Action       engine.Action
}

// EvaluateResult is what the daemon returns for one evaluate request: the final
// decision (after any approval wait) plus bookkeeping for the caller/CLI.
// EventID identifies the audit event the decision was recorded as, so the
// caller can later `report` the execution outcome against it.
type EvaluateResult struct {
	Decision   engine.Decision
	ApprovalID string
	LatencyMS  int64
	EventID    string
}

// Awaiter resolves a REQUIRE_APPROVAL decision by asking a human, returning
// the final result and — when the mechanism mints one — an approval id
// (the broker does; a TTY prompt does not). It is the one seam through which
// Decide differs between the daemon (broker + notifier) and a standalone
// proxy (terminal prompt).
type Awaiter func(actor string, action engine.Action, decision engine.Decision, timeout time.Duration, onTimeout engine.Result) (engine.Result, string)

// PromptAwaiter adapts a synchronous prompt of the approval.Func shape
// (returning "" when no decision could be reached) into an Awaiter that
// falls back to the policy's on_timeout result. A nil prompt yields a nil
// Awaiter, which Decide treats as "no way to ask": straight to on_timeout.
func PromptAwaiter(prompt func(action engine.Action, decision engine.Decision, timeout time.Duration) engine.Result) Awaiter {
	if prompt == nil {
		return nil
	}
	return func(_ string, action engine.Action, decision engine.Decision, timeout time.Duration, onTimeout engine.Result) (engine.Result, string) {
		if r := prompt(action, decision, timeout); r != "" {
			return r, ""
		}
		return onTimeout, ""
	}
}

// Decide is the single place a policy decision is made, optionally awaited,
// and audited. Every enforcement point — the daemon's socket API, the MCP
// proxy, the network proxy — calls it, so the audit event shape and the
// approval semantics are defined exactly once.
//
// audit may be nil to skip logging (standalone proxies allow that). The
// action is evaluated with its real arguments, then redacted per
// policy.audit.redact_args before being shown to an approver or written to
// the log. Every call produces exactly one audit event, with the final
// (post-approval) decision.
func Decide(policy *engine.Policy, audit *AuditLogger, req DecisionRequest, await Awaiter) EvaluateResult {
	start := time.Now()
	actor := req.Actor
	if actor == "" {
		actor = req.Action.Actor
	}

	decision := engine.Evaluate(policy, req.Action)
	final := decision
	approvalID := ""

	logged := req.Action
	logged.Args = policy.RedactArgs(req.Action.Args)
	logged.Description = truncateUTF8(logged.Description, MaxDescriptionBytes)

	if decision.Result == engine.RequireApproval {
		timeout := time.Duration(policy.ApprovalTimeoutSeconds()) * time.Second
		result := policy.OnTimeoutResult()
		if await != nil {
			result, approvalID = await(actor, logged, decision, timeout, policy.OnTimeoutResult())
		}
		final = engine.Decision{Result: result, MatchedRule: decision.MatchedRule, Reason: decision.Reason}
	}

	latency := time.Since(start)
	eventID := newHexID(8)
	if audit != nil {
		_ = audit.Log(AuditEvent{
			Timestamp:    start,
			Actor:        actor,
			ActionType:   logged.Type,
			Resource:     logged.Resource(),
			Decision:     final.Result,
			MatchedRule:  final.MatchedRule,
			Reason:       final.Reason,
			ApprovalID:   approvalID,
			LatencyMS:    latency.Milliseconds(),
			EventID:      eventID,
			RunID:        req.RunID,
			AgentVersion: req.AgentVersion,
			PolicyHash:   policy.Hash,
			Action:       &logged,
		})
	}

	return EvaluateResult{Decision: final, ApprovalID: approvalID, LatencyMS: latency.Milliseconds(), EventID: eventID}
}

// Evaluate runs Decide with this daemon's current policy, audit log, and
// broker-backed approval flow (which also fires Notify).
func (d *Daemon) Evaluate(req DecisionRequest) EvaluateResult {
	return Decide(d.Policy(), d.Audit, req, d.brokerAwaiter())
}

func (d *Daemon) brokerAwaiter() Awaiter {
	return func(actor string, action engine.Action, decision engine.Decision, timeout time.Duration, onTimeout engine.Result) (engine.Result, string) {
		return d.Approvals.Await(actor, action, decision, timeout, onTimeout, d.Notify)
	}
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

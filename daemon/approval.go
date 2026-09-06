package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"agentguard/engine"
)

// PendingApproval describes one action that is blocked awaiting a human decision.
type PendingApproval struct {
	ID          string        `json:"id"`
	Actor       string        `json:"actor,omitempty"`
	Action      engine.Action `json:"action"`
	MatchedRule string        `json:"matched_rule"`
	Reason      string        `json:"reason,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
}

type pendingEntry struct {
	summary  PendingApproval
	resolved chan engine.Result
}

// ApprovalBroker tracks actions that require human approval and lets a second
// caller (the CLI's `agentctl approve`/`deny`, or a webhook resolving it
// remotely) resolve them while the original Evaluate call blocks.
type ApprovalBroker struct {
	mu      sync.Mutex
	pending map[string]*pendingEntry
}

// NewApprovalBroker returns an empty broker.
func NewApprovalBroker() *ApprovalBroker {
	return &ApprovalBroker{pending: make(map[string]*pendingEntry)}
}

// Notifier is called once a pending approval is registered, so a human can
// be alerted that something needs `agentctl approve`/`deny` (e.g. by posting
// to a Slack/webhook URL — see WebhookNotifier). Await always calls it in
// its own goroutine, so a slow or blocking Notifier implementation can never
// delay the approval flow itself; a broken notifier is a missed
// notification, never a stuck (or accidentally denied) action.
type Notifier func(PendingApproval)

// Await registers a pending approval, invokes notify (if non-nil) with it,
// and blocks until it is resolved via Resolve or the timeout elapses, in
// which case onTimeout is returned. The pending entry is removed before
// Await returns.
func (b *ApprovalBroker) Await(actor string, action engine.Action, decision engine.Decision, timeout time.Duration, onTimeout engine.Result, notify Notifier) (engine.Result, string) {
	id := newApprovalID()
	entry := &pendingEntry{
		summary: PendingApproval{
			ID:          id,
			Actor:       actor,
			Action:      action,
			MatchedRule: decision.MatchedRule,
			Reason:      decision.Reason,
			CreatedAt:   time.Now(),
		},
		resolved: make(chan engine.Result, 1),
	}

	b.mu.Lock()
	b.pending[id] = entry
	b.mu.Unlock()

	if notify != nil {
		go notify(entry.summary)
	}

	defer func() {
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
	}()

	select {
	case result := <-entry.resolved:
		return result, id
	case <-time.After(timeout):
		return onTimeout, id
	}
}

// Resolve delivers a human decision to the pending approval identified by id.
// It returns an error if no such pending approval exists (e.g. it already
// timed out).
func (b *ApprovalBroker) Resolve(id string, result engine.Result) error {
	b.mu.Lock()
	entry, ok := b.pending[id]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("no pending approval with id %q", id)
	}
	select {
	case entry.resolved <- result:
		return nil
	default:
		return fmt.Errorf("approval %q was already resolved", id)
	}
}

// List returns all currently pending approvals, oldest first.
func (b *ApprovalBroker) List() []PendingApproval {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]PendingApproval, 0, len(b.pending))
	for _, e := range b.pending {
		out = append(out, e.summary)
	}
	return out
}

func newApprovalID() string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

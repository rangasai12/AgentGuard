package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"agentguard/engine"
)

// AuditEvent is one recorded policy decision, written as one line of JSON to the
// audit log and also kept in a bounded in-memory ring for fast `audit tail`/`audit
// query` without re-reading the file.
type AuditEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	Actor       string            `json:"actor,omitempty"`
	ActionType  engine.ActionType `json:"action_type"`
	Resource    string            `json:"resource"`
	Decision    engine.Result     `json:"decision"`
	MatchedRule string            `json:"matched_rule"`
	Reason      string            `json:"reason,omitempty"`
	ApprovalID  string            `json:"approval_id,omitempty"`
	LatencyMS   int64             `json:"latency_ms"`
}

// AuditFilter narrows an audit query. Zero-value fields are not filtered on.
type AuditFilter struct {
	ActionType engine.ActionType `json:"action_type,omitempty"`
	Decision   engine.Result     `json:"decision,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	Limit      int               `json:"limit,omitempty"`
}

// AuditLogger appends events to a JSONL file and keeps a bounded recent-events
// ring buffer in memory. Safe for concurrent use.
type AuditLogger struct {
	mu        sync.Mutex
	file      *os.File
	writer    *bufio.Writer
	recent    []AuditEvent
	maxRecent int
}

const defaultMaxRecent = 2000

// NewAuditLogger opens (creating if necessary) the JSONL audit log at path.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %s: %w", path, err)
	}
	return &AuditLogger{file: f, writer: bufio.NewWriter(f), maxRecent: defaultMaxRecent}, nil
}

// Log appends ev to the audit log and the in-memory ring.
func (l *AuditLogger) Log(ev AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshaling audit event: %w", err)
	}
	if _, err := l.writer.Write(data); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}
	if err := l.writer.WriteByte('\n'); err != nil {
		return err
	}
	if err := l.writer.Flush(); err != nil {
		return fmt.Errorf("flushing audit log: %w", err)
	}

	l.recent = append(l.recent, ev)
	if len(l.recent) > l.maxRecent {
		l.recent = l.recent[len(l.recent)-l.maxRecent:]
	}
	return nil
}

// Tail returns the n most recent events, oldest first.
func (l *AuditLogger) Tail(n int) []AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.recent) {
		n = len(l.recent)
	}
	start := len(l.recent) - n
	out := make([]AuditEvent, n)
	copy(out, l.recent[start:])
	return out
}

// Query returns recent events matching filter, most recent first, capped at
// filter.Limit (default 100).
func (l *AuditLogger) Query(filter AuditFilter) []AuditEvent {
	l.mu.Lock()
	events := make([]AuditEvent, len(l.recent))
	copy(events, l.recent)
	l.mu.Unlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var out []AuditEvent
	for i := len(events) - 1; i >= 0 && len(out) < limit; i-- {
		ev := events[i]
		if filter.ActionType != "" && ev.ActionType != filter.ActionType {
			continue
		}
		if filter.Decision != "" && ev.Decision != filter.Decision {
			continue
		}
		if filter.Actor != "" && ev.Actor != filter.Actor {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// Close flushes and closes the underlying file.
func (l *AuditLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.writer.Flush(); err != nil {
		return err
	}
	return l.file.Close()
}

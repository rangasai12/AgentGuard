package daemon

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"agentguard/engine"
)

// Outcome is what an enforcement point learns after a tool actually ran:
// whether it succeeded, how long it took, and (a bounded preview of) what
// it returned. It is both the payload of the `report` socket command and
// the sub-object stored on an AuditEvent, so the wire format and the log
// format cannot drift apart.
//
// Output is a preview. A caller that sends the full output leaves
// OutputBytes zero and the logger fills OutputBytes and OutputSHA256 from
// that full value before truncating to its preview size. A caller that
// sends something shorter than the real output — a client that truncated
// locally, or the network proxy recording a status line for a streamed
// body — must set OutputBytes itself (and OutputSHA256 if it has one),
// since a hash of the preview would masquerade as a hash of the output.
type Outcome struct {
	Status       string `json:"status"` // OutcomeSuccess | OutcomeError
	ExecMS       int64  `json:"exec_ms"`
	Output       string `json:"output,omitempty"`
	OutputBytes  int64  `json:"output_bytes,omitempty"`
	OutputSHA256 string `json:"output_sha256,omitempty"`
	Error        string `json:"error,omitempty"`
}

const (
	OutcomeSuccess = "success"
	OutcomeError   = "error"

	// KindOutcome marks an audit log line that patches an earlier decision
	// line (matched by EventID) with its Outcome, rather than recording a
	// new decision. Readers of the JSONL file must merge such lines into
	// the decision they refer to; the in-memory ring already holds the
	// merged form.
	KindOutcome = "outcome"

	// DefaultOutputPreviewBytes is how much of a tool's output the audit
	// log keeps by default.
	DefaultOutputPreviewBytes = 4096
	// MaxDescriptionBytes bounds Action.Description on a logged event; an
	// enforcement point that sends more is truncated inside Decide.
	MaxDescriptionBytes = 512

	// MaxOutputPreviewBytes is the hard ceiling on a stored output preview,
	// regardless of configuration — well under the socket's 1 MiB line
	// limit.
	MaxOutputPreviewBytes = 64 << 10
)

// AuditEvent is one recorded policy decision, written as one line of JSON to the
// audit log and also kept in a bounded in-memory ring for fast `audit tail`/`audit
// query` without re-reading the file.
//
// The first nine fields are the original v0.1 shape. The rest identify the
// event (EventID), the execution it belongs to (RunID, AgentVersion,
// PolicyHash), carry the structured Action it was about (including any
// arguments, after audit.redact_args), and — once the tool has run and
// reported back — its Outcome. Old log lines lacking these fields
// unmarshal with them empty/nil.
type AuditEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	Actor       string            `json:"actor,omitempty"`
	ActionType  engine.ActionType `json:"action_type"`
	Resource    string            `json:"resource"`
	Decision    engine.Result     `json:"decision"`
	MatchedRule string            `json:"matched_rule"`
	Reason      string            `json:"reason,omitempty"`
	ApprovalID  string            `json:"approval_id,omitempty"`
	LatencyMS   int64             `json:"latency_ms"` // policy evaluation plus any approval wait — not tool execution (see Outcome.ExecMS)

	EventID      string         `json:"event_id,omitempty"`
	Kind         string         `json:"kind,omitempty"` // "" for a decision, KindOutcome for a patch line
	RunID        string         `json:"run_id,omitempty"`
	AgentVersion string         `json:"agent_version,omitempty"`
	PolicyHash   string         `json:"policy_hash,omitempty"`
	Action       *engine.Action `json:"action,omitempty"`
	Outcome      *Outcome       `json:"outcome,omitempty"`
}

// AuditFilter narrows an audit query. Zero-value fields are not filtered on.
type AuditFilter struct {
	ActionType engine.ActionType `json:"action_type,omitempty"`
	Decision   engine.Result     `json:"decision,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	RunID      string            `json:"run_id,omitempty"`
	EventID    string            `json:"event_id,omitempty"`
	Limit      int               `json:"limit,omitempty"`
}

// AuditLogger appends events to a JSONL file and keeps a bounded recent-events
// ring buffer in memory. Safe for concurrent use.
type AuditLogger struct {
	mu                 sync.Mutex
	file               *os.File
	writer             *bufio.Writer
	recent             []AuditEvent
	maxRecent          int
	outputPreviewBytes int
}

const defaultMaxRecent = 2000

// NewAuditLogger opens (creating if necessary) the JSONL audit log at path.
func NewAuditLogger(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %s: %w", path, err)
	}
	return &AuditLogger{file: f, writer: bufio.NewWriter(f), maxRecent: defaultMaxRecent, outputPreviewBytes: DefaultOutputPreviewBytes}, nil
}

// SetOutputPreviewBytes changes how much of a reported output is stored,
// clamped to [0, MaxOutputPreviewBytes].
func (l *AuditLogger) SetOutputPreviewBytes(n int) {
	if n < 0 {
		n = 0
	}
	if n > MaxOutputPreviewBytes {
		n = MaxOutputPreviewBytes
	}
	l.mu.Lock()
	l.outputPreviewBytes = n
	l.mu.Unlock()
}

// Log appends ev to the audit log and the in-memory ring.
func (l *AuditLogger) Log(ev AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.appendLine(ev); err != nil {
		return err
	}
	l.recent = append(l.recent, ev)
	if len(l.recent) > l.maxRecent {
		l.recent = l.recent[len(l.recent)-l.maxRecent:]
	}
	return nil
}

// Report records the execution outcome of the decision identified by
// eventID: the matching event in the in-memory ring is patched in place
// (so Tail/Query return one merged event) and a KindOutcome patch line is
// appended to the file for readers that tail it (the cloud forwarder). The
// patch line is appended even when the ring no longer holds the decision —
// e.g. the daemon restarted between evaluate and report — since downstream
// stores can still merge it.
//
// Output is truncated to the configured preview size; when the caller left
// OutputBytes zero (meaning Output is the whole output), OutputBytes and
// OutputSHA256 are filled from the untruncated value first.
func (l *AuditLogger) Report(eventID string, o Outcome) error {
	if !isHexID(eventID) {
		return fmt.Errorf("report: invalid event id %q", eventID)
	}
	switch o.Status {
	case OutcomeSuccess, OutcomeError:
	case "":
		return fmt.Errorf("report: outcome status is required (%q or %q)", OutcomeSuccess, OutcomeError)
	default:
		return fmt.Errorf("report: invalid outcome status %q", o.Status)
	}
	if o.Output != "" && o.OutputBytes == 0 {
		// The caller sent the whole output: derive size and hash from it.
		o.OutputBytes = int64(len(o.Output))
		sum := sha256.Sum256([]byte(o.Output))
		o.OutputSHA256 = hex.EncodeToString(sum[:])
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	o.Output = truncateUTF8(o.Output, l.outputPreviewBytes)

	for i := len(l.recent) - 1; i >= 0; i-- {
		if l.recent[i].EventID == eventID && l.recent[i].Kind == "" {
			oc := o
			l.recent[i].Outcome = &oc
			break
		}
	}
	patch := AuditEvent{Timestamp: time.Now(), Kind: KindOutcome, EventID: eventID, Outcome: &o}
	return l.appendLine(patch)
}

// appendLine writes one JSON line and flushes. Caller holds l.mu.
func (l *AuditLogger) appendLine(ev AuditEvent) error {
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
		if filter.RunID != "" && ev.RunID != filter.RunID {
			continue
		}
		if filter.EventID != "" && ev.EventID != filter.EventID {
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

// truncateUTF8 cuts s to at most max bytes without splitting a multi-byte
// rune, so the preview stays valid UTF-8 (and valid JSON).
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// isHexID reports whether id looks like something newHexID produced
// (8–32 lowercase hex chars), rejecting anything a caller might try to
// smuggle into the log as an "id".
func isHexID(id string) bool {
	if len(id) < 8 || len(id) > 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

package daemon

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/rangasai12/AgentGuard/engine"
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
	// log keeps — fixed, not configurable (see CHANGELOG "Fix 5": a
	// configurable ceiling here was dead code with no caller, and made
	// the forwarder's per-request byte budget a guess rather than a fact;
	// well under the daemon socket's 1 MiB line limit either way).
	DefaultOutputPreviewBytes = 4096
	// MaxDescriptionBytes bounds Action.Description on a logged event; an
	// enforcement point that sends more is truncated inside Decide.
	MaxDescriptionBytes = 512
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
	Timestamp  time.Time         `json:"timestamp"`
	Actor      string            `json:"actor,omitempty"`
	ActionType engine.ActionType `json:"action_type"`
	Resource   string            `json:"resource"`
	Decision   engine.Result     `json:"decision"`
	// ShadowDecision is set only under policy `mode: shadow`, when the
	// policy would have denied or held the action but let it through:
	// Decision records what happened (allow), this records what enforcement
	// would have done.
	ShadowDecision engine.Result `json:"shadow_decision,omitempty"`
	MatchedRule    string        `json:"matched_rule"`
	Reason         string        `json:"reason,omitempty"`
	ApprovalID     string        `json:"approval_id,omitempty"`
	LatencyMS      int64         `json:"latency_ms"` // policy evaluation plus any approval wait — not tool execution (see Outcome.ExecMS)

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
// ring buffer in memory. Safe for concurrent use, including by several
// processes appending to the same file (the daemon, `agentctl proxy` and
// `agentctl mcp-proxy` all default to the same policy-scoped log): every
// line is written under an exclusive flock, and is hash-chained to the line
// before it (see appendLine and VerifyAuditLog).
type AuditLogger struct {
	mu        sync.Mutex
	file      *os.File
	recent    []AuditEvent
	maxRecent int
}

const defaultMaxRecent = 2000

// NewAuditLogger opens (creating if necessary) the JSONL audit log at path.
func NewAuditLogger(path string) (*AuditLogger, error) {
	// Read access too: appendLine reads the last line to chain onto it.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %s: %w", path, err)
	}
	return &AuditLogger{file: f, maxRecent: defaultMaxRecent}, nil
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
// Output is truncated to DefaultOutputPreviewBytes; when the caller left
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
	o.Output = truncateUTF8(o.Output, DefaultOutputPreviewBytes)

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

// appendLine writes one JSON line, chained to the file's current last line.
// Caller holds l.mu; the flock additionally serializes against other
// processes appending to the same file, so the "last line" read here is
// still the last line when this one is written.
func (l *AuditLogger) appendLine(ev AuditEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshaling audit event: %w", err)
	}
	fd := int(l.file.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("locking audit log: %w", err)
	}
	defer syscall.Flock(fd, syscall.LOCK_UN) //nolint:errcheck // closing the fd releases it anyway

	last, err := readLastLine(l.file)
	if err != nil {
		return fmt.Errorf("reading audit log tail: %w", err)
	}
	var line []byte
	if len(last) > 0 && last[len(last)-1] != '\n' {
		// A torn write left a partial line; don't glue this event onto it.
		// VerifyAuditLog will (rightly) report that partial line.
		line = append(line, '\n')
	}
	line = append(line, chainLine(body, chainLink(bytes.TrimSuffix(last, []byte("\n"))))...)
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}
	return nil
}

// The audit log is a hash chain: each line ends in a "chain" field holding
// sha256(<previous line's link> + "\n" + <this line without the chain
// field>). A line's link is its chain value, or — for a line written before
// chaining existed — the sha256 of its bytes, so a log that predates chaining
// keeps working and its first chained line anchors to the old tail. Editing,
// inserting or deleting any line breaks every chain value after it (see
// VerifyAuditLog). Hashing the exact bytes written, rather than a
// re-marshaled event, keeps verification independent of JSON encoding
// details. The chain field is appended textually and never parsed into
// AuditEvent; readers that unmarshal lines ignore it.
const chainPrefix = `,"chain":"`

// chainLine returns body (a JSON object) with its chain field appended.
func chainLine(body []byte, prevLink string) []byte {
	sum := sha256.Sum256([]byte(prevLink + "\n" + string(body)))
	out := make([]byte, 0, len(body)+len(chainPrefix)+66)
	out = append(out, body[:len(body)-1]...)
	out = append(out, chainPrefix...)
	out = append(out, hex.EncodeToString(sum[:])...)
	return append(out, '"', '}')
}

// splitChain separates a line into its body and chain value; ok is false
// for a line with no chain field.
func splitChain(line []byte) (body []byte, chain string, ok bool) {
	const tail = 64 + 2 // hex digest + `"}`
	n := len(line) - tail - len(chainPrefix)
	if n < 1 || string(line[n:n+len(chainPrefix)]) != chainPrefix || line[len(line)-2] != '"' || line[len(line)-1] != '}' {
		return nil, "", false
	}
	chain = string(line[n+len(chainPrefix) : len(line)-2])
	if !isHexID(chain[:32]) || !isHexID(chain[32:]) {
		return nil, "", false
	}
	body = append(append([]byte(nil), line[:n]...), '}')
	return body, chain, true
}

// chainLink is what the next line chains onto: line's chain value, or the
// hash of the whole line if it has none ("" for an empty log).
func chainLink(line []byte) string {
	if len(line) == 0 {
		return ""
	}
	if _, chain, ok := splitChain(line); ok {
		return chain
	}
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// readLastLine returns the file's last line including its trailing newline
// (if any), reading backwards from the end in chunks.
func readLastLine(f *os.File) ([]byte, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	end := info.Size()
	const chunk = 64 << 10
	var buf []byte
	for pos := end; pos > 0; {
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		pos -= n
		part := make([]byte, n)
		if _, err := f.ReadAt(part, pos); err != nil {
			return nil, err
		}
		buf = append(part, buf...)
		// Ignore the line's own trailing newline when looking for its start.
		search := buf
		if int64(len(buf)) == end-pos && len(search) > 0 && search[len(search)-1] == '\n' {
			search = search[:len(search)-1]
		}
		if i := bytes.LastIndexByte(search, '\n'); i >= 0 {
			return buf[i+1:], nil
		}
	}
	return buf, nil
}

// AuditVerifyReport is the result of VerifyAuditLog.
type AuditVerifyReport struct {
	Lines     int    // total lines read
	Unchained int    // lines written before chaining existed (not tamper-evident)
	Head      string // the last line's link — record it elsewhere to detect truncation later
	// BrokenAt is the 1-based line number where the chain first fails to
	// verify (0 when intact), with Problem saying why.
	BrokenAt int
	Problem  string
}

// VerifyAuditLog checks an audit log's hash chain from the first line. It
// detects any edited, inserted, deleted or reordered line, except that
// lines removed from the very end leave a shorter chain that still
// verifies — compare Head against a value recorded earlier to catch that.
// Unchained lines are accepted only before the first chained one.
func VerifyAuditLog(r io.Reader) (AuditVerifyReport, error) {
	var rep AuditVerifyReport
	br := bufio.NewReaderSize(r, 64<<10)
	prev, chained := "", false
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			rep.Lines++
			if line[len(line)-1] != '\n' {
				rep.BrokenAt, rep.Problem = rep.Lines, "last line is incomplete (a torn write)"
				return rep, nil
			}
			line = line[:len(line)-1]
			body, _, ok := splitChain(line)
			switch {
			case ok:
				if want := chainLine(body, prev); !bytes.Equal(want, line) {
					rep.BrokenAt, rep.Problem = rep.Lines, "chain hash does not match: this line or one before it was changed, inserted or removed"
					return rep, nil
				}
				chained = true
			case chained:
				rep.BrokenAt, rep.Problem = rep.Lines, "line has no chain field after chaining began"
				return rep, nil
			default:
				rep.Unchained++
			}
			prev = chainLink(line)
			rep.Head = prev
		}
		if err == io.EOF {
			return rep, nil
		}
		if err != nil {
			return rep, err
		}
	}
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

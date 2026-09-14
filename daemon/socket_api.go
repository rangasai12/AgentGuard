package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/rangasai12/AgentGuard/engine"
)

// Request is one line-delimited JSON message a client (SDK, CLI, proxy) sends
// to the daemon over its Unix domain socket. Cmd selects which fields apply.
type Request struct {
	Cmd    string        `json:"cmd"`
	Actor  string        `json:"actor,omitempty"`
	Action engine.Action `json:"action,omitempty"`
	N      int           `json:"n,omitempty"`
	ID     string        `json:"id,omitempty"` // approval id for approve/deny; event id for report
	Filter AuditFilter   `json:"filter,omitempty"`

	// RunID and AgentVersion tag an evaluate request with the execution and
	// agent build it belongs to (see DecisionRequest).
	RunID        string `json:"run_id,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	// Outcome is the payload of a report request.
	Outcome *Outcome `json:"outcome,omitempty"`
}

// Response is the daemon's line-delimited JSON reply to one Request.
type Response struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Decision   *engine.Decision  `json:"decision,omitempty"`
	ApprovalID string            `json:"approval_id,omitempty"`
	LatencyMS  int64             `json:"latency_ms,omitempty"`
	EventID    string            `json:"event_id,omitempty"` // for evaluate: pass back to report
	Events     []AuditEvent      `json:"events,omitempty"`
	Pending    []PendingApproval `json:"pending,omitempty"`

	// PolicyHash and PolicyPath identify the policy this daemon is running,
	// returned on every "ping" response so a client can tell whether it has
	// connected to the daemon it expects: cli.DefaultSocketPath's
	// policy-scoped default keeps two *different* policies from ever
	// landing on the same socket, but the *same* policy file edited on disk
	// after its daemon started still needs a content check — see
	// Guard._ensure_daemon (sdk-python/agentguard/guard.py,
	// sdk-ts/src/guard.ts), which compares PolicyHash against the file's
	// current contents before trusting a daemon that answers here.
	PolicyHash string `json:"policy_hash,omitempty"`
	PolicyPath string `json:"policy_path,omitempty"`
}

// maxLineBytes bounds one line of the daemon's own socket protocol.
// proxy/mcp/proxy.go defines an unrelated constant of the same name at
// 4 MiB, for the MCP stdio transport's JSON-RPC messages — deliberately
// different values for two different transports with different payload
// shapes, not drift; each package's copy is the only one that matters to
// it, so this stays a plain const, not a shared one.
const maxLineBytes = 1 << 20 // 1 MiB, generous for the small JSON payloads this protocol carries

// Serve listens on socketPath (a Unix domain socket) and handles requests
// against d until ctx is canceled. Each accepted connection may carry
// multiple sequential requests.
//
// Unless force is true, Serve first checks whether something is already
// listening and answering the daemon protocol at socketPath and, if so,
// refuses to start rather than silently unlinking that daemon's socket out
// from under it — this used to orphan a running daemon on every restart at
// the (formerly machine-wide, now policy-scoped) default path.
func Serve(ctx context.Context, socketPath string, d *Daemon, force bool) error {
	if !force {
		if err := checkNoLiveDaemon(socketPath); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(socketPath); err != nil {
		return fmt.Errorf("removing stale socket %s: %w", socketPath, err)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accepting connection: %w", err)
		}
		go handleConn(conn, d)
	}
}

// checkNoLiveDaemon returns an error if a daemon is already listening and
// answering pings at socketPath. Any failure to dial or speak the protocol
// (nothing listening, a stale socket file, an unrelated process on this
// path) is treated as "safe to proceed" — this is a narrow guard against
// clobbering a live daemon, not a general liveness prober.
func checkNoLiveDaemon(socketPath string) error {
	conn, err := net.DialTimeout("unix", socketPath, 200*time.Millisecond)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if err := json.NewEncoder(conn).Encode(Request{Cmd: "ping"}); err != nil {
		return nil
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil || !resp.OK {
		return nil
	}
	policyPath := resp.PolicyPath
	if policyPath == "" {
		policyPath = "(unknown)"
	}
	return fmt.Errorf("a daemon is already running at %s (policy: %s) — stop it first, or pass --force to take over this socket", socketPath, policyPath)
}

func handleConn(conn net.Conn, d *Daemon) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			_ = enc.Encode(Response{OK: false, Error: fmt.Sprintf("invalid request: %v", err)})
			continue
		}
		resp := dispatch(d, req)
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func dispatch(d *Daemon, req Request) Response {
	switch req.Cmd {
	case "ping":
		hash := ""
		if p := d.Policy(); p != nil {
			hash = p.Hash
		}
		return Response{OK: true, PolicyHash: hash, PolicyPath: d.PolicyPath}

	case "evaluate":
		result := d.Evaluate(DecisionRequest{Actor: req.Actor, RunID: req.RunID, AgentVersion: req.AgentVersion, Action: req.Action})
		return Response{OK: true, Decision: &result.Decision, ApprovalID: result.ApprovalID, LatencyMS: result.LatencyMS, EventID: result.EventID}

	case "report":
		if req.ID == "" {
			return errResponse(errors.New("report requires an id (the event_id returned by evaluate)"))
		}
		if req.Outcome == nil {
			return errResponse(errors.New("report requires an outcome"))
		}
		if err := d.Audit.Report(req.ID, *req.Outcome); err != nil {
			return errResponse(err)
		}
		return Response{OK: true}

	case "audit_tail":
		return Response{OK: true, Events: d.Audit.Tail(req.N)}

	case "audit_query":
		return Response{OK: true, Events: d.Audit.Query(req.Filter)}

	case "pending_approvals":
		return Response{OK: true, Pending: d.Approvals.List()}

	case "approve":
		if req.ID == "" {
			return errResponse(errors.New("approve requires an id"))
		}
		if err := d.Approve(req.ID); err != nil {
			return errResponse(err)
		}
		return Response{OK: true}

	case "deny":
		if req.ID == "" {
			return errResponse(errors.New("deny requires an id"))
		}
		if err := d.Deny(req.ID); err != nil {
			return errResponse(err)
		}
		return Response{OK: true}

	default:
		return errResponse(fmt.Errorf("unknown cmd %q", req.Cmd))
	}
}

func errResponse(err error) Response {
	return Response{OK: false, Error: err.Error()}
}

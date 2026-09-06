package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"agentguard/engine"
)

// Request is one line-delimited JSON message a client (SDK, CLI, proxy) sends
// to the daemon over its Unix domain socket. Cmd selects which fields apply.
type Request struct {
	Cmd    string        `json:"cmd"`
	Actor  string        `json:"actor,omitempty"`
	Action engine.Action `json:"action,omitempty"`
	N      int           `json:"n,omitempty"`
	ID     string        `json:"id,omitempty"`
	Filter AuditFilter   `json:"filter,omitempty"`
}

// Response is the daemon's line-delimited JSON reply to one Request.
type Response struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Decision   *engine.Decision  `json:"decision,omitempty"`
	ApprovalID string            `json:"approval_id,omitempty"`
	LatencyMS  int64             `json:"latency_ms,omitempty"`
	Events     []AuditEvent      `json:"events,omitempty"`
	Pending    []PendingApproval `json:"pending,omitempty"`
}

const maxLineBytes = 1 << 20 // 1 MiB, generous for the small JSON payloads this protocol carries

// Serve listens on socketPath (a Unix domain socket, removing any stale file
// left over from a previous run) and handles requests against d until ctx is
// canceled. Each accepted connection may carry multiple sequential requests.
func Serve(ctx context.Context, socketPath string, d *Daemon) error {
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
		return Response{OK: true}

	case "evaluate":
		result := d.Evaluate(req.Actor, req.Action)
		return Response{OK: true, Decision: &result.Decision, ApprovalID: result.ApprovalID, LatencyMS: result.LatencyMS}

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

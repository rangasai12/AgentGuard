package daemon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rangasai12/AgentGuard/engine"
)

// shortSocketPath returns a Unix domain socket path under /tmp rather than
// t.TempDir(), because Unix socket paths are capped at ~104 bytes on macOS/BSD
// and t.TempDir()'s nested per-test directories routinely exceed that.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	path := filepath.Join("/tmp", fmt.Sprintf("ag-%s.sock", hex.EncodeToString(buf)))
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

// testClient is a minimal synchronous client over the daemon's line-delimited
// JSON protocol, standing in for what the Python SDK and CLI do for real.
type testClient struct {
	conn    net.Conn
	scanner *bufio.Scanner
}

func dialTestDaemon(t *testing.T, socketPath string) *testClient {
	t.Helper()
	var conn net.Conn
	var err error
	// The daemon's listener may not be up yet on the very first attempt.
	for i := 0; i < 100; i++ {
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dialing daemon socket: %v", err)
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), maxLineBytes)
	return &testClient{conn: conn, scanner: sc}
}

func (c *testClient) send(t *testing.T, req Request) Response {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if _, err := c.conn.Write(append(data, '\n')); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if !c.scanner.Scan() {
		t.Fatalf("no response from daemon (scanner err: %v)", c.scanner.Err())
	}
	var resp Response
	if err := json.Unmarshal(c.scanner.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

func startTestServer(t *testing.T) (*Daemon, string) {
	t.Helper()
	policy, err := engine.ParsePolicy([]byte(daemonTestPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	audit, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	d := New(policy, audit)
	d.PolicyPath = "test-policy.yaml"

	socketPath := shortSocketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Serve(ctx, socketPath, d, false) }()
	t.Cleanup(func() {
		cancel()
		_ = audit.Close()
	})
	return d, socketPath
}

func TestSocketAPIPing(t *testing.T) {
	d, socketPath := startTestServer(t)
	c := dialTestDaemon(t, socketPath)
	resp := c.send(t, Request{Cmd: "ping"})
	if !resp.OK {
		t.Fatalf("expected ok ping response, got %+v", resp)
	}
	if resp.PolicyHash == "" || resp.PolicyHash != d.Policy().Hash {
		t.Fatalf("expected ping to report the daemon's policy hash %q, got %+v", d.Policy().Hash, resp)
	}
	if resp.PolicyPath != "test-policy.yaml" {
		t.Fatalf("expected ping to report the daemon's policy path, got %+v", resp)
	}
}

// TestServeRefusesToClobberALiveDaemon guards against the bug this was
// written to fix: a second `daemon start` on an already-occupied socket
// path used to silently os.RemoveAll the first daemon's socket and take
// over, orphaning it rather than erroring. Serve must now refuse unless
// force is true.
func TestServeRefusesToClobberALiveDaemon(t *testing.T) {
	policy, err := engine.ParsePolicy([]byte(daemonTestPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	audit1, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = audit1.Close() })
	d1 := New(policy, audit1)
	d1.PolicyPath = "first.yaml"

	socketPath := shortSocketPath(t)
	ctx1, cancel1 := context.WithCancel(context.Background())
	t.Cleanup(cancel1)
	go func() { _ = Serve(ctx1, socketPath, d1, false) }()
	dialTestDaemon(t, socketPath).conn.Close() // wait for it to come up

	audit2, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = audit2.Close() })
	d2 := New(policy, audit2)
	d2.PolicyPath = "second.yaml"

	if err := Serve(context.Background(), socketPath, d2, false); err == nil {
		t.Fatal("expected Serve to refuse to start over a live daemon without force")
	}

	// The first daemon must still be reachable — not orphaned by an
	// unlink the refused second Serve call should never have performed.
	resp := dialTestDaemon(t, socketPath).send(t, Request{Cmd: "ping"})
	if resp.PolicyPath != "first.yaml" {
		t.Fatalf("expected the original daemon to still be serving, got %+v", resp)
	}

	// force:true still takes over, matching today's documented escape hatch.
	// Serve's os.RemoveAll+Listen races the still-running first daemon's
	// listener on the same path (it isn't told to stop), so poll for the
	// takeover to actually complete rather than trusting the first
	// successful dial.
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	go func() { _ = Serve(ctx2, socketPath, d2, true) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp = dialTestDaemon(t, socketPath).send(t, Request{Cmd: "ping"})
		if resp.PolicyPath == "second.yaml" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected --force to take over the socket, got %+v", resp)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSocketAPIEvaluateAllowAndDeny(t *testing.T) {
	_, socketPath := startTestServer(t)
	c := dialTestDaemon(t, socketPath)

	resp := c.send(t, Request{Cmd: "evaluate", Actor: "agent-1", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/workspace/x"}})
	if !resp.OK || resp.Decision == nil || resp.Decision.Result != engine.Allow {
		t.Fatalf("expected allow decision, got %+v", resp)
	}
	if resp.EventID == "" {
		t.Fatalf("expected evaluate to return an event_id for later report, got %+v", resp)
	}

	resp = c.send(t, Request{Cmd: "evaluate", Actor: "agent-1", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/etc/passwd"}})
	if !resp.OK || resp.Decision == nil || resp.Decision.Result != engine.Deny {
		t.Fatalf("expected deny decision, got %+v", resp)
	}
}

func TestSocketAPIUnknownCmd(t *testing.T) {
	_, socketPath := startTestServer(t)
	c := dialTestDaemon(t, socketPath)
	resp := c.send(t, Request{Cmd: "not_a_real_command"})
	if resp.OK {
		t.Fatal("expected error response for unknown command")
	}
}

func TestSocketAPIApprovalFlowAcrossConnections(t *testing.T) {
	_, socketPath := startTestServer(t)

	// One connection blocks on an evaluate call requiring approval...
	evalConn := dialTestDaemon(t, socketPath)
	respCh := make(chan Response, 1)
	go func() {
		respCh <- evalConn.send(t, Request{
			Cmd:    "evaluate",
			Actor:  "agent-1",
			Action: engine.Action{Type: engine.ActionShell, Command: "rm -rf /workspace/build"},
		})
	}()

	// ...while a second connection discovers and approves it.
	adminConn := dialTestDaemon(t, socketPath)
	var pendingID string
	deadline := time.After(time.Second)
	for pendingID == "" {
		resp := adminConn.send(t, Request{Cmd: "pending_approvals"})
		if len(resp.Pending) == 1 {
			pendingID = resp.Pending[0].ID
			break
		}
		select {
		case <-deadline:
			t.Fatal("approval never appeared over the socket API")
		case <-time.After(10 * time.Millisecond):
		}
	}

	approveResp := adminConn.send(t, Request{Cmd: "approve", ID: pendingID})
	if !approveResp.OK {
		t.Fatalf("approve failed: %+v", approveResp)
	}

	select {
	case resp := <-respCh:
		if resp.Decision == nil || resp.Decision.Result != engine.Allow {
			t.Fatalf("expected the blocked evaluate call to resolve Allow, got %+v", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("evaluate call never returned after approval")
	}
}

func TestSocketAPIAuditTailOverSocket(t *testing.T) {
	_, socketPath := startTestServer(t)
	c := dialTestDaemon(t, socketPath)

	c.send(t, Request{Cmd: "evaluate", Actor: "a", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/workspace/x"}})
	c.send(t, Request{Cmd: "evaluate", Actor: "a", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/etc/passwd"}})

	resp := c.send(t, Request{Cmd: "audit_tail", N: 10})
	if !resp.OK || len(resp.Events) != 2 {
		t.Fatalf("expected 2 audit events over the socket, got %+v", resp)
	}
}

func TestSocketAPIReportOutcomeRoundTrip(t *testing.T) {
	_, socketPath := startTestServer(t)
	c := dialTestDaemon(t, socketPath)

	eval := c.send(t, Request{Cmd: "evaluate", Actor: "a", RunID: "run-1", AgentVersion: "2.0", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/workspace/x"}})
	if !eval.OK || eval.EventID == "" {
		t.Fatalf("evaluate: %+v", eval)
	}

	// A report over a *different* connection, as an SDK's connect-per-call
	// client would do.
	c2 := dialTestDaemon(t, socketPath)
	rep := c2.send(t, Request{Cmd: "report", ID: eval.EventID, Outcome: &Outcome{Status: OutcomeSuccess, ExecMS: 7, Output: "ok"}})
	if !rep.OK {
		t.Fatalf("report: %+v", rep)
	}

	tail := c.send(t, Request{Cmd: "audit_tail", N: 10})
	if !tail.OK || len(tail.Events) != 1 {
		t.Fatalf("expected exactly one merged event over the socket, got %+v", tail)
	}
	ev := tail.Events[0]
	if ev.EventID != eval.EventID || ev.RunID != "run-1" || ev.AgentVersion != "2.0" {
		t.Errorf("identity fields not round-tripped: %+v", ev)
	}
	if ev.Outcome == nil || ev.Outcome.Status != OutcomeSuccess || ev.Outcome.ExecMS != 7 || ev.Outcome.Output != "ok" {
		t.Errorf("expected the reported outcome on the event, got %+v", ev.Outcome)
	}

	// Filtering by run id works over the socket too.
	byRun := c.send(t, Request{Cmd: "audit_query", Filter: AuditFilter{RunID: "run-1"}})
	if !byRun.OK || len(byRun.Events) != 1 {
		t.Errorf("expected run_id filter to match the event, got %+v", byRun)
	}

	// Malformed reports are rejected with an error, not silently dropped.
	if bad := c2.send(t, Request{Cmd: "report", ID: eval.EventID}); bad.OK {
		t.Error("expected report without an outcome to fail")
	}
	if bad := c2.send(t, Request{Cmd: "report", Outcome: &Outcome{Status: OutcomeSuccess}}); bad.OK {
		t.Error("expected report without an id to fail")
	}
}

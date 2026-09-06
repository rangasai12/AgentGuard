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

	"agentguard/engine"
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

	socketPath := shortSocketPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Serve(ctx, socketPath, d) }()
	t.Cleanup(func() {
		cancel()
		_ = audit.Close()
	})
	return d, socketPath
}

func TestSocketAPIPing(t *testing.T) {
	_, socketPath := startTestServer(t)
	c := dialTestDaemon(t, socketPath)
	resp := c.send(t, Request{Cmd: "ping"})
	if !resp.OK {
		t.Fatalf("expected ok ping response, got %+v", resp)
	}
}

func TestSocketAPIEvaluateAllowAndDeny(t *testing.T) {
	_, socketPath := startTestServer(t)
	c := dialTestDaemon(t, socketPath)

	resp := c.send(t, Request{Cmd: "evaluate", Actor: "agent-1", Action: engine.Action{Type: engine.ActionFSWrite, Path: "/workspace/x"}})
	if !resp.OK || resp.Decision == nil || resp.Decision.Result != engine.Allow {
		t.Fatalf("expected allow decision, got %+v", resp)
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

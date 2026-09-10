package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentguard/approval"
	"agentguard/daemon"
	"agentguard/engine"
)

const proxyTestPolicy = `
version: 1
mcp:
  default: deny
  servers:
    - name: payments-mcp
      default: deny
      tools:
        - name: list_transactions
          allow: true
        - name: charge_customer
          require_approval: true
        - name: refund_customer
          deny: true
          reason: "refunds go through support"
`

func newTestProxy(t *testing.T, approve approval.Func) (*Proxy, *daemon.AuditLogger) {
	t.Helper()
	policy, err := engine.ParsePolicy([]byte(proxyTestPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	audit, err := daemon.NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	return &Proxy{Policy: policy, Audit: audit, ServerName: "payments-mcp", Actor: "test-agent", Approve: approve}, audit
}

// harness wires a Proxy between an in-memory "client" and a hand-rolled
// in-memory "server" (a goroutine reading requests and writing canned
// responses), so the real line-protocol parsing/forwarding/interception logic
// runs exactly as it would against a real subprocess, without spawning one.
type harness struct {
	clientToProxyW io.WriteCloser // test writes client requests here
	proxyToClientR io.ReadCloser  // test reads what the proxy sent the client from here
	done           chan error
}

func startHarness(t *testing.T, p *Proxy, serverHandler func(req rpcMessage) (resp any, forwardOK bool)) *harness {
	t.Helper()

	clientToProxyR, clientToProxyW := io.Pipe()
	proxyToClientR, proxyToClientW := io.Pipe()
	proxyToServerR, proxyToServerW := io.Pipe()
	serverToProxyR, serverToProxyW := io.Pipe()

	// Fake "server": reads one JSON-RPC line at a time, hands it to
	// serverHandler, and writes back the response if forwardOK is true (a
	// real server would never see a denied call at all, but callers use
	// forwardOK=false to assert that).
	go func() {
		scanner := bufio.NewScanner(proxyToServerR)
		scanner.Buffer(make([]byte, 4096), maxLineBytes)
		for scanner.Scan() {
			var req rpcMessage
			_ = json.Unmarshal(scanner.Bytes(), &req)
			resp, ok := serverHandler(req)
			if !ok || resp == nil {
				continue
			}
			data, _ := json.Marshal(resp)
			_, _ = serverToProxyW.Write(append(data, '\n'))
		}
	}()

	h := &harness{clientToProxyW: clientToProxyW, proxyToClientR: proxyToClientR, done: make(chan error, 1)}
	go func() {
		h.done <- p.run(context.Background(), clientToProxyR, proxyToClientW, serverToProxyR, proxyToServerW)
	}()
	return h
}

func (h *harness) sendClient(t *testing.T, msg any) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := h.clientToProxyW.Write(append(data, '\n')); err != nil {
		t.Fatalf("write client request: %v", err)
	}
}

func (h *harness) readClientResponse(t *testing.T) map[string]any {
	t.Helper()
	sc := bufio.NewScanner(h.proxyToClientR)
	sc.Buffer(make([]byte, 4096), maxLineBytes)
	done := make(chan bool, 1)
	go func() { done <- sc.Scan() }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatalf("no response reached the client (scanner err: %v)", sc.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a response to reach the client")
	}
	var out map[string]any
	if err := json.Unmarshal(sc.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal client response: %v", err)
	}
	return out
}

func toolCallRequest(id, tool string) map[string]any {
	return toolCallRequestWithArgs(id, tool, map[string]any{})
}

func toolCallRequestWithArgs(id, tool string, args map[string]any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": args},
	}
}

func TestProxyForwardsAllowedToolCall(t *testing.T) {
	p, audit := newTestProxy(t, nil)
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"ok": true}}, true
	})

	p.RunID, p.AgentVersion = "run-7", "3.1"
	h.sendClient(t, toolCallRequestWithArgs("1", "list_transactions", map[string]any{"account": "acc_123", "limit": 5}))
	resp := h.readClientResponse(t)
	if _, isError := resp["error"]; isError {
		t.Fatalf("expected the allowed call to be forwarded and succeed, got %+v", resp)
	}
	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Allow {
		t.Fatalf("expected one Allow audit event, got %+v", events)
	}
	ev := events[0]
	if ev.Action == nil || ev.Action.Args["account"] != "acc_123" || ev.Action.Args["limit"] != float64(5) {
		t.Errorf("expected the tool call's arguments on the audit event, got %+v", ev.Action)
	}
	if ev.RunID != "run-7" || ev.AgentVersion != "3.1" || ev.EventID == "" {
		t.Errorf("expected run/version/event identity on the audit event, got %+v", ev)
	}
	// The proxy observed the server's response on its way back to the
	// client (before forwarding it), so the outcome is already recorded.
	if ev.Outcome == nil || ev.Outcome.Status != daemon.OutcomeSuccess {
		t.Fatalf("expected a success outcome reported from the server's response, got %+v", ev.Outcome)
	}
	if !strings.Contains(ev.Outcome.Output, `"ok":true`) || ev.Outcome.OutputBytes == 0 || ev.Outcome.OutputSHA256 == "" {
		t.Errorf("expected the result preview, size, and hash on the outcome, got %+v", ev.Outcome)
	}
}

func TestProxyAttachesToolDescriptionOnce(t *testing.T) {
	p, audit := newTestProxy(t, nil)
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		if req.Method == "tools/list" {
			return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"tools": []map[string]any{
				{"name": "list_transactions", "description": "List a customer's recent transactions."},
				{"name": "charge_customer", "description": "Charge a card."},
			}}}, true
		}
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"ok": true}}, true
	})

	// tools/list passes through and is answered normally...
	h.sendClient(t, map[string]any{"jsonrpc": "2.0", "id": "l1", "method": "tools/list"})
	listResp := h.readClientResponse(t)
	if _, ok := listResp["result"]; !ok {
		t.Fatalf("tools/list response was not relayed: %+v", listResp)
	}
	// ...and the next two calls to the same tool carry the description once.
	h.sendClient(t, toolCallRequest("1", "list_transactions"))
	h.readClientResponse(t)
	h.sendClient(t, toolCallRequest("2", "list_transactions"))
	h.readClientResponse(t)

	events := audit.Tail(10)
	if len(events) != 2 {
		t.Fatalf("expected two audit events, got %+v", events)
	}
	if events[0].Action == nil || events[0].Action.Description != "List a customer's recent transactions." {
		t.Fatalf("first call should carry the tool description, got %+v", events[0].Action)
	}
	if events[1].Action == nil || events[1].Action.Description != "" {
		t.Fatalf("second call must not repeat the description, got %+v", events[1].Action)
	}
}

func TestProxyRecordsErrorOutcomeFromJSONRPCError(t *testing.T) {
	p, audit := newTestProxy(t, nil)
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		if string(req.ID) == `"err-rpc"` {
			return map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32603, "message": "upstream exploded"}}, true
		}
		// A tool-level failure: JSON-RPC success carrying result.isError.
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": "no such account"}}}}, true
	})

	h.sendClient(t, toolCallRequest("err-rpc", "list_transactions"))
	h.readClientResponse(t)
	h.sendClient(t, toolCallRequest("err-tool", "list_transactions"))
	h.readClientResponse(t)

	events := audit.Tail(10)
	if len(events) != 2 {
		t.Fatalf("expected two audit events, got %+v", events)
	}
	if o := events[0].Outcome; o == nil || o.Status != daemon.OutcomeError || !strings.Contains(o.Error, "upstream exploded") {
		t.Errorf("expected a JSON-RPC error to be recorded as an error outcome with the error body, got %+v", o)
	}
	if o := events[1].Outcome; o == nil || o.Status != daemon.OutcomeError || !strings.Contains(o.Output, "no such account") {
		t.Errorf("expected result.isError to be recorded as an error outcome with the result preview, got %+v", o)
	}
}

func TestProxyDeniedCallHasNoOutcome(t *testing.T) {
	p, audit := newTestProxy(t, nil)
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"ok": true}}, true
	})

	h.sendClient(t, toolCallRequest("9", "refund_customer"))
	h.readClientResponse(t)
	// A server-originated *request* to the client that happens to reuse the
	// same id must not be mistaken for a response to the denied (never
	// forwarded) call, nor for anything else in flight.
	h.sendClient(t, map[string]any{"jsonrpc": "2.0", "id": "ping-1", "method": "ping"})
	h.readClientResponse(t)

	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Deny {
		t.Fatalf("expected exactly one Deny audit event, got %+v", events)
	}
	if events[0].Outcome != nil {
		t.Errorf("a denied call never ran, so it must have no outcome, got %+v", events[0].Outcome)
	}
	p.mu.Lock()
	n := len(p.inflight)
	p.mu.Unlock()
	if n != 0 {
		t.Errorf("nothing should be left in flight, got %d", n)
	}
}

func TestProxyBlocksDeniedToolCallWithoutReachingServer(t *testing.T) {
	p, audit := newTestProxy(t, nil)
	serverSawCall := false
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		if req.Method == "tools/call" {
			serverSawCall = true
		}
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"ok": true}}, true
	})

	h.sendClient(t, toolCallRequest("2", "refund_customer"))
	resp := h.readClientResponse(t)
	errObj, isError := resp["error"].(map[string]any)
	if !isError {
		t.Fatalf("expected a denied tool call to get an error response, got %+v", resp)
	}
	if msg, _ := errObj["message"].(string); msg == "" {
		t.Error("expected a non-empty error message")
	}
	if serverSawCall {
		t.Error("denied tool call must never reach the real server")
	}

	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Deny {
		t.Errorf("expected one Deny audit event, got %+v", events)
	}
}

func TestProxyRequiresApprovalAndHonorsApproveFunc(t *testing.T) {
	p, audit := newTestProxy(t, func(action engine.Action, decision engine.Decision, timeout time.Duration) engine.Result {
		if action.Tool != "charge_customer" {
			t.Errorf("unexpected tool requiring approval: %s", action.Tool)
		}
		return engine.Allow
	})
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"ok": true}}, true
	})

	h.sendClient(t, toolCallRequest("3", "charge_customer"))
	resp := h.readClientResponse(t)
	if _, isError := resp["error"]; isError {
		t.Fatalf("expected the human-approved charge to be forwarded, got %+v", resp)
	}
	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Allow {
		t.Errorf("expected the audit log to record the approved decision, not the initial require_approval, got %+v", events)
	}
}

func TestProxyApproveFuncNilFallsBackToOnTimeoutDeny(t *testing.T) {
	// No Approve func at all (as if launched with no TTY, matching PromptTTY's
	// "" return) and the policy has no explicit escalation.on_timeout, so it
	// must fail closed (default Deny) rather than accidentally forwarding.
	p, audit := newTestProxy(t, nil)
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"ok": true}}, true
	})

	h.sendClient(t, toolCallRequest("4", "charge_customer"))
	resp := h.readClientResponse(t)
	if _, isError := resp["error"]; !isError {
		t.Fatalf("expected no-approval-available to fail closed (deny), got %+v", resp)
	}
	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Deny {
		t.Errorf("expected a Deny audit event, got %+v", events)
	}
}

func TestProxyClosesServerStdinWhenClientInputEnds(t *testing.T) {
	// Regression test for a real deadlock found in manual testing: a real
	// subprocess blocked reading its own stdin never sees EOF unless the
	// proxy closes its write-end of the server's stdin pipe once the
	// client's input stream ends. A pipe-based harness like the other tests
	// here doesn't surface this because nothing downstream cares whether the
	// pipe is closed — so this test asserts on serverIn.Close() directly.
	p, _ := newTestProxy(t, nil)

	clientToProxyR, clientToProxyW := io.Pipe()
	proxyToServerR, proxyToServerW := io.Pipe()
	serverToProxyR, _ := io.Pipe()

	closed := make(chan struct{})
	sw := &closeTrackingWriteCloser{WriteCloser: proxyToServerW, onClose: func() { close(closed) }}

	runDone := make(chan error, 1)
	go func() { runDone <- p.run(context.Background(), clientToProxyR, io.Discard, serverToProxyR, sw) }()

	// Drain whatever the proxy forwards so pumpClientToServer doesn't block on a full pipe.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := proxyToServerR.Read(buf); err != nil {
				return
			}
		}
	}()

	if err := clientToProxyW.Close(); err != nil { // simulate the client's stdin (our own os.Stdin) hitting EOF
		t.Fatalf("closing client writer: %v", err)
	}

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy never closed the server's stdin pipe after client input ended — a real subprocess would hang forever")
	}

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not return after client EOF")
	}
}

type closeTrackingWriteCloser struct {
	io.WriteCloser
	onClose func()
}

func (c *closeTrackingWriteCloser) Close() error {
	err := c.WriteCloser.Close()
	c.onClose()
	return err
}

// TestProxyConcurrentWritesToClientDontInterleave drives many large denied
// tool calls (answered by pumpClientToServer directly) concurrently with many
// large forwarded server responses (relayed by pumpLines), and asserts every
// line the client receives is still valid, complete JSON — i.e. no two
// messages got interleaved mid-write. Run with -race to also catch the data
// race directly.
func TestProxyConcurrentWritesToClientDontInterleave(t *testing.T) {
	p, _ := newTestProxy(t, nil)
	const n = 200
	bigText := strings.Repeat("x", 8192) // comfortably larger than typical pipe atomic-write sizes

	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"text": bigText}}, true
	})

	go func() {
		for i := 0; i < n; i++ {
			// Alternate an allowed call (forwarded, answered by the fake
			// server) with a denied call (answered directly by the proxy),
			// so both writers to clientOut are active concurrently.
			if i%2 == 0 {
				h.sendClient(t, toolCallRequest(fmt.Sprintf("allow-%d", i), "list_transactions"))
			} else {
				h.sendClient(t, toolCallRequest(fmt.Sprintf("deny-%d", i), "refund_customer"))
			}
		}
	}()

	sc := bufio.NewScanner(h.proxyToClientR)
	sc.Buffer(make([]byte, 4096), maxLineBytes)
	for i := 0; i < n; i++ {
		if !sc.Scan() {
			t.Fatalf("expected %d responses, got %d (err: %v)", n, i, sc.Err())
		}
		var out map[string]any
		if err := json.Unmarshal(sc.Bytes(), &out); err != nil {
			t.Fatalf("response %d is not valid JSON (interleaved write?): %v\nraw: %s", i, err, sc.Bytes())
		}
	}
}

func TestProxyPassesThroughNonToolCallMethods(t *testing.T) {
	p, _ := newTestProxy(t, nil)
	h := startHarness(t, p, func(req rpcMessage) (any, bool) {
		if req.Method != "initialize" {
			t.Errorf("expected the server to see the untouched 'initialize' method, got %q", req.Method)
		}
		return map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"protocolVersion": "2024-11-05"}}, true
	})

	h.sendClient(t, map[string]any{"jsonrpc": "2.0", "id": "0", "method": "initialize", "params": map[string]any{}})
	resp := h.readClientResponse(t)
	if _, isError := resp["error"]; isError {
		t.Fatalf("expected pass-through method to succeed, got %+v", resp)
	}
}

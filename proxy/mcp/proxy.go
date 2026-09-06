// Package mcp implements AgentGuard's MCP enforcement point: a proxy that
// speaks the Model Context Protocol on both sides, sitting between an agent
// (the MCP client) and a real MCP server. Every `tools/call` request is
// evaluated against policy before being forwarded; everything else passes
// through unchanged. This requires zero code changes to either the agent or
// the MCP server — only the launch command changes (point it at the proxy
// instead of the real server).
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"agentguard/approval"
	"agentguard/daemon"
	"agentguard/engine"
)

// maxLineBytes bounds a single MCP JSON-RPC message. The MCP stdio transport
// requires one message per line with no embedded newlines.
const maxLineBytes = 4 << 20 // 4 MiB, generous for tool call payloads

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type toolCallParams struct {
	Name string `json:"name"`
}

// Proxy intercepts tools/call requests between an MCP client and server.
type Proxy struct {
	Policy     *engine.Policy
	Audit      *daemon.AuditLogger // may be nil to disable audit logging
	ServerName string
	Actor      string
	Approve    approval.Func
}

// New returns a Proxy that prompts for approval on the controlling terminal
// (falling back to the policy's on_timeout setting when none is available).
func New(policy *engine.Policy, audit *daemon.AuditLogger, serverName, actor string) *Proxy {
	return &Proxy{Policy: policy, Audit: audit, ServerName: serverName, Actor: actor, Approve: approval.PromptTTY}
}

// RunCommand spawns command as the real MCP server and proxies between it and
// clientIn/clientOut (the agent), forwarding the subprocess's stderr through
// unchanged so its diagnostics aren't lost. It blocks until the subprocess
// exits or ctx is canceled.
func (p *Proxy) RunCommand(ctx context.Context, command string, args []string, clientIn io.Reader, clientOut io.Writer, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stderr = stderr

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("wiring server stdin: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("wiring server stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", command, err)
	}

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- p.run(ctx, clientIn, clientOut, serverOut, serverIn) }()

	waitErr := cmd.Wait()
	runErr := <-runErrCh
	if waitErr != nil {
		return fmt.Errorf("%s: %w", command, waitErr)
	}
	return runErr
}

// run wires the two directions of a proxied session: client requests flow
// through handleClientLine (which may intercept and short-circuit tool
// calls), and server responses pass through unchanged. It returns when
// either side reaches EOF/errors, or ctx is canceled.
//
// serverIn must be closed once the client's input ends, or the subprocess on
// the other end (blocked reading its own stdin) never sees EOF and hangs
// forever even though nothing is wrong — this bit us during manual testing
// against a real subprocess (a fake MCP server left running after `agentctl
// mcp-proxy`'s own stdin closed), which a pipe-only unit test does not
// surface because nothing downstream cares whether the pipe is closed.
func (p *Proxy) run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, serverOut io.Reader, serverIn io.WriteCloser) error {
	done := make(chan error, 2)

	// Both directions can write to clientOut concurrently: pumpClientToServer
	// writes synthesized deny/error responses, pumpLines writes forwarded
	// server responses. Without synchronization, two large-enough concurrent
	// messages could interleave mid-write and corrupt the one-message-per-line
	// framing the MCP stdio transport requires. writeLine issues exactly one
	// Write per message, so a plain mutex around clientOut is sufficient.
	syncOut := &syncWriter{w: clientOut}

	go func() { done <- p.pumpClientToServer(clientIn, syncOut, serverIn) }()
	go func() { done <- pumpLines(serverOut, syncOut) }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Proxy) pumpClientToServer(clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser) error {
	defer serverIn.Close()

	scanner := bufio.NewScanner(clientIn)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		forward, response := p.handleClientLine(line)
		if response != nil {
			if err := writeLine(clientOut, response); err != nil {
				return err
			}
			continue
		}
		if err := writeLine(serverIn, forward); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func pumpLines(src io.Reader, dst io.Writer) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	for scanner.Scan() {
		if err := writeLine(dst, scanner.Bytes()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// writeLine writes line plus a trailing newline as a single Write call, so
// that a mutex-guarded destination (see syncWriter) only needs to serialize
// one call per message rather than protect a multi-call critical section.
func writeLine(w io.Writer, line []byte) error {
	buf := make([]byte, len(line)+1)
	copy(buf, line)
	buf[len(line)] = '\n'
	_, err := w.Write(buf)
	return err
}

// syncWriter serializes Write calls from multiple goroutines onto one
// underlying writer.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// handleClientLine inspects one line from the client. If it is a tools/call
// request that policy denies, it returns a synthesized JSON-RPC error
// response (to be sent to the client) and forward == nil, so nothing reaches
// the real server. Otherwise it returns the original line unchanged to be
// forwarded as-is.
func (p *Proxy) handleClientLine(line []byte) (forward []byte, response []byte) {
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		// Not a JSON-RPC message we understand; pass it through rather than
		// breaking the session over a shape we don't recognize.
		return line, nil
	}
	if msg.Method != "tools/call" {
		return line, nil
	}
	var params toolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		return line, nil
	}

	action := engine.Action{Actor: p.Actor, Type: engine.ActionMCPTool, Server: p.ServerName, Tool: params.Name}
	decision := p.evaluate(action)
	if decision.Result == engine.Allow {
		return line, nil
	}
	return nil, marshalErrorResponse(msg.ID, decision)
}

func (p *Proxy) evaluate(action engine.Action) engine.Decision {
	start := time.Now()
	decision := engine.Evaluate(p.Policy, action)
	final := decision

	if decision.Result == engine.RequireApproval {
		timeout := time.Duration(p.Policy.ApprovalTimeoutSeconds()) * time.Second
		var result engine.Result
		if p.Approve != nil {
			result = p.Approve(action, decision, timeout)
		}
		if result == "" {
			result = p.Policy.OnTimeoutResult()
		}
		final = engine.Decision{Result: result, MatchedRule: decision.MatchedRule, Reason: decision.Reason}
	}

	if p.Audit != nil {
		_ = p.Audit.Log(daemon.AuditEvent{
			Timestamp:   start,
			Actor:       p.Actor,
			ActionType:  action.Type,
			Resource:    action.Resource(),
			Decision:    final.Result,
			MatchedRule: final.MatchedRule,
			Reason:      final.Reason,
			LatencyMS:   time.Since(start).Milliseconds(),
		})
	}
	return final
}

func marshalErrorResponse(id json.RawMessage, decision engine.Decision) []byte {
	reason := decision.Reason
	if reason == "" {
		reason = decision.MatchedRule
	}
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id,omitempty"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	resp.Error.Code = -32000
	resp.Error.Message = fmt.Sprintf("blocked by agentguard policy: %s", reason)
	data, err := json.Marshal(resp)
	if err != nil {
		// json.Marshal on this fixed, JSON-safe struct cannot fail in practice.
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32000,"message":"blocked by agentguard policy"}}`)
	}
	return data
}

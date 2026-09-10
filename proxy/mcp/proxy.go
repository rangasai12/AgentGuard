// Package mcp implements AgentGuard's MCP enforcement point: a proxy that
// speaks the Model Context Protocol on both sides, sitting between an agent
// (the MCP client) and a real MCP server. Every `tools/call` request is
// evaluated against policy before being forwarded; everything else passes
// through unchanged. This requires zero code changes to either the agent or
// the MCP server — only the launch command changes (point it at the proxy
// instead of the real server).
//
// Because the proxy also sees every response the server sends back, it
// correlates each forwarded tools/call with its JSON-RPC response by id and
// records the call's outcome (success/error, duration, a bounded preview of
// the result) against the same audit event the decision was logged as.
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
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// inflightCall is a forwarded tools/call awaiting its response.
type inflightCall struct {
	eventID string
	start   time.Time
}

// Proxy intercepts tools/call requests between an MCP client and server.
type Proxy struct {
	Policy     *engine.Policy
	Audit      *daemon.AuditLogger // may be nil to disable audit logging
	ServerName string
	Actor      string
	Approve    approval.Func

	// RunID and AgentVersion tag every audit event this proxy writes (see
	// daemon.DecisionRequest). The CLI defaults them from $AGENTGUARD_RUN_ID
	// and $AGENTGUARD_AGENT_VERSION, which an SDK-wrapped parent exports.
	RunID        string
	AgentVersion string

	// inflight maps a forwarded tools/call's raw JSON-RPC id to the audit
	// event it was logged as, so the response can be reported against it.
	// Keyed by the id's raw bytes: a server that re-encodes `1` as `1.0`
	// would miss correlation, which has not been observed in practice.
	// Entries whose response never arrives stay until the process exits —
	// proxies are one-per-session and short-lived, so this is not bounded.
	mu       sync.Mutex
	inflight map[string]inflightCall

	// listRequests holds the ids of forwarded tools/list requests so their
	// responses can be recognized; descriptions caches each tool's
	// description from those responses, and described records which
	// tools have already had it attached to an audit event (it is sent on
	// the first call to each tool only — see engine.Action.Description).
	listRequests map[string]bool
	descriptions map[string]string
	described    map[string]bool
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
// calls), and server responses pass through unchanged (after being matched
// against in-flight tool calls for outcome reporting). It returns when
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
	// writes synthesized deny/error responses, pumpServerToClient writes
	// forwarded server responses. Without synchronization, two large-enough
	// concurrent messages could interleave mid-write and corrupt the
	// one-message-per-line framing the MCP stdio transport requires.
	// writeLine issues exactly one Write per message, so a plain mutex
	// around clientOut is sufficient.
	syncOut := &syncWriter{w: clientOut}

	go func() { done <- p.pumpClientToServer(clientIn, syncOut, serverIn) }()
	go func() { done <- p.pumpServerToClient(serverOut, syncOut) }()

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

// pumpServerToClient relays every server line to the client unchanged. On
// the way through, a line that is a response (has an id and no method — a
// server's own requests to the client, e.g. sampling, carry a method and
// their own id space, so they must not be mistaken for responses) is
// matched against the in-flight tool calls and its outcome reported.
func (p *Proxy) pumpServerToClient(src io.Reader, dst io.Writer) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		p.observeServerLine(line)
		if err := writeLine(dst, line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// observeServerLine reports the outcome of a forwarded tools/call when line
// is its response. It never alters or withholds the line.
func (p *Proxy) observeServerLine(line []byte) {
	if p.Audit == nil {
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil || len(msg.ID) == 0 || msg.Method != "" {
		return
	}
	p.mu.Lock()
	call, ok := p.inflight[string(msg.ID)]
	if ok {
		delete(p.inflight, string(msg.ID))
	}
	isList := p.listRequests[string(msg.ID)]
	if isList {
		delete(p.listRequests, string(msg.ID))
	}
	p.mu.Unlock()
	if isList {
		p.rememberDescriptions(msg.Result)
		return
	}
	if !ok {
		return
	}

	o := daemon.Outcome{Status: daemon.OutcomeSuccess, ExecMS: time.Since(call.start).Milliseconds()}
	switch {
	case len(msg.Error) > 0:
		o.Status = daemon.OutcomeError
		o.Error = string(msg.Error)
	default:
		// MCP signals a tool-level failure inside a successful JSON-RPC
		// response via result.isError.
		var res struct {
			IsError bool `json:"isError"`
		}
		if json.Unmarshal(msg.Result, &res) == nil && res.IsError {
			o.Status = daemon.OutcomeError
		}
		o.Output = string(msg.Result)
	}
	_ = p.Audit.Report(call.eventID, o)
}

// rememberDescriptions caches tool descriptions from a tools/list result
// so the first tools/call to each tool can carry one.
func (p *Proxy) rememberDescriptions(result json.RawMessage) {
	var res struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	if json.Unmarshal(result, &res) != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.descriptions == nil {
		p.descriptions = make(map[string]string)
	}
	for _, t := range res.Tools {
		if t.Name != "" && t.Description != "" {
			p.descriptions[t.Name] = t.Description // daemon.Decide caps the length
		}
	}
}

// descriptionFor returns the cached description for tool the first time
// it is asked, and "" afterwards.
func (p *Proxy) descriptionFor(tool string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.descriptions[tool]
	if !ok || p.described[tool] {
		return ""
	}
	if p.described == nil {
		p.described = make(map[string]bool)
	}
	p.described[tool] = true
	return d
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
// forwarded as-is, remembering the call so its response can be reported.
func (p *Proxy) handleClientLine(line []byte) (forward []byte, response []byte) {
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		// Not a JSON-RPC message we understand; pass it through rather than
		// breaking the session over a shape we don't recognize.
		return line, nil
	}
	if msg.Method == "tools/list" && len(msg.ID) > 0 && p.Audit != nil {
		p.mu.Lock()
		if p.listRequests == nil {
			p.listRequests = make(map[string]bool)
		}
		p.listRequests[string(msg.ID)] = true
		p.mu.Unlock()
		return line, nil
	}
	if msg.Method != "tools/call" {
		return line, nil
	}
	var params toolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		return line, nil
	}

	action := engine.Action{Actor: p.Actor, Type: engine.ActionMCPTool, Server: p.ServerName, Tool: params.Name, Args: params.Arguments, Description: p.descriptionFor(params.Name)}
	res := daemon.Decide(p.Policy, p.Audit, daemon.DecisionRequest{
		Actor: p.Actor, RunID: p.RunID, AgentVersion: p.AgentVersion, Action: action,
	}, daemon.PromptAwaiter(p.Approve))
	if res.Decision.Result != engine.Allow {
		return nil, marshalErrorResponse(msg.ID, res.Decision)
	}
	if len(msg.ID) > 0 && p.Audit != nil {
		p.mu.Lock()
		if p.inflight == nil {
			p.inflight = make(map[string]inflightCall)
		}
		p.inflight[string(msg.ID)] = inflightCall{eventID: res.EventID, start: time.Now()}
		p.mu.Unlock()
	}
	return line, nil
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

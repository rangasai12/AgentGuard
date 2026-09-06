// Package network implements AgentGuard's network egress enforcement point:
// a local forward proxy that intercepts HTTPS via a locally-generated CA
// (the client must be pointed at this proxy and configured to trust that
// CA — see CA.CertPEM) so the domain/method-level policy in the plan can
// actually be enforced, not just guessed at from an opaque CONNECT tunnel.
// Opt-in per the plan: most policy enforcement happens at the SDK/MCP layer;
// this exists for the case where an agent's own code makes arbitrary HTTP
// calls no SDK wrapper or MCP proxy would ever see.
package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"agentguard/approval"
	"agentguard/daemon"
	"agentguard/engine"
)

// Proxy is an HTTP/HTTPS forward proxy that evaluates every request against
// policy before forwarding it.
type Proxy struct {
	Policy  *engine.Policy
	Audit   *daemon.AuditLogger // may be nil to disable audit logging
	Actor   string
	CA      *CA
	Approve approval.Func

	// UpstreamTLSConfig customizes how the proxy dials real origin servers
	// after intercepting a CONNECT tunnel. nil means the system default
	// trust store (real certificate verification) — the correct production
	// default. Tests override this to trust a local test server's
	// self-signed certificate. Set this before the first request is served;
	// it is read once to build the shared upstream transport.
	UpstreamTLSConfig *tls.Config

	transportOnce sync.Once
	transport     *http.Transport
}

// New returns a Proxy that prompts for approval on the controlling terminal.
func New(policy *engine.Policy, audit *daemon.AuditLogger, ca *CA, actor string) *Proxy {
	return &Proxy{Policy: policy, Audit: audit, Actor: actor, CA: ca, Approve: approval.PromptTTY}
}

// ListenAndServe starts the proxy on addr (e.g. "127.0.0.1:8080") and serves
// until ctx is canceled.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
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
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
		return
	}
	normalizePlainURL(req)
	p.serveLoop(conn, reader, req, false)
}

// handleConnect implements the HTTPS interception path: establish the
// tunnel, then terminate TLS ourselves using a certificate minted for the
// requested host, so subsequent requests inside the tunnel are visible in
// plaintext for policy evaluation (method-aware, not just domain-aware).
func (p *Proxy) handleConnect(conn net.Conn, req *http.Request) {
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host // no explicit port
	}

	// A raw-IP CONNECT target can be judged immediately, without ever
	// completing a TLS handshake for it — a cheap, early SSRF/exfil guard
	// that doesn't depend on decrypting anything.
	if isIPLiteral(host) {
		decision := p.evaluate(engine.Action{Actor: p.Actor, Type: engine.ActionNetwork, Domain: host, Method: "CONNECT", IsIPLiteral: true})
		if decision.Result != engine.Allow {
			writeSimpleResponse(conn, http.StatusForbidden, decision)
			return
		}
	}

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	leaf, err := p.CA.LeafFor(host)
	if err != nil {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	tlsReader := bufio.NewReader(tlsConn)
	firstReq, err := http.ReadRequest(tlsReader)
	if err != nil {
		return
	}
	firstReq.URL.Scheme = "https"
	firstReq.URL.Host = req.Host
	p.serveLoop(tlsConn, tlsReader, firstReq, true)
}

func normalizePlainURL(req *http.Request) {
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
}

// serveLoop evaluates req against policy, forwards or denies it, and — as
// long as the connection is meant to stay open — keeps reading further
// pipelined requests off reader, mirroring ordinary HTTP keep-alive. This
// applies equally to the plain-HTTP path and, inside the TLS tunnel, to the
// CONNECT path, so both support more than one request per connection.
func (p *Proxy) serveLoop(conn io.Writer, reader *bufio.Reader, req *http.Request, viaTLS bool) {
	for {
		if !p.serveOneRequest(conn, req, viaTLS) {
			return
		}
		next, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if viaTLS {
			next.URL.Scheme = "https"
			next.URL.Host = req.URL.Host
		} else {
			normalizePlainURL(next)
		}
		req = next
	}
}

// serveOneRequest evaluates one already-parsed HTTP request against policy
// and either forwards it upstream (relaying the response back to conn) or
// writes a synthesized deny response directly. It reports whether the
// caller should keep reading further requests off the same connection —
// false on a denial (fail closed: close rather than risk protocol desync)
// or a round-trip error, or when either side asked for the connection to
// close.
func (p *Proxy) serveOneRequest(conn io.Writer, req *http.Request, viaTLS bool) bool {
	host := req.URL.Hostname()
	action := engine.Action{
		Actor:       p.Actor,
		Type:        engine.ActionNetwork,
		Domain:      host,
		Method:      req.Method,
		IsIPLiteral: isIPLiteral(host),
	}
	decision := p.evaluate(action)
	if decision.Result != engine.Allow {
		writeSimpleResponse(conn, http.StatusForbidden, decision)
		return false
	}

	resp, err := p.roundTrip(req)
	if err != nil {
		writeErrorResponse(conn, err)
		return false
	}
	defer resp.Body.Close()
	_ = resp.Write(conn)
	return !resp.Close && !req.Close
}

// roundTrip forwards req to its real origin using one shared *http.Transport
// (built lazily on first use so tests can set UpstreamTLSConfig before any
// traffic flows), so repeated requests to the same host reuse connections
// instead of paying a fresh TCP+TLS handshake every time.
func (p *Proxy) roundTrip(req *http.Request) (*http.Response, error) {
	p.transportOnce.Do(func() {
		p.transport = &http.Transport{TLSClientConfig: p.UpstreamTLSConfig}
	})
	// Outbound requests must not carry proxy/server-side-only fields.
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	return p.transport.RoundTrip(outReq)
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

func isIPLiteral(host string) bool {
	return net.ParseIP(host) != nil
}

func writeSimpleResponse(w io.Writer, status int, decision engine.Decision) {
	reason := decision.Reason
	if reason == "" {
		reason = decision.MatchedRule
	}
	body := fmt.Sprintf("blocked by agentguard policy: %s\n", reason)
	resp := &http.Response{
		StatusCode: status,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Close:      true,
	}
	_ = resp.Write(w)
}

func writeErrorResponse(w io.Writer, err error) {
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("agentguard proxy error: %v\n", err))),
		Close:      true,
	}
	_ = resp.Write(w)
}

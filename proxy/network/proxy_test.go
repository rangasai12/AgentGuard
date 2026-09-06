package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentguard/daemon"
	"agentguard/engine"
)

const proxyTestPolicy = `
version: 1
network:
  default: deny
  allow:
    - domain: "allowed.example.com"
      methods: ["GET"]
    - domain: "localhost"
      methods: ["GET"]
  deny:
    - ip_literal: true
      reason: "no raw IPs"
escalation:
  approval_timeout_seconds: 1
  on_timeout: deny
`

func newTestProxy(t *testing.T) (*Proxy, *daemon.AuditLogger) {
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
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return &Proxy{Policy: policy, Audit: audit, Actor: "test-agent", CA: ca}, audit
}

// startProxy runs p on an ephemeral loopback port and returns its address.
func startProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close() // ListenAndServe re-listens; this only reserves a free port

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.ListenAndServe(ctx, addr) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("tcp", addr); err == nil {
			conn.Close()
			return addr
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("proxy at %s never came up", addr)
	return ""
}

func proxyClient(proxyAddr string, tlsConfig *tls.Config) *http.Client {
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}
}

func TestPlainHTTPAllowedRequestIsForwarded(t *testing.T) {
	p, audit := newTestProxy(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin, method=%s", r.Method)
	}))
	defer origin.Close()

	// The policy governs the domain, but the actual TCP dial still needs a
	// real, resolvable target — so route through "localhost:<origin's real
	// port>" rather than a policy-only placeholder domain that resolves
	// nowhere. Domain matching strips the port (see engine.Action.Domain),
	// so the policy rule for "localhost" still applies.
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parsing origin URL: %v", err)
	}
	proxyAddr := startProxy(t, p)
	client := proxyClient(proxyAddr, nil)

	req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	req.Host = "localhost:" + originURL.Port()
	req.URL.Host = "localhost:" + originURL.Port()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Allow {
		t.Errorf("expected one Allow audit event, got %+v", events)
	}
}

func TestPlainHTTPDeniedRequestNeverReachesOrigin(t *testing.T) {
	p, audit := newTestProxy(t)
	originHit := false
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
	}))
	defer origin.Close()

	proxyAddr := startProxy(t, p)
	client := proxyClient(proxyAddr, nil)

	req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	req.Host = "not-allowed.example.com"
	req.URL.Host = "not-allowed.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if originHit {
		t.Error("denied request must never reach the real origin")
	}
	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Deny {
		t.Errorf("expected one Deny audit event, got %+v", events)
	}
}

func TestPlainHTTPWrongMethodDenied(t *testing.T) {
	p, _ := newTestProxy(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin must not be reached for a method the policy doesn't allow")
	}))
	defer origin.Close()

	proxyAddr := startProxy(t, p)
	client := proxyClient(proxyAddr, nil)

	req, _ := http.NewRequest(http.MethodPost, origin.URL, nil)
	req.Host = "allowed.example.com"
	req.URL.Host = "allowed.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a POST when only GET is allowed, got %d", resp.StatusCode)
	}
}

func TestHTTPSInterceptionAllowedRequestIsForwarded(t *testing.T) {
	p, audit := newTestProxy(t)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello over https, path=%s", r.URL.Path)
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String() // "127.0.0.1:PORT"
	_, originPort, _ := net.SplitHostPort(originAddr)

	// httptest's fixed test certificate only covers example.com/127.0.0.1/::1,
	// not "localhost" (used below so the request also exercises a real DNS
	// name rather than the IP literal deny rule), so hostname verification
	// against it can't be made to match cleanly here; skip verification for
	// this synthetic origin only — production leaves UpstreamTLSConfig nil,
	// which performs real verification against real hostnames. The *client*
	// (below) separately trusts the proxy's own MITM CA, which is the trust
	// relationship a real user actually has to configure.
	p.UpstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}

	proxyAddr := startProxy(t, p)
	client := proxyClient(proxyAddr, tlsConfigTrusting(p.CA))

	targetURL := fmt.Sprintf("https://localhost:%s/some/path", originPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("https request through the intercepting proxy failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if string(body) != "hello over https, path=/some/path" {
		t.Errorf("unexpected body: %s", body)
	}

	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Allow || events[0].Resource != "GET localhost" {
		t.Errorf("expected one Allow audit event for the HTTPS request, got %+v", events)
	}
}

func TestHTTPSInterceptionDeniedRequestNeverReachesOrigin(t *testing.T) {
	p, audit := newTestProxy(t)
	originHit := false
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
	}))
	defer origin.Close()

	originAddr := origin.Listener.Addr().String()
	_, originPort, _ := net.SplitHostPort(originAddr)
	// httptest's fixed test certificate only covers example.com/127.0.0.1/::1,
	// not "localhost" (verified separately), so hostname verification against
	// it can't be made to match cleanly here; skip verification for this
	// synthetic origin only — production leaves UpstreamTLSConfig nil, which
	// performs real verification against real hostnames.
	p.UpstreamTLSConfig = &tls.Config{InsecureSkipVerify: true}

	proxyAddr := startProxy(t, p)
	client := proxyClient(proxyAddr, tlsConfigTrusting(p.CA))

	targetURL := fmt.Sprintf("https://blocked.example.com:%s/", originPort)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if originHit {
		t.Error("denied HTTPS request must never reach the real origin")
	}
	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Deny {
		t.Errorf("expected one Deny audit event, got %+v", events)
	}
}

func TestConnectToRawIPDeniedBeforeHandshake(t *testing.T) {
	p, audit := newTestProxy(t)
	proxyAddr := startProxy(t, p)
	client := proxyClient(proxyAddr, tlsConfigTrusting(p.CA))

	// A denied CONNECT is rejected before "200 Connection Established" is
	// ever sent, so net/http's client surfaces it as a failed dial (an
	// error), not as a *http.Response the caller could inspect — this is
	// standard Go http.Transport behavior for a failed proxy CONNECT, not
	// something this proxy controls.
	_, err := client.Get("https://127.0.0.1:9/") // port 9 (discard) — must never actually be dialed
	if err == nil {
		t.Fatal("expected the request to fail: a raw-IP CONNECT target must be denied before any tunnel is established")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("expected the CONNECT failure to mention Forbidden (403), got: %v", err)
	}

	events := audit.Tail(10)
	if len(events) != 1 || events[0].Decision != engine.Deny || events[0].ActionType != engine.ActionNetwork {
		t.Errorf("expected one Deny network audit event for the raw IP, got %+v", events)
	}
}

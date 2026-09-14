// cloud_cmd.go implements `agentctl cloud ...`: a CLI path from "I have no
// account" to "I have a running agentguard-forwarder" without touching a
// browser or reverse-engineering the REST API by hand — the exact gap an
// external developer hit (see CHANGELOG "Fix 3"). It talks to the same
// three endpoints the dashboard's own frontend uses
// (dashboard/web/src/api/client.ts): POST /api/signup, POST /api/agents,
// POST /v1/agents/register (the last one via agentguard-forwarder itself,
// not duplicated here).
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"
)

func runCloud(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: agentctl cloud <signup|agents> [flags]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "signup":
		return runCloudSignup(rest, stdout, stderr)
	case "agents":
		return runCloudAgents(rest, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: agentctl cloud <signup|agents> [flags]")
		return 2
	}
}

func runCloudSignup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cloud signup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiURL := fs.String("api-url", envOrDefault("AGENTGUARD_CONTROL_API", "http://127.0.0.1:8090"), "base URL of the agentguard-cloud API")
	company := fs.String("company", "", "company/organization name")
	email := fs.String("email", "", "account email")
	password := fs.String("password", "", "account password (min 8 characters)")
	statePath := fs.String("state", DefaultCloudSessionPath(), "where to save the session for later `cloud agents` commands")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *company == "" || *email == "" || *password == "" {
		fmt.Fprintln(stderr, "usage: agentctl cloud signup --company NAME --email EMAIL --password PASS [--api-url URL]")
		return 2
	}

	c := &cloudClient{base: *apiURL, http: &http.Client{Timeout: 10 * time.Second}}
	userID, tenantID, err := c.signUp(*company, *email, *password)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl cloud signup: %v\n", err)
		return 1
	}
	if err := EnsureParentDir(*statePath); err != nil {
		fmt.Fprintf(stderr, "agentctl cloud signup: %v\n", err)
		return 1
	}
	sess := cloudSessionState{APIURL: *apiURL, SessionCookie: c.cookie, TenantID: tenantID}
	if err := saveCloudSession(*statePath, sess); err != nil {
		fmt.Fprintf(stderr, "agentctl cloud signup: saving session to %s: %v\n", *statePath, err)
		return 1
	}
	fmt.Fprintf(stdout, "signed up as %s (user %s), tenant %s\n", *email, userID, tenantID)
	fmt.Fprintln(stdout, "next: agentctl cloud agents create <name> --register")
	return 0
}

func runCloudAgents(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "create" {
		fmt.Fprintln(stderr, "usage: agentctl cloud agents create [--register] [--tenant id] <name>")
		return 2
	}
	fs := flag.NewFlagSet("cloud agents create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apiURL := fs.String("api-url", "", "base URL of the agentguard-cloud API (default: the one saved by `cloud signup`)")
	tenantID := fs.String("tenant", "", "tenant id to create the agent under (default: the one saved by `cloud signup`)")
	statePath := fs.String("state", DefaultCloudSessionPath(), "session file saved by `cloud signup`")
	register := fs.Bool("register", false, "also run agentguard-forwarder -register-token=<token> -once, so the agent shows up connected immediately")
	forwarderPath := fs.String("forwarder-path", "agentguard-forwarder", "path to the agentguard-forwarder binary, used with --register")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(stderr, "usage: agentctl cloud agents create [--register] [--tenant id] <name>")
		return 2
	}
	name := rest[0]

	sess, err := loadCloudSession(*statePath)
	if err != nil || sess.SessionCookie == "" {
		fmt.Fprintf(stderr, "agentctl cloud agents create: no saved session at %s — run `agentctl cloud signup` first\n", *statePath)
		return 1
	}
	base := *apiURL
	if base == "" {
		base = sess.APIURL
	}
	tenant := *tenantID
	if tenant == "" {
		tenant = sess.TenantID
	}

	c := &cloudClient{base: base, http: &http.Client{Timeout: 10 * time.Second}, cookie: sess.SessionCookie}
	agentID, regToken, err := c.createAgent(tenant, name)
	if err != nil {
		fmt.Fprintf(stderr, "agentctl cloud agents create: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "created agent %q (id %s) in tenant %s\nregistration token: %s\n", name, agentID, tenant, regToken)

	if !*register {
		fmt.Fprintf(stdout, "next: %s -register-token=%s\n", *forwarderPath, regToken)
		return 0
	}
	fmt.Fprintf(stdout, "running %s -register-token=... -once\n", *forwarderPath)
	cmd := exec.Command(*forwarderPath, "-register-token="+regToken, "-once")
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(stderr, "agentctl cloud agents create: running %s: %v\n", *forwarderPath, err)
		return 1
	}
	return 0
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- session persistence -----------------------------------------------

// cloudSessionState is this command's only local persistence: the browser
// session cookie signup obtained (so `cloud agents create` can reuse it
// without asking for a password again) and which tenant/API it was for.
// Mirrors cmd/agentguard-forwarder/state.go's forwarderState — same shape
// of problem (a small local credential cache), same plain-JSON-file fix,
// not a shared type since the two processes have no common package to put
// one in without introducing a dependency neither otherwise needs.
type cloudSessionState struct {
	APIURL        string `json:"api_url,omitempty"`
	SessionCookie string `json:"session_cookie,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
}

// DefaultCloudSessionPath returns the default path `cloud signup` saves its
// session to and `cloud agents create` reads it from, overridable via
// AGENTGUARD_CLOUD_SESSION.
func DefaultCloudSessionPath() string {
	if v := os.Getenv("AGENTGUARD_CLOUD_SESSION"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home + "/.agentguard/cloud-session.json"
	}
	return os.TempDir() + "/agentguard-cloud-session.json"
}

func loadCloudSession(path string) (cloudSessionState, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cloudSessionState{}, nil
	}
	if err != nil {
		return cloudSessionState{}, err
	}
	var st cloudSessionState
	if err := json.Unmarshal(data, &st); err != nil {
		return cloudSessionState{}, err
	}
	return st, nil
}

func saveCloudSession(path string, st cloudSessionState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// --- HTTP client ---------------------------------------------------------

// cloudClient is a minimal, session-cookie-authenticated client for
// agentguard-cloud's browser-facing API (dashboard/server/webapi.go) — the
// only two calls `agentctl cloud` ever needs. Distinct from
// cmd/agentguard-forwarder's httpClient, which talks to the bearer-token
// Control API (dashboard/server/controlapi.go) instead; the two auth
// schemes and endpoint sets don't overlap, so this is not a duplicate of
// that client, and living in package main there, it isn't importable here
// even if it were.
type cloudClient struct {
	base   string
	http   *http.Client
	cookie string // the "ag_session" cookie value, once signUp has run
}

const cloudSessionCookieName = "ag_session"

func (c *cloudClient) signUp(companyName, email, password string) (userID, tenantID string, err error) {
	var resp struct {
		UserID   string `json:"user_id"`
		TenantID string `json:"tenant_id"`
	}
	httpResp, err := c.doJSON(http.MethodPost, "/api/signup", map[string]string{
		"company_name": companyName, "email": email, "password": password,
	}, &resp)
	if err != nil {
		return "", "", err
	}
	for _, ck := range httpResp.Cookies() {
		if ck.Name == cloudSessionCookieName {
			c.cookie = ck.Value
		}
	}
	if c.cookie == "" {
		return "", "", fmt.Errorf("signup succeeded but the server set no %s cookie", cloudSessionCookieName)
	}
	return resp.UserID, resp.TenantID, nil
}

func (c *cloudClient) createAgent(tenantID, name string) (agentID, registrationToken string, err error) {
	var resp struct {
		AgentID           string `json:"agent_id"`
		RegistrationToken string `json:"registration_token"`
	}
	path := "/api/agents?" + url.Values{"tenant_id": {tenantID}}.Encode()
	if _, err := c.doJSON(http.MethodPost, path, map[string]string{"name": name}, &resp); err != nil {
		return "", "", err
	}
	return resp.AgentID, resp.RegistrationToken, nil
}

// doJSON sends body as a JSON request, attaching the session cookie if one
// is set, and decodes a JSON response into out (nil to discard it). The
// *http.Response is returned (body already closed) so a caller can still
// read response headers, e.g. signUp reading Set-Cookie.
func (c *cloudClient) doJSON(method, path string, body any, out any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: cloudSessionCookieName, Value: c.cookie})
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return resp, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, errBody.Error)
		}
		return resp, fmt.Errorf("%s %s: %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("decoding response: %w", err)
		}
	}
	return resp, nil
}

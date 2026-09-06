//go:build darwin

package hardened

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentguard/engine"
)

func policyAllowingWrite(t *testing.T, dir string) *engine.Policy {
	t.Helper()
	p, err := engine.ParsePolicy([]byte(`
version: 1
filesystem:
  - allow: read_write
    paths: ["` + dir + `/**"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return p
}

func TestCompileProfileFilesystemDirectoryWrite(t *testing.T) {
	dir := t.TempDir()
	profile, err := CompileProfile(policyAllowingWrite(t, dir), "")
	if err != nil {
		t.Fatalf("CompileProfile: %v", err)
	}
	resolved, err := resolvePath(dir)
	if err != nil {
		t.Fatalf("resolvePath: %v", err)
	}
	if !strings.Contains(profile, `(subpath "`+resolved+`")`) {
		t.Errorf("expected profile to contain a subpath clause for the resolved dir, got:\n%s", profile)
	}
}

func TestCompileProfileRejectsUnsupportedGlob(t *testing.T) {
	p, err := engine.ParsePolicy([]byte(`
version: 1
filesystem:
  - allow: write
    paths: ["/workspace/*.go"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	_, err = CompileProfile(p, "")
	if !errors.Is(err, ErrUnsupportedPattern) {
		t.Fatalf("expected ErrUnsupportedPattern, got %v", err)
	}
}

func TestCompileProfileExactLiteralPath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	p, err := engine.ParsePolicy([]byte(`
version: 1
filesystem:
  - allow: write
    paths: ["` + file + `"]
`))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	profile, err := CompileProfile(p, "")
	if err != nil {
		t.Fatalf("CompileProfile: %v", err)
	}
	resolved, _ := resolvePath(file)
	if !strings.Contains(profile, `(literal "`+resolved+`")`) {
		t.Errorf("expected a literal clause, got:\n%s", profile)
	}
}

func TestCompileProfileNetworkScoping(t *testing.T) {
	noNetworkPolicy, _ := engine.ParsePolicy([]byte("version: 1\n"))
	profile, err := CompileProfile(noNetworkPolicy, "")
	if err != nil {
		t.Fatalf("CompileProfile: %v", err)
	}
	if strings.Contains(profile, "network") {
		t.Errorf("expected no network directives when policy has no network section, got:\n%s", profile)
	}

	withNetworkPolicy, _ := engine.ParsePolicy([]byte("version: 1\nnetwork:\n  default: deny\n"))
	profile, err = CompileProfile(withNetworkPolicy, "")
	if err != nil {
		t.Fatalf("CompileProfile: %v", err)
	}
	if !strings.Contains(profile, "(deny network*)") {
		t.Errorf("expected network to be denied when policy configures it but no proxy is given, got:\n%s", profile)
	}
	if strings.Contains(profile, "network-outbound") {
		t.Errorf("expected no allow-outbound clause without a proxy address, got:\n%s", profile)
	}

	profile, err = CompileProfile(withNetworkPolicy, "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("CompileProfile: %v", err)
	}
	if !strings.Contains(profile, `(allow network-outbound (remote ip "localhost:8080"))`) {
		t.Errorf("expected an allow clause scoped to the proxy's port, got:\n%s", profile)
	}
}

// The remaining tests actually invoke sandbox-exec via Run and check real
// enforcement, not just profile text — this is the only way to be sure the
// generated Scheme profile does what it claims, given how easy it is to get
// this undocumented profile language subtly wrong (see the package doc for
// the /tmp-symlink bug this caught during development).

func TestRunAllowsWritingToDevNull(t *testing.T) {
	// Regression test: writes to /dev/null were blocked by the first draft
	// of the base profile, breaking the extremely common `-o /dev/null` /
	// `2>/dev/null` pattern for reasons unrelated to anything the policy
	// actually restricts — found via the network+filesystem combined smoke
	// test documented in CHANGELOG.md.
	policy, _ := engine.ParsePolicy([]byte("version: 1\n"))
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, policy, "", "sh", []string{"-c", "echo discarded > /dev/null"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected writing to /dev/null to succeed, got error: %v (stderr: %s)", err, stderr.String())
	}
}

func TestRunActuallyRestrictsFilesystemWrites(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "workspace")
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	policy := policyAllowingWrite(t, workspace)

	outside := filepath.Join(dir, "blocked.txt")
	script := "echo ok > '" + filepath.Join(workspace, "ok.txt") + "' && echo blocked > '" + outside + "'"

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, policy, "", "sh", []string{"-c", script}, nil, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected the script to fail (the second write is outside the allowed workspace)")
	}
	if _, statErr := os.Stat(filepath.Join(workspace, "ok.txt")); statErr != nil {
		t.Errorf("expected the write inside the allowed workspace to succeed, got: %v (stderr: %s)", statErr, stderr.String())
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Error("expected the write outside the allowed workspace to be blocked, but the file was created")
	}
}

func TestRunDeniesAllNetworkWithoutProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	policy, _ := engine.ParsePolicy([]byte("version: 1\nnetwork:\n  default: deny\n"))

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Run(ctx, policy, "", "curl", []string{"-sS", "--max-time", "3", origin.URL}, nil, &stdout, &stderr)

	if err == nil {
		t.Fatalf("expected curl to fail with all network denied, got success (stdout: %s)", stdout.String())
	}
}

func TestRunAllowsOnlyTheConfiguredProxyAddress(t *testing.T) {
	allowedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("allowed-server-response"))
	}))
	defer allowedServer.Close()
	blockedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("blocked-server-response"))
	}))
	defer blockedServer.Close()

	policy, _ := engine.ParsePolicy([]byte("version: 1\nnetwork:\n  default: deny\n"))
	allowedAddr := allowedServer.Listener.Addr().String() // "127.0.0.1:PORT"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := Run(ctx, policy, allowedAddr, "curl", []string{"-sS", "--max-time", "3", allowedServer.URL}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected the request to the configured proxy address to succeed, got error: %v (stderr: %s)", err, stderr.String())
	}
	if stdout.String() != "allowed-server-response" {
		t.Errorf("unexpected response body: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	err = Run(ctx, policy, allowedAddr, "curl", []string{"-sS", "--max-time", "3", blockedServer.URL}, nil, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected the request to a different local address to be blocked, got success (stdout: %s)", stdout.String())
	}
}

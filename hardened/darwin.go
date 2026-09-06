//go:build darwin

package hardened

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"agentguard/engine"
)

// CompileProfile translates policy's filesystem write rules and network
// rules into a macOS sandbox-exec profile (Apple's undocumented but stable
// Scheme-based sandbox profile language). proxyAddr, if set, is the address
// of a running network egress proxy (see proxy/network) — see the network
// scoping note below.
//
// Scope, deliberately narrow:
//
//   - Only file WRITE access is restricted. Restricting reads too would
//     require allow-listing the large, interpreter/OS-dependent set of
//     paths a program needs merely to start (dynamic libraries, the
//     interpreter's own stdlib, /dev/null, ...) — fragile to get right, and
//     a wrong allow-list here is a correctness/security bug, not a
//     convenience gap. The SDK/MCP-level policy engine already governs
//     which declared tool calls can read what; this layer adds write and
//     network hardening as defense-in-depth beyond that, not a full read
//     sandbox.
//
//   - Only filesystem patterns shaped like a directory prefix ("/dir/**")
//     or an exact literal path (no wildcard at all) are supported, mapping
//     to sandbox-exec's (subpath ...) and (literal ...) primitives
//     respectively. Any other glob shape (a mid-pattern "*", a "?", "**" not
//     as a full trailing segment) returns ErrUnsupportedPattern rather than
//     attempting a regex translation that could be subtly wrong in a
//     security-relevant way.
//
//   - Paths are resolved via filepath.EvalSymlinks before being embedded,
//     because sandbox-exec's (subpath ...) matches the *resolved* path —
//     verified empirically while building this: on macOS /tmp is a symlink
//     to /private/tmp, and a profile written with the literal "/tmp/..."
//     path silently failed to match at all. That would make hardened mode
//     look like it was working (no errors) while actually blocking every
//     write, including into the supposedly-allowed directory — exactly the
//     kind of false confidence a security feature must not produce.
//
//   - Network is coarse: sandbox-exec's network primitive only accepts
//     "localhost" or "*" as a literal host (verified empirically — a raw IP
//     is rejected outright), which maps naturally onto "only allow reaching
//     our own local network-egress-proxy": if proxyAddr is set, only
//     outbound connections to that address are allowed; real per-domain
//     filtering happens in that proxy, not at this layer. If policy.Network
//     is configured (the user has opted into network policy) but proxyAddr
//     is empty, all network is denied outright. If policy.Network is
//     entirely unset, network is left unrestricted at this layer.
func CompileProfile(policy *engine.Policy, proxyAddr string) (string, error) {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n(deny file-write*)\n")
	// /dev/null has no security relevance (writes to it are discarded, not
	// persisted or exfiltrated) but is written to constantly by completely
	// ordinary commands (`-o /dev/null`, `2>/dev/null`, ...) — found via the
	// combined-scenario smoke test in CHANGELOG.md, where blocking it turned
	// a successful, policy-compliant curl into a confusing exit-23 failure
	// unrelated to anything the policy actually cares about.
	b.WriteString(`(allow file-write* (literal "/dev/null"))` + "\n")

	for i, r := range policy.Filesystem {
		if r.Allow != "write" && r.Allow != "read_write" {
			continue // deny rules need nothing extra (file-write* is already denied by default); read-only allows don't affect the write sandbox
		}
		for _, pat := range r.Paths {
			clause, err := compileFSClause(pat)
			if err != nil {
				return "", fmt.Errorf("filesystem[%d]: %w", i, err)
			}
			fmt.Fprintf(&b, "(allow file-write* %s)\n", clause)
		}
	}

	if policy.HasNetworkRules() {
		b.WriteString("(deny network*)\n")
		if proxyAddr != "" {
			_, port, err := net.SplitHostPort(proxyAddr)
			if err != nil {
				return "", fmt.Errorf("proxy address %q: %w", proxyAddr, err)
			}
			fmt.Fprintf(&b, "(allow network-outbound (remote ip \"localhost:%s\"))\n", port)
		}
	}

	return b.String(), nil
}

func compileFSClause(pattern string) (string, error) {
	switch {
	case pattern == "**":
		return `(subpath "/")`, nil
	case strings.HasSuffix(pattern, "/**"):
		dir := strings.TrimSuffix(pattern, "/**")
		if strings.ContainsAny(dir, "*?") {
			return "", fmt.Errorf("%w: %q (wildcards are only supported as a full trailing \"/**\" segment)", ErrUnsupportedPattern, pattern)
		}
		resolved, err := resolvePath(dir)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(subpath %q)", resolved), nil
	case strings.ContainsAny(pattern, "*?"):
		return "", fmt.Errorf("%w: %q (only a full trailing \"/**\" segment or an exact literal path are supported)", ErrUnsupportedPattern, pattern)
	default:
		resolved, err := resolvePath(pattern)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(literal %q)", resolved), nil
	}
}

// resolvePath resolves symlinks in path, walking up to the nearest existing
// ancestor and resolving that if the full path doesn't exist yet — so a
// policy can reference a workspace directory that hasn't been created at
// compile time without CompileProfile failing.
func resolvePath(path string) (string, error) {
	clean := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return resolved, nil
	}
	parent := filepath.Dir(clean)
	if parent == clean {
		return clean, nil // reached the root without finding an existing ancestor; use as-is
	}
	resolvedParent, err := resolvePath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(clean)), nil
}

// Run compiles a profile from policy (and proxyAddr) and executes command
// under sandbox-exec, wiring stdio through unchanged. It blocks until the
// subprocess exits or ctx is canceled.
func Run(ctx context.Context, policy *engine.Policy, proxyAddr string, command string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	profile, err := CompileProfile(policy, proxyAddr)
	if err != nil {
		return fmt.Errorf("compiling sandbox profile: %w", err)
	}

	f, err := os.CreateTemp("", "agentguard-sandbox-*.sb")
	if err != nil {
		return fmt.Errorf("writing sandbox profile: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(profile); err != nil {
		f.Close()
		return fmt.Errorf("writing sandbox profile: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing sandbox profile: %w", err)
	}

	fullArgs := append([]string{"-f", f.Name(), command}, args...)
	cmd := exec.CommandContext(ctx, "sandbox-exec", fullArgs...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

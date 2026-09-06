//go:build !darwin

package hardened

import (
	"context"
	"io"

	"agentguard/engine"
)

// CompileProfile always fails on this platform: hardened mode has no
// implementation here (see the package doc for why Linux support was not
// attempted). Failing loudly is deliberate — silently no-op'ing would let a
// user believe hardened mode is protecting them when it isn't.
func CompileProfile(policy *engine.Policy, proxyAddr string) (string, error) {
	return "", ErrUnsupportedPlatform
}

// Run always fails on this platform; see CompileProfile.
func Run(ctx context.Context, policy *engine.Policy, proxyAddr string, command string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return ErrUnsupportedPlatform
}

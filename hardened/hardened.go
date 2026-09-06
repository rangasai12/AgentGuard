// Package hardened implements AgentGuard's OS-level defense-in-depth mode:
// running an agent's own process (not just its declared tool calls) under a
// kernel/OS sandbox derived from policy.yaml, so a process that bypasses the
// SDK/MCP/proxy layers entirely — writing files directly, opening raw
// sockets — is still constrained.
//
// v0.2 scope, deliberately narrow: this hardens filesystem WRITES and
// NETWORK only, not reads, process execution, or IPC — see darwin.go's
// CompileProfile doc comment for why. Only macOS (via sandbox-exec) is
// implemented; Linux (seccomp/Landlock) could not be built or verified in
// this environment (no Linux/KVM host available) and is deliberately not
// attempted rather than shipped untested — see CHANGELOG.md.
package hardened

import "errors"

// ErrUnsupportedPlatform is returned on any OS without a hardened mode
// implementation.
var ErrUnsupportedPlatform = errors.New("hardened mode is not implemented on this platform")

// ErrUnsupportedPattern is returned when a policy's filesystem rule uses a
// glob shape CompileProfile cannot faithfully translate into an OS sandbox
// primitive. Compilation fails loudly rather than silently emitting a
// profile that is more permissive than the policy intends.
var ErrUnsupportedPattern = errors.New("hardened mode cannot translate this filesystem pattern")

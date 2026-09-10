# Changelog

Running log of significant implementation decisions and milestones, kept alongside git history so the reasoning behind the code is easy to find later. Contributor rules (the anti-duplication guardrail and the entry template every milestone below follows from 2026-09-09 on) live in `docs/conventions.md`. See `/Users/rangasaiyalaka/.claude/plans/this-is-a-new-glimmering-pretzel.md` for the original product plan this build follows.

## 2026-09-04 — Project bootstrap + policy engine (PDP) v0.1

- Initialized the repo (Go module `agentguard`, MIT-style OSS-core layout per the plan) with the directory structure from the plan: `/engine`, `/daemon`, `/proxy/{mcp,network}`, `/cli`, `/sdk-python`, `/policy-spec`, `/examples`, `/docs`.
- **Wrote `policy-spec/schema.yaml`**: the YAML policy DSL (filesystem, network, shell, mcp, secrets, escalation sections) plus two worked examples (`coding-agent.yaml`, `payments-mcp.yaml`).
- **Built `/engine`**, the policy decision point (PDP) — `Evaluate(policy, action) -> Decision`. This is pure, side-effect-free Go with full test coverage (`go test ./engine/...`, all passing).
  - **Deviation from the original plan**: the plan called for compiling the YAML DSL down to embedded OPA/Rego. v0.1 ships a native Go evaluator instead, behind the same `Evaluate` function signature. Rationale: OPA/Rego adds real integration surface (input/data document shape, Rego authoring) without changing what the PEPs (SDK wrapper, MCP proxy, network proxy) see — they only ever call `Evaluate`. Swapping in an OPA-backed implementation later, or adding a Rego escape hatch for power users, doesn't require touching any PEP. Keeping v0.1 native-Go kept the first slice small, fully testable, and dependency-light. Revisit this once there's a concrete user request for arbitrary Rego logic beyond what the YAML DSL expresses.
  - **Rule precedence design decision**: `filesystem` rules are a single ordered list where the first matching rule wins (in declaration order) — this is what makes "allow /workspace/**, then deny ** as a catch-all" work as an ACL-style rule list. `network`/`shell`/`mcp` instead keep separate `allow`/`deny` lists where `deny` is always checked first, so a safety-critical deny (raw IP, `rm -rf`) always wins regardless of rule order. Documented in `policy-spec/schema.yaml`.
  - **Security fix found by the test suite itself**: the first draft of `evaluateFS` matched glob patterns against the raw, unnormalized path, which let `/workspace/../etc/shadow` bypass a workspace-scoped allow rule via path traversal (the traversal string still starts with `/workspace/`, so a naive glob match let it through). Fixed by resolving the path with `path.Clean` before matching. `TestFilesystemDenyWinsOverAllow` covers this. This is a logical-layer mitigation; real symlink-based escapes are out of scope until the v0.2 kernel-hardened mode (Landlock/seccomp), as called out in the plan.
  - Also fixed: the `**` glob fragment didn't match its own parent directory (`/workspace/**` failed to match literal `/workspace`) under the original single-regex implementation. Replaced with a segment-by-segment recursive matcher (`matchSegs` in `engine/match.go`), which handles this correctly and is easier to reason about than one large generated regex.

### Verification run at this milestone
- `go test ./engine/... -v` — all tests pass (filesystem/network/shell/mcp/secrets rule evaluation, glob/domain matching, policy validation).
- `gofmt -l .` — clean.
- `go vet ./...` — clean.

## 2026-09-04 — Local sidecar daemon (`/daemon`)

Built the daemon that hosts the policy engine behind a shared process, per the
PDP/PEP architecture in the plan: every enforcement point (SDK, MCP proxy,
network proxy, CLI) talks to one running daemon instead of embedding its own
policy logic, so policy is defined once and audited in one place.

- **`AuditLogger`** (`daemon/audit.go`): appends JSONL events to disk and keeps
  a bounded in-memory ring (2000 events) for fast `tail`/`query` without
  re-reading the file. `Query` supports filtering by action type, decision, actor.
- **`ApprovalBroker`** (`daemon/approval.go`): tracks actions blocked on human
  approval. `Await` blocks the caller (with a timeout falling back to the
  policy's `on_timeout` setting) while a second caller — the CLI's
  `agentctl approve/deny`, later Slack/webhook — resolves it via `Resolve`.
- **`Daemon`** (`daemon/daemon.go`): wires policy + engine.Evaluate + audit +
  approvals together. `Evaluate` runs the decision, blocks on approval if
  required, and logs exactly one audit event per call with the *final*
  (post-approval) decision — so the audit trail never shows a stale
  pre-approval verdict.
- **Socket API** (`daemon/socket_api.go`): a line-delimited JSON protocol over
  a Unix domain socket (`evaluate`, `ping`, `audit_tail`, `audit_query`,
  `pending_approvals`, `approve`, `deny`). Chosen over a streaming JSON decoder
  so a from-scratch client (the Python SDK) only needs "read one line, parse
  one JSON object" rather than a stateful streaming parser.
- Full test coverage including a real cross-connection integration test
  (`TestSocketAPIApprovalFlowAcrossConnections`): one connection blocks on an
  `evaluate` call requiring approval while a second connection discovers it via
  `pending_approvals` and resolves it via `approve`, proving the blocking
  approval flow actually works over the wire, not just in-process.

**Bug caught during this milestone**: socket tests initially failed with
`connect: invalid argument` on macOS — `t.TempDir()` nests deeply enough
(`/var/folders/.../T/<test-name>.../agentguard.sock`) to exceed the ~104-byte
`sun_path` limit on Unix domain sockets on macOS/BSD. Fixed by generating a
short socket path directly under `/tmp` for tests (`daemon/socket_api_test.go:shortSocketPath`);
production code takes the socket path as a configurable argument, so this is a
test-only concern, but worth remembering when choosing a default socket path
location for `agentctl` itself.

### Verification run at this milestone
- `go test ./... -v` — all tests pass (engine + daemon).
- `gofmt -l .` — clean.
- `go vet ./...` — clean.

## 2026-09-04 — MCP proxy (`/proxy/mcp`), the flagship enforcement point

Built the MCP stdio proxy called out in the plan as the strongest demo moment:
it speaks MCP on both sides, so putting policy enforcement in front of *any*
MCP server (filesystem, GitHub, payments, a homegrown one) requires zero
changes to the agent or the server — only the launch command changes to
`agentctl mcp-proxy --policy policy.yaml -- <real-server-command>`.

- **Protocol handling** (`proxy/mcp/proxy.go`): line-delimited JSON-RPC per
  the MCP stdio transport spec. Only `tools/call` requests are inspected;
  every other method (`initialize`, `tools/list`, `resources/*`, ...) passes
  through unchanged in both directions — v0.1 policy governs tool
  invocations, not protocol negotiation.
- **Deny short-circuits before the server ever sees the call**: a denied
  `tools/call` gets a synthesized JSON-RPC error response written straight
  back to the client; the request is never forwarded. Verified directly in
  `TestProxyBlocksDeniedToolCallWithoutReachingServer` (the fake server
  handler asserts it was never invoked).
- **Approval is pluggable** (`ApproveFunc`): the default (`PromptTTY`) opens
  `/dev/tty` directly, independent of the proxy's stdin/stdout (which are
  dedicated to the MCP JSON-RPC stream with the agent and can't double as an
  approval prompt). If no controlling terminal is available, it returns "" so
  the policy's `escalation.on_timeout` applies — fails closed by default.
  Async approval (Slack/webhook, or delegating to a shared daemon so multiple
  concurrent proxies share one approval queue) is a v0.2 addition once there's
  a concrete need; noted as a deliberate v0.1 gap.
- Reuses `daemon.AuditLogger`/`daemon.AuditEvent` directly rather than
  reinventing audit logging for this PEP — one audit event shape across the
  whole system, whether it came from the daemon or a standalone proxy.
- **Testing approach**: rather than spawning a real subprocess MCP server
  (which would need network/npm access in CI), tests wire the proxy between
  in-memory pipes with a hand-rolled fake "server" goroutine — this exercises
  the exact same line-parsing/forwarding/interception code path a real
  subprocess would, including a real assertion that a denied call's bytes
  never reach the "server" side of the pipe. Testing against an actual
  reference MCP server (filesystem/GitHub) is deferred to manual verification
  once the CLI wiring (`agentctl mcp-proxy`) exists.

### Verification run at this milestone
- `go test ./... -timeout 30s` — all tests pass (engine + daemon + proxy/mcp).
- `gofmt -l .` — clean.
- `go vet ./...` — clean.

## 2026-09-04 — `agentctl` CLI: the v0.1 slice becomes a runnable product

Wired everything built so far behind a single binary (`cli/`, entrypoint at
`cli/cmd/agentctl`): `init`, `policy validate`, `daemon start`, `audit
tail/query`, `approve`/`deny`, and `mcp-proxy`. This is the point where
AgentGuard stopped being a set of libraries and became something a developer
could actually run.

- `agentctl init` scaffolds a starter `policy.yaml`; `agentctl policy
  validate` loads and validates one via `engine.LoadPolicy`.
- `agentctl daemon start` runs the daemon in the foreground over a Unix
  socket (default `~/.agentguard/agentguard.sock`, overridable via
  `AGENTGUARD_SOCKET`), shutting down cleanly on SIGINT/SIGTERM.
- `agentctl audit tail`/`query` and `agentctl approve`/`deny` are thin
  clients (`cli/client.go`) over the same socket protocol the daemon exposes.
- `agentctl mcp-proxy --policy policy.yaml -- <cmd>` wires `proxy/mcp.Proxy`
  to a real subprocess.

### Two real bugs found by testing the actual binary against a real subprocess, not just in-process tests

Both engine and daemon and the MCP proxy's pipe-based unit tests were fully
green before this point, but running the built `agentctl mcp-proxy` binary
against a real Python subprocess (see manual smoke test below) surfaced two
bugs that no amount of in-memory-pipe testing would have caught, because nothing downstream
of those pipes cared about the properties a real subprocess depends on:

1. **Deadlock**: the proxy never closed its write-end of the subprocess's
   stdin pipe when the client's input ended, so a real subprocess blocked
   reading its own stdin (as any well-behaved server does) hung forever
   waiting for EOF that never came. Fixed by closing `serverIn` at the end of
   `pumpClientToServer` (`proxy/mcp/proxy.go`); added
   `TestProxyClosesServerStdinWhenClientInputEnds`, which asserts on the
   close directly via a `io.WriteCloser` wrapper, so this can't silently
   regress again.
2. **Unsynchronized concurrent writes**: both proxy directions (denied calls
   answered directly, allowed calls' responses relayed from the real server)
   write to the same client-facing output stream from separate goroutines.
   For messages larger than a pipe's atomic-write size, two concurrent
   `Write` calls could interleave mid-message and corrupt the
   one-JSON-object-per-line framing MCP's stdio transport requires. Fixed
   with a `syncWriter` mutex wrapper around the client output, and by making
   `writeLine` issue exactly one `Write` call per message (data + newline in
   one buffer) so the mutex only needs to guard a single call, not a
   multi-call critical section. Added
   `TestProxyConcurrentWritesToClientDontInterleave`, which drives 200
   alternating large allow/deny responses concurrently and parses every line
   the client receives, and confirmed the whole suite is clean under
   `go test ./... -race`.

**Lesson for the rest of this build**: pipe/mock-based unit tests are
necessary but not sufficient for anything that talks to a real OS-level
process or shares a writer across goroutines — plan to manually exercise the
actual built binary against a real counterpart (a real subprocess, a real
socket client) at least once per enforcement point, the way this milestone's
smoke test did, rather than trusting green unit tests alone.

### Manual smoke test performed
Built `bin/agentctl` and ran it against a small hand-written fake MCP server
subprocess (`fake_mcp_server.py`, kept out of the repo — it's scratch, not a
project artifact) with `policy-spec/examples/payments-mcp.yaml`: confirmed
`list_transactions` is forwarded and executed by the real subprocess,
`refund_customer` is denied without the subprocess ever seeing the call, and
an unlisted tool is denied by the server's default — and confirmed the
process now exits cleanly (`exit: 0`) instead of hanging.

### Verification run at this milestone
- `go test ./... -race -timeout 60s` — all tests pass (engine, daemon,
  proxy/mcp, cli), clean under the race detector.
- `gofmt -l .` — clean.
- `go vet ./...` — clean.
- Manual smoke test against a real subprocess (above).

## 2026-09-04 — Python SDK (`sdk-python/agentguard`), completing the v0.1 slice

Built the last piece of the v0.1 scope from the plan: a stdlib-only Python
client (`Guard`) that wraps an agent's tools so every call is policy-checked
by the same daemon everything else in the system already talks to.

- **`client.py`**: a connect-per-call `DaemonClient` reimplementing the
  daemon's line-delimited JSON protocol from scratch (not a binding) —
  chosen deliberately in the daemon milestone specifically so this would be
  easy. Zero runtime dependencies (`pyproject.toml` has none), matching the
  "thin SDK, one policy implementation" design principle from the plan.
- **`guard.py`**: `Guard.check_and_execute()` is the primitive every
  higher-level helper is built on; `wrap_tools()` duck-types three shapes —
  a plain function, LangChain's legacy `Tool(name, func)`, and
  `BaseTool`/`StructuredTool`'s `.name`/`._run` — and raises `TypeError`
  loudly for anything else rather than silently skipping enforcement.
  `Guard(policy=...)` auto-starts `agentctl daemon start` via subprocess if
  nothing answers a ping first, matching the plan's stated adoption UX.
- **Design decision — reusing the `mcp` policy section for SDK-wrapped
  tools**: the policy DSL only has one section shaped for "named tool,
  allow/deny/require_approval, with a default" (`mcp.servers[].tools[]`).
  Rather than add a near-duplicate `tools:` section for non-MCP function
  calling, the SDK evaluates its checks as `mcp_tool` actions with
  `server = <namespace>` (default `"local-tools"`) — so the same policy
  concept governs a tool call whether it arrived through the Go MCP proxy or
  the Python SDK wrapper. Documented in `guard.py`'s docstring; revisit if a
  real use case needs SDK-wrapped tools to have genuinely different
  semantics from MCP tools.
- **`adapters/openai.py` and `adapters/anthropic.py`**: no dependency on
  either SDK — duck-type on dict-or-object tool-call shapes so they work
  whichever way a caller happens to have parsed the API response.
  `adapters/langchain.py` is a thin, explicitly-named entry point over the
  same generic `wrap_tools` logic in `guard.py`.
- **Testing without the Go binary**: `tests/conftest.py` implements a
  from-scratch fake daemon (a real Unix socket server in a background
  thread, speaking the identical protocol) so the full SDK test suite
  (25 tests) runs without building or running `agentctl` at all.

### Real cross-language interop test (this is what actually validates the two independent protocol implementations agree)
The Go and Python sides of this protocol were written independently from the
same design, which is exactly the situation where a subtle mismatch (a wrong
JSON field name, a different default) would silently break in production
while every mocked unit test stayed green. Built `agentctl`, started a real
daemon against a real policy file, and ran the real `agentguard` Python
package against it over the actual socket — confirmed `ping`, an allowed
`check_and_execute`, a denied call, and an unlisted-tool default-deny all
behave identically to the fake-daemon-backed unit tests, and that
`agentctl audit tail` shows the resulting audit trail. No mismatches found,
but this is the check that would have caught one.

### Verification run at this milestone
- `go test ./... -race -timeout 60s` — clean (unchanged Go code this milestone).
- `python3 -m pytest -q` in `sdk-python/` — 25 passed.
- Real Go daemon ↔ real Python SDK interop test over an actual Unix socket (above).
- `python3 -m py_compile` on all SDK modules — clean. (`black`/`mypy` are not
  installed in this environment; noting as a gap rather than skipping silently —
  worth adding to CI once this project has one.)

## 2026-09-04 — Shared `approval` package (small refactor)

Before building the network proxy, extracted the MCP proxy's `PromptTTY`
approval mechanism into its own package (`approval/`), since the network
proxy needs the exact same "ask a human on /dev/tty, fail-safe to '' if no
terminal" behavior. `proxy/mcp` now imports `approval.Func`/`approval.PromptTTY`
instead of defining its own copy. One implementation, two consumers, no
duplication — done now specifically because this is the moment a second
consumer appeared, not preemptively.

## 2026-09-04 — Network egress proxy (`proxy/network`), completing v0.1

Built the last item from the v0.1 list: a local HTTP/HTTPS forward proxy for
the case an SDK wrapper or the MCP proxy can't see — an agent's own code
making arbitrary outbound HTTP calls directly.

- **Real TLS interception, not just CONNECT-tunnel domain-sniffing**
  (`proxy/network/ca.go`, `proxy.go`): generates a local CA (ECDSA P-256,
  10-year validity) and mints short-lived per-host leaf certificates on the
  fly, cached in memory. This was a deliberate scope decision over the
  cheaper alternative (reading only the CONNECT target's hostname and
  ignoring HTTP method): the policy DSL already has a per-domain `methods`
  field, and honoring it for HTTPS — the overwhelming majority of real API
  traffic — requires actually decrypting the tunnel. A raw-IP CONNECT target
  is still judged immediately, before completing any handshake, since that
  check needs no decryption.
- **Not automated**: trusting the CA into a client's TLS trust (env vars like
  `SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS`/`--cacert`, not the OS/browser store)
  is left to the user — `agentctl proxy ca` prints exactly how. Installing a
  CA into a system trust store is the kind of invasive, hard-to-reverse
  action this project's own operating principles say to avoid doing
  automatically; it's also unnecessary for the proxy to be useful.
- **One shared `*http.Transport` per proxy** (not one per request) so
  repeated calls to the same upstream host reuse connections — built lazily
  on first use so tests can still set `UpstreamTLSConfig` beforehand.
- **CLI**: `agentctl proxy start` (loads/creates the CA via
  `LoadOrGenerateCA`, starts the forward proxy) and `agentctl proxy ca`
  (prints/exports the CA cert and the exact env vars to trust it).

### Bugs the tests found in the test design itself, not the proxy
Writing the HTTPS-interception tests surfaced two wrong assumptions before
they became false confidence:
1. Tests initially pointed requests at a placeholder policy domain
   (`allowed.example.com`) that doesn't resolve to anything — the deny-path
   tests passed anyway (a denied request never reaches the dial step), which
   masked that the allow-path tests weren't actually exercising a real
   round-trip to an origin at all. Fixed by routing through `localhost:<the
   real test origin's port>`, since domain policy matching strips the port
   (`engine.Action.Domain`) while the actual dial still needs it.
2. Assumed a denied CONNECT would come back as a normal `*http.Response`
   with status 403. Go's `net/http` client actually surfaces a failed
   CONNECT as a dial *error* (the tunnel was never established), not a
   response the caller can inspect — this is standard library behavior, not
   a proxy bug, but it means the raw-IP-CONNECT test's original assertion
   was checking the wrong thing entirely. A domain-level deny discovered
   *inside* an already-established tunnel behaves differently and correctly
   comes back as a normal 403 response, which is what
   `TestHTTPSInterceptionDeniedRequestNeverReachesOrigin` actually tests.

### Manual smoke test against the live internet
Built `agentctl`, ran `agentctl proxy start` with a policy allowing only GET
to `httpbin.org`, and drove real `curl` requests through it with
`--cacert`: GET to the allowed domain → 200 (audit: allow), GET to a
non-allowlisted domain → 403 (audit: deny), POST to the allowed domain (only
GET is permitted) → 403 (audit: deny, proving method-level enforcement over
real HTTPS works, not just domain-level), and a plain (non-TLS) HTTP request
→ 200. All four matched the audit log exactly.

### Verification run at this milestone
- `go test ./... -race -timeout 60s` — all packages pass, race-clean.
- `gofmt -l .` / `go vet ./...` — clean.
- Manual smoke test against the live internet (above).

---

## v0.1 status: complete

Every component in the plan's v0.1 scope now exists and is tested: the
policy engine, the local daemon, the MCP proxy, the network egress proxy,
the CLI, and the Python SDK.

---

## 2026-09-04 — TypeScript SDK (`sdk-ts/agentguard`), first v0.2 item

Started v0.2 with TypeScript SDK parity (LangChain.js, Vercel AI SDK), the
first item on the plan's v0.2 list — chosen over the OS-level hardened mode
because Linux seccomp/Landlock can't even be exercised on this development
machine (macOS/Darwin), while a TS SDK mirroring the working Python one is
fully buildable and testable here, and covers a large share of real agent
frameworks (LangChain.js, Vercel AI SDK, raw OpenAI/Anthropic Node SDKs, any
Node-based MCP host).

- **Runs as native TypeScript, no build step**: Node 22.6+ can execute `.ts`
  files directly via type-stripping, so `sdk-ts/src/*.ts` ships as source,
  and tests run via Node's built-in test runner (`node --test`) against
  `.ts` test files directly — no `tsc`, `ts-node`, or bundler dependency,
  matching the Python SDK's "zero runtime dependencies" principle. Verified
  this capability empirically before committing to the approach (see the
  session's build log), not assumed.
- **`client.ts`/`guard.ts`/`exceptions.ts`/`adapters/*.ts`**: a structural
  mirror of `sdk-python/agentguard` — `DaemonClient` reimplements the same
  line-delimited JSON protocol, `Guard.checkAndExecute` is the core
  primitive, `wrapTools` duck-types plain functions and three LangChain.js
  tool shapes (`.func`, `.call`, `.invoke`).
- **`Guard.create()` static async factory instead of an async constructor**:
  JS/TS constructors can't be `async`, so auto-starting the daemon (which
  needs to `await` a ping loop) can't happen in `new Guard(...)` the way
  Python's synchronous `__init__` does it. This is a genuine language-level
  difference from the Python SDK, not an inconsistency — documented in the
  class's own comments.
- **`adapters/vercel.ts`**: the Vercel AI SDK's `tools` parameter is a
  `Record<name, ToolDefinition>` keyed by name with an `execute` function,
  not an array of named objects like LangChain's — genuinely different
  enough to need its own small adapter rather than forcing it through
  `wrapTools`.

### Three real bugs the tests/manual verification caught before they shipped
1. **Prototype loss on tool wrapping**: the first draft of `wrapAttr` used
   `{...tool, [callAttr]: wrapped}` to clone a tool object before overriding
   its call method. A plain object spread only copies *own* enumerable
   properties — for a real framework tool implemented as a class instance
   (methods live on the prototype, not as own properties), this would
   silently return an object missing every prototype method, breaking
   exactly the class-instance case duck-typing exists to support. Python's
   `copy.copy` doesn't have this problem (method resolution always goes
   through the class), so this is a real JS/TS-specific pitfall the language
   mirror didn't automatically avoid. Fixed with
   `Object.assign(Object.create(Object.getPrototypeOf(tool)), tool)` to
   preserve the prototype chain; `guard.test.ts` asserts
   `wrapped instanceof FakeLangChainTool` specifically to catch a
   regression here.
2. **Dead error-handling branch in `ensureDaemon`**: modeled on Python's
   `subprocess.Popen`, which raises synchronously if the binary doesn't
   exist — but Node's `child_process.spawn()` returns immediately and only
   reports a missing binary via an async `"error"` event. The original
   `try/catch` around `spawn()` could never fire for the common
   binary-not-found case, silently falling through to the ping-deadline
   loop and only failing after the *full* timeout with a generic "didn't
   come up" message. Verified the actual Node behavior directly (a one-off
   script) rather than assuming parity with Python, then fixed by racing
   the spawn's error event against the ping loop with `Promise.race`, so a
   missing binary now fails in milliseconds with a specific message. The
   "agentctl missing" test's duration dropped from waiting out its timeout
   to ~10ms once fixed — a visible symptom of the original bug, not just a
   theoretical one.
3. **Constructor parameter properties don't work under Node's strip-only TS
   mode**: `constructor(private readonly x: T)` is valid TypeScript but
   requires real code generation (assigning the parameter to `this.x`), not
   pure type erasure — Node's type-stripping rejects it outright at import
   time. This broke every class in the SDK (`DaemonClient`, `PolicyDenied`,
   `Guard`, the test fixtures) the first time the suite actually ran.
   Rewrote every constructor to declare fields explicitly and assign them in
   the constructor body.

### Real cross-language interop test
Same check as the Python SDK milestone, for the same reason: built
`agentctl`, started a real daemon against a real policy, and ran the actual
TypeScript package against it over a real Unix socket. `add` (allowed),
`dangerous` (explicit deny), and `never_listed` (server-default deny) all
behaved identically to the fake-daemon-backed unit tests, and
`agentctl audit tail` showed the correct trail.

### Verification run at this milestone
- `node --test test/*.test.ts` in `sdk-ts/` — 27 passed.
- Real Go daemon ↔ real TypeScript SDK interop test over an actual Unix
  socket (above).
- No lint/format tooling (prettier/eslint) available in this environment —
  noted as a gap, same as Python's black/mypy, rather than skipped silently.

---

## 2026-09-04 — `agentctl policy test`: policy regression testing for CI

Built the second v0.2 item from the plan: a dry-run harness so a team can
write regression tests for their `policy.yaml` and run them in CI, the same
way they test any other code, instead of discovering a policy mistake in
production the first time a real agent hits it.

- **`engine/testsuite.go`**: a trace file (`version: 1`, a list of `{name,
  action, want}` cases) parses to a `TestSuite`; `RunTestSuite(policy,
  suite)` evaluates every case's `action` against the policy and compares
  the result to `want`. Lives in `engine/` rather than `cli/` since it's
  fundamentally a testing feature of the policy engine itself (same reason
  `LoadPolicy`/`ParsePolicy` live there), with the CLI only wiring up
  `agentctl policy test <policy.yaml> <traces.yaml>` and formatting output.
- **Added `yaml` tags to `engine.Action`** (previously JSON-only, used by the
  daemon socket protocol): trace files use exactly the same field names
  (`is_ip_literal`, `env_var`, etc.) a developer already sees in audit logs
  and SDK code, rather than a second naming dialect for the same concept.
- **`policy-spec/examples/coding-agent.traces.yaml`**: a worked example
  covering all five action types against `coding-agent.yaml`, doubling as
  the manual smoke test for this feature (`agentctl policy test
  coding-agent.yaml coding-agent.traces.yaml` → 9 passed, 0 failed).
- Validates the same things `ParsePolicy` does for policies: version,
  required fields, duplicate case names, and that `want` is one of
  allow/deny/require_approval — failing fast on a malformed trace file
  rather than a confusing panic or silent no-op mid-run.

### Verification run at this milestone
- `go test ./... -race -timeout 60s` — all packages pass, race-clean.
- `gofmt -l .` / `go vet ./...` — clean.
- Manual run of `agentctl policy test` against a real policy + trace file
  (above) — all 9 cases pass.

---

## 2026-09-04 — Slack/webhook async approvals

Third v0.2 item: the daemon can now notify a webhook URL (Slack Incoming
Webhooks work as-is) the instant an action starts requiring approval,
instead of a human having to know to poll `agentctl audit tail`/
`pending_approvals`. Fully built and tested without any real Slack
account — the actual HTTP POST mechanism is what needed proving, and that's
provider-agnostic.

- **A real, if narrow, gap this closed**: before this, the *daemon* path had
  no active notification at all — only the standalone MCP/network proxies'
  TTY prompt did. A human using the daemon (the shared, multi-client path)
  had no way to find out an approval was pending except by polling.
- **`ApprovalBroker.Await` gained a `Notifier` parameter**
  (`daemon/approval.go`), called once with the pending approval right after
  it's registered (so the ID it reports is already resolvable — a human
  clicking "approve" the instant they see a notification can't hit a
  not-yet-registered ID). The broker always invokes it in its own goroutine,
  so any notifier implementation is automatically non-blocking by
  construction — a slow or broken notifier can never delay or corrupt the
  approval flow itself. Verified directly: `TestApprovalBrokerSlowNotifyDoesNotDelayResolution`
  gives `notify` a 500ms sleep and asserts `Resolve` still takes effect in
  under 200ms.
- **`daemon.WebhookNotifier`** (`daemon/webhook.go`): POSTs a JSON payload
  with a Slack-compatible top-level `text` field plus structured fields for
  any other consumer. POST failures (unreachable host, non-2xx status) are
  reported via an optional `errLog` callback but never block, panic, or
  otherwise affect the approval outcome.
- **Policy-driven config**: `escalation.webhook_url` in `policy.yaml`
  (validated to start with `http://`/`https://`), wired up by `agentctl
  daemon start`. Deliberately scoped to the daemon only — the standalone
  `mcp-proxy`/`proxy start` commands have no daemon-backed, remotely
  resolvable approval ID to notify about (they resolve via a direct TTY
  read), so they remain TTY-only in v0.2; documented in
  `policy-spec/schema.yaml` rather than silently unsupported.
- **This is a notification channel, not remote-approval-by-click**: the
  message tells a human to run `agentctl approve`/`deny <id>`, which still
  requires reaching the daemon's (local-only) socket. Real one-click
  resolution (e.g. Slack interactive message buttons) would need the socket
  exposed over a network and a public callback endpoint — a bigger change
  out of scope here, called out explicitly rather than implied.

### Real end-to-end smoke test
Built `agentctl`, started a real daemon with `escalation.webhook_url`
pointed at a small local Python HTTP server standing in for Slack, and
drove a real `evaluate` call for a `rm -rf` command over the daemon's actual
socket: the webhook fired immediately with the correct pending ID, ran
`agentctl approve <id>` from that notification's own text, and confirmed via
`agentctl audit tail` that the final decision recorded was `allow` — the
complete asynchronous approval loop, live, not simulated.

### Verification run at this milestone
- `go test ./... -race -timeout 60s` — all packages pass, race-clean.
- `gofmt -l .` / `go vet ./...` — clean.
- Real end-to-end smoke test against a local webhook receiver (above).

---

## 2026-09-04 — OS-level hardened mode (`agentctl run`), macOS only

Final v0.2 item, scoped honestly around a hard platform constraint: macOS's
`sandbox-exec` is fully built, tested, and verified for real on this
machine; Linux (seccomp/Landlock) is explicitly **not attempted**, because
this development environment has no Linux/KVM host to build or verify it
against, and shipping untested kernel-level security code would be worse
than not shipping it — false confidence is an actively bad outcome for a
security feature. This was discussed with the user in the context of the
sandbox-provider-adapter/Firecracker question and is the same underlying
constraint applied to a different feature.

- **`hardened/` package**: `CompileProfile(policy, proxyAddr)` translates a
  policy's filesystem write rules and network rules into a macOS
  `sandbox-exec` profile (Apple's undocumented but stable Scheme-based
  sandbox language); `Run(...)` writes it to a temp file and execs the
  target command under `sandbox-exec -f`.
- **Deliberately narrow scope, stated up front rather than discovered
  later**: only filesystem **writes** and **network** are hardened — not
  reads, process exec, or IPC. Restricting reads too would require
  allow-listing the large, interpreter-dependent set of paths any program
  needs merely to start (dynamic libraries, stdlib, `/dev/null`, ...);
  getting that allow-list wrong is a correctness/security bug, not a
  convenience gap, so it's out of scope rather than attempted and
  potentially wrong. The SDK/MCP-level policy engine already governs
  declared tool calls; this is defense-in-depth for code that bypasses that
  layer entirely, not a full process sandbox.
- **Filesystem pattern support is intentionally limited**: only a directory
  prefix (`/dir/**`, → `subpath`) or an exact literal path (no wildcard at
  all, → `literal`) translate; anything else (a mid-pattern `*`, a `?`)
  returns `ErrUnsupportedPattern` rather than attempting a regex translation
  that could be subtly wrong in a security-relevant way.
- **Network is coarse and proxy-shaped by design, not by limitation**:
  `sandbox-exec`'s network primitive only accepts `localhost`/`*` as a
  literal host (verified empirically — a raw IP address is rejected
  outright by the profile parser), which maps naturally onto "only allow
  reaching our own local network-egress-proxy." `agentctl run --proxy-addr
  127.0.0.1:8080` allows outbound connections only to that address; real
  per-domain filtering still happens in the proxy, not at this layer. If the
  policy configures network rules but no `--proxy-addr` is given, all
  network is denied outright (with a warning), rather than silently
  ignoring the policy's intent.

### Two real bugs `sandbox-exec`'s undocumented, easy-to-misuse profile language produced — both caught by testing against the real thing, not by reading docs (there mostly aren't any)
1. **Symlink resolution**: a profile written with a policy's literal path
   (e.g. `/tmp/workspace`) silently failed to match *anything*, including
   writes into the supposedly-allowed directory — because `/tmp` is a
   symlink to `/private/tmp` on macOS, and `subpath` matches the *resolved*
   path. This would have made hardened mode appear to work (no errors, just
   universal denial) while giving zero of the intended access — exactly the
   false-confidence failure mode this feature exists to avoid causing
   elsewhere. Found empirically (a throwaway `sandbox-exec` invocation
   before writing any Go code) and fixed with `resolvePath`, which resolves
   as much of a path as exists so a not-yet-created workspace directory
   still compiles correctly.
2. **`/dev/null` writes blocked**: the base profile's `(deny file-write*)`
   also blocked the extremely common `-o /dev/null`/`2>/dev/null` pattern,
   found via the combined filesystem+network smoke test below (`curl`
   returned a confusing exit-23 "failure writing output" unrelated to
   anything the policy actually restricted). `/dev/null` has no security
   relevance — writes to it are discarded, not persisted or exfiltrated —
   so it's now unconditionally allowed in the base profile, with a
   regression test.

### Real combined smoke test: hardened mode + the network proxy together
This is the actual design intent, verified live: started `agentctl proxy
start` for real, then ran `agentctl run --policy ... --proxy-addr
127.0.0.1:18081 -- sh script.sh` where the script (1) wrote inside the
allowed workspace — succeeded; (2) wrote outside it — blocked; (3) curled
`httpbin.org` *through* the configured proxy with the proxy's CA trusted —
succeeded (200); (4) curled `httpbin.org` **directly, bypassing the
proxy** — failed with "Could not resolve host" (DNS itself is blocked, not
just the TCP connect). Step 4 is the whole point: even a rogue or buggy
agent process that ignores `HTTP_PROXY`/`HTTPS_PROXY` entirely cannot reach
the network except through the one address hardened mode allows.

### Verification run at this milestone
- `go test ./... -race -timeout 60s` — all packages pass, race-clean,
  including 8 tests in `hardened/` that invoke real `sandbox-exec` processes
  (not mocked).
- `GOOS=linux GOARCH=amd64 go build ./... && go vet ./...` — the
  non-Darwin stub (`ErrUnsupportedPlatform`) compiles and vets cleanly,
  which is the only verification possible for it in this environment; it is
  not runtime-tested, and is not claimed to be.
- Real combined smoke test against a real `agentctl proxy start` instance
  and the live internet (above).

---

## v0.2 status

Every v0.2 item that was feasible to build and verify in this environment
is done: TypeScript SDK parity, `agentctl policy test`, Slack/webhook async
approvals, and macOS hardened mode. Two items remain explicitly deferred,
both for the same reason (no Linux/KVM host in this environment), discussed
with and decided by the user rather than assumed:
- **Linux seccomp/Landlock** hardened mode — the other half of this
  milestone's scope.
- **Sandbox-provider adapters / owned Firecracker compute** — skipped
  entirely for now rather than building against a third-party API (E2B/Box)
  as a stopgap; revisit when either a Linux/KVM host or provider credentials
  are available.

---

## Demo agents: `examples/openai-coding-agent/` and `examples/mcp-proxy-demo/`

Everything built through v0.2 had no runnable example demonstrating it
end-to-end — `examples/langchain-agent/` and `examples/mcp-filesystem/` were
README-only stubs. Built two real, working demos, plus closed two small
real gaps that surfaced while making sure the demos would be accurate
rather than approximate.

### Two gaps closed (not workarounds — real, tested additions)

1. **`Guard` had no public way to do a resource-aware policy check.**
   `Guard.check()`/`wrap_tools()`/`check_and_execute()` only ever construct
   `mcp_tool` actions (checked by tool *name*), even though
   `daemon/socket_api.go` and `engine.Action` fully support `fs_read`,
   `fs_write`, `network`, `shell`, and `secret_env` actions with real
   resource fields (path/domain/command/env_var). The only way to issue one
   of these from Python was reaching into the private `Guard._client`.
   Added `Guard.evaluate_action(action: dict) -> dict`
   (`sdk-python/agentguard/guard.py`), a thin public wrapper around the same
   `evaluate` RPC, mirroring `check()`'s error handling. Four new tests in
   `sdk-python/tests/test_guard.py` cover all four action types against a
   fake daemon.
2. **No CLI command listed pending approvals.** The daemon already exposed
   a `pending_approvals` socket command and `agentctl approve/deny <id>`
   existed, but nothing surfaced the `id` a human needs to call them with,
   short of the Slack/webhook path. Added `agentctl pending [--socket path]`
   (`cli/pending_cmd.go`), following `cli/approve_cmd.go`'s exact
   `Dial`/`Call` pattern. Two new tests in `cli/audit_approve_test.go`,
   including one that parses an id out of real `pending` output and feeds
   it to `approve` against a live daemon.

### `examples/openai-coding-agent/` — the flagship live demo

A small coding agent (read/write files, run shell, HTTPS calls, read env
"secrets") driven by a real OpenAI tool-use loop (`agent.py`), scoped to a
dev workspace and explicitly denied production access — directly
demonstrating the dev-vs-prod separation and "a disguised shell command
doesn't matter, the effect is what's checked" points from product
discussion. Every tool in `tools.py` goes through a `checked()` helper that
calls the new `Guard.evaluate_action()` with a fully-typed action before
doing the real operation — the same primitive the MCP proxy and network
proxy already use internally, now exercised from a plain SDK integration
too, not just from those two PEPs. `policy.yaml` also declares a permissive
`mcp.servers[].default: allow` for these five tool names specifically so
`agentguard.adapters.openai.dispatch()` (the outer per-tool-name gate) can
be shown working layered on top of the resource-aware checks, rather than
skipping that adapter to avoid a conflict.

`tests/test_tools_policy.py` builds the real `agentctl` binary and runs a
real daemon against the real `policy.yaml` (see `tests/conftest.py`) — 11
tests covering every allow/deny/require_approval path, including a real
network call to `api.github.com` (allowed) and a real blocked attempt at
`deploy.prod.internal` and a raw IP, run and passing in 23s (the `rm -rf`
require-approval test genuinely waits out the policy's 20s timeout rather
than mocking it). The live OpenAI loop itself is intentionally not part of
this suite — it's non-deterministic by nature (a real model decides what to
call) and is a manual showcase, verified separately by actually running it.

### `examples/mcp-proxy-demo/` — the MCP proxy, zero code changes

`mcp_server.py` is a plain, dependency-free stdio JSON-RPC 2.0 MCP server
with no AgentGuard awareness at all (`list_files`/`read_file`/`delete_file`
against a small sandbox directory). `client_demo.py` is a plain client
driving it. Run directly, they work like any MCP server/client pair. Point
`client_demo.py` at `agentctl mcp-proxy --policy policy.yaml --server
demo-files -- python3 mcp_server.py` instead — the only change, nothing
about either script's code — and `delete_file` (denied in `policy.yaml`)
comes back as a synthesized JSON-RPC `-32000` error before ever reaching the
real server process, while `list_files`/`read_file` pass through untouched.
Verified with a real run of `client_demo.py` against the real `agentctl`
binary and a real subprocess (not a mock), doubling as an integration test.

### Verification run at this milestone
- `go build ./... && go vet ./... && go test ./... -race` — all packages
  pass, race-clean, including the two new `pending` tests.
- `python3 -m pytest` in `sdk-python/` — 29 tests pass, including the four
  new `evaluate_action` tests.
- `python3 -m pytest tests/` in `examples/openai-coding-agent/` — 11 tests
  pass against a real built `agentctl` + real daemon (23s, dominated by the
  genuine 20s approval timeout).
- `python3 client_demo.py /tmp/agentctl` in `examples/mcp-proxy-demo/` — real
  run, `delete_file` denied as expected, others pass through.
- Live run of `agent.py` against the real OpenAI API (`gpt-4o-mini`): the
  model attempted all 6 steps of `USER_TASK`, and the audit log confirms
  exactly the expected allow/deny split (`agentctl audit tail`).

### Follow-up: `@guard.checked()` decorator, closing a real gap the demo itself exposed

Building the demo above and documenting it in `docs/sdk-guide.md` surfaced
an inconsistency the user caught directly: `tools.py` had every function
take an explicit `guard` parameter and call a hand-rolled `checked()`
helper around `evaluate_action()` — real, working code, but exactly the
kind of per-call-site boilerplate the "under 10 minutes, minimal code
changes" adoption pitch is supposed to avoid. `@guard.tool()` was already a
one-line decorator, but only for name-based checks; there was no equivalent
for the resource-aware checks that do the actual enforcement.

Added `Guard.checked(action_type, **field_map)` to
`sdk-python/agentguard/guard.py`: a decorator that uses
`inspect.signature(fn).bind()` on the wrapped function's real call
arguments to build the typed `Action` itself, so the function's signature
never has to include `guard` and its body never has to call
`evaluate_action` manually. `field_map` values are either a parameter name
to copy, or `callable(call_args) -> value` for a computed field (e.g.
`is_ip_literal` derived from `domain`). Four new tests in
`sdk-python/tests/test_guard.py` cover allow, deny-before-call, default-value
handling, and computed fields.

Rewrote `examples/openai-coding-agent/tools.py` to use it: every tool is now
a plain function with one decorator line, `guard` is constructed once at
module level (`guard = Guard(policy=POLICY_PATH)` — the same shape as
`app = Flask(__name__)` then `@app.route(...)`), and `agent.py` no longer
threads a `guard` object through `make_handlers()` at all — it only still
needs `tools.guard` once, for the outer per-tool-name check via
`openai_adapter.dispatch()`.

This traded away one thing worth naming honestly: constructing `Guard` at
*module import time* means a test importing `tools` needs a real daemon
already listening first, or `Guard`'s auto-start reaches for the real
default socket path instead of an isolated test one. Rewrote
`examples/openai-coding-agent/tests/conftest.py` to start the daemon and set
`AGENTGUARD_SOCKET` at collection time, *before* `import tools` — documented
inline and in `docs/sdk-guide.md`'s "Current limitations" section, rather
than left as a surprise. All 11 tests in that suite still pass unchanged in
behavior (only the fixture plumbing changed — no `guard` parameter appears
in any test anymore either), and the live OpenAI run was re-verified against
the refactored code with identical allow/deny behavior to before.

Also updated `docs/sdk-guide.md` to make `@guard.checked()` the documented,
recommended pattern for resource-aware enforcement, with `evaluate_action()`
demoted to "the lower-level primitive, for when the action can't be
expressed as a static field mapping."

---

## New policy section: `functions` — argument-aware conditions, requested directly by the user

The user asked for a real architecture change: instead of only fixed,
purpose-built policy sections (`filesystem`'s paths, `network`'s domains,
`shell`'s command patterns), give policy authors a generic
`function-name: args: condition` mechanism with comparison operators
(`<`, `>`, `=`, ...) — while keeping the code change required to adopt it
minimal, continuing the theme from the `@guard.checked()` decorator work
above. This also directly closes the "generic MCP tool can't be told a read
from a write" gap called out as a limitation in `docs/sdk-guide.md`.

**Engine (`engine/`)**: added `ActionFunction` (`"function"`) as a sixth
action type, purely additive — `Action` gained `Name` and `Args
map[string]any` fields (`engine/types.go`); `Policy` gained a `Functions`
section (`engine/policy.go`): `functions.default` (allow/deny, defaults
deny) plus `functions.rules[]`, each with a `name`, optional `conditions[]`
(`{arg, op, value}`), and `allow`/`deny`/`require_approval`. Unlike
`network`/`shell`/`mcp` (separate allow/deny lists, deny always checked
first), `functions.rules` is a **single ordered list, first-match-wins** —
the same choice as `filesystem`, because argument conditions are naturally
written as partitioning ranges (`amount < 1000` then `amount >= 1000`) where
declaration order is exactly how you express which one takes priority if
ranges ever overlap. A condition on an argument the call didn't pass is
simply false (falls through), never an error.

New file `engine/conditions.go` implements `conditionHolds`: ordering
operators (`<`, `<=`, `>`, `>=`) require both sides to be numeric;
equality operators (`=`, `==`, `!=`) compare numbers numerically regardless
of Go type and compare everything else by `%v`. This numeric-normalization
step is load-bearing, not incidental: a condition's `value` comes from YAML
(which preserves whole numbers as `int`) while an action's `args` arrive
over the wire as JSON (which represents every number as `float64`) — without
normalizing both to `float64` first, `amount: 1000` (int) would never equal
an incoming `1000.0` (float64) despite being the same number. Caught and
fixed by writing a test for exactly this cross-encoding case
(`TestFunctions/non-numeric-typed_amount_from_JSON_(float64)...`) before it
could surface as a confusing false-negative in real use.

18 new Go tests: 9 table-driven decision cases in `engine/decision_test.go`
(small/large/boundary amounts, cross-type numeric equality, non-matching
currency, a no-conditions name-only rule, a missing-argument case, an
unknown-function case) plus 4 new `Validate()` rejection tests in
`engine/policy_test.go` (no name, no allow/deny/require_approval flag, bad
operator, condition with no arg) and an `Action.Resource()` case. All pass,
including under `-race`.

**Python SDK**: added `Guard.function(name: Optional[str] = None)` — the
zero-config decorator this was really about. Where `@guard.checked` still
needs a `field_map`, `@guard.function()` needs none: it binds the wrapped
function's real call arguments via `inspect.signature(...).bind()` and
passes *all* of them straight through as the action's `args`, so adopting
argument-aware policy for a new tool is exactly one decorator line with
nothing else to write:

```python
@guard.function()
def charge_customer(amount: int, currency: str = "USD") -> str:
    return billing.charge(amount, currency)
```

3 new tests in `sdk-python/tests/test_guard.py` (zero-config pass-through,
explicit name override, deny-before-call). Full suite: 36 tests pass.

**Verified for real, not just unit-tested**: `policy-spec/examples/billing-functions.yaml`
+ `billing-functions.traces.yaml` (6 cases) pass against the actual built
`agentctl policy test` binary. Separately ran `Guard.function()` against a
real daemon + real engine from a throwaway script: a $500 charge allowed, a
non-USD transfer denied, and a $5000 charge correctly triggered
`require_approval` — which then surfaced a real instance of the exact
client/daemon timeout mismatch already documented in `docs/sdk-guide.md`
("Approvals and timeouts"): the example policy didn't set
`escalation.approval_timeout_seconds`, so the daemon's default 300s
approval wait outlived the Python `DaemonClient`'s default 30s socket
timeout, and the call surfaced `DaemonStartError` instead of resolving.
Not a bug in this feature — confirmation that the previously-documented
gotcha is real and easy to hit — but a reminder to always set a policy's
`approval_timeout_seconds` deliberately (or a longer client timeout) rather
than relying on the 300s default.

`docs/sdk-guide.md` updated: a new `@guard.function()` section, a `function`
row in the Action field reference table, and the "generic MCP tool" known
limitation narrowed to specifically MCP-server-side tools (SDK-side generic
tools are now fully solved by this feature).

### Demo updated to actually showcase `functions`

Extended `examples/openai-coding-agent/` rather than leaving the new
capability undemonstrated: added a sixth tool, `scale_service(service,
replicas)`, decorated with `@guard.function()` (zero field mapping, unlike
every other tool in `tools.py`) and gated in `policy.yaml` by a `functions`
section (`replicas <= 5` allowed, `> 5` require_approval). `agent.py`'s
scripted `USER_TASK` gained a step asking the model to scale to 20 replicas;
`tests/test_tools_policy.py` gained two cases (small scale-up allowed, large
one denied on the real approval timeout). Verified with a live run against
the real OpenAI API: the model attempted the scale-up, got blocked with the
exact configured reason, and `agentctl audit tail` shows the two-tier
decision (`mcp_tool allow` name gate, then `function deny ... require_approval`
underneath) — the same layered pattern as every other tool in this demo, now
proven for the new policy dimension too. Full suite: 13 tests pass.

---

## Dead-code audit

The user asked to remove any irrelevant/dead code before continuing. Checked
systematically rather than by guessing: cross-referenced every exported Go
function's usage count (none found unreferenced), ran `pyflakes` across the
Python SDK and example scripts (clean, no unused imports/names), and
cross-referenced every exported TypeScript symbol's usage (clean). Two real
findings:

1. **`agentguard.DaemonError`** (`sdk-python/agentguard/client.py`) — defined,
   documented, and exported in `__all__`, but never actually raised anywhere.
   The two call sites that should raise it on a daemon `{"ok": false, ...}`
   response (`guard.py`'s `check()` and `evaluate_action()`) raise a bare
   `RuntimeError` instead — and the TypeScript SDK has no equivalent class at
   all. Removed it from `client.py` and `__init__.py`'s exports; reworded
   `DaemonUnavailable`'s docstring, which used to define itself relative to
   the now-removed class.
2. **`examples/langchain-agent/`** — a stub predating the real, working
   examples: its README showed only `wrap_tools()` against `pretend results`/
   `pretend write to` placeholder functions, not even reflecting the
   `@guard.checked()`/`@guard.function()` decorators added earlier this
   session. Superseded in substance by `examples/openai-coding-agent/` (a
   real agent, real tools, real tests) and in spirit by `docs/sdk-guide.md`.
   Removed the directory rather than leave stale, misleading example code
   sitting next to the real thing.

`examples/mcp-filesystem/` was considered and kept: despite surface overlap
with `examples/mcp-proxy-demo/`, it documents a genuinely different scenario
neither `mcp-proxy-demo` nor anything else covers — pointing an existing
third-party MCP client config (Claude Desktop, etc.) at the proxy in front
of a third-party server, a config-only change with no code to run at all.

Verified nothing broke: full Go suite (`-race`) and full Python suite (36
tests) both pass unchanged after both removals.

---

## Cloud dashboard (Phase 1) — multi-tenant visibility for a fleet of agents

Everything up to this point is local and CLI-only: `daemon/audit.go` writes
one JSONL line per decision plus a 2000-event in-memory ring, and
`agentctl audit tail/query` are the only way to see it, on the same machine
the daemon runs on. The user asked for a real dashboard — visibility across
every agent a company runs, across machines — explicitly planned for
multiple companies (multi-tenant SaaS) with remote approve/deny from the
browser from day one. Full architecture is in
`~/.claude/plans/this-is-a-new-glimmering-pretzel.md`; summary of what
Phase 1 actually built and why:

**New Go dependencies** (`go.mod`): `github.com/jackc/pgx/v5` (Postgres
driver) and `golang.org/x/crypto/bcrypt` (password hashing) — the first
external runtime dependencies this repo has needed beyond `yaml.v3`, and a
deliberate exception to the SDKs' zero-dependency principle: this is a new
hosted backend service, not a library embedded in a customer's agent
process, so the tradeoff is different. Pinned `x/crypto@v0.31.0` rather
than latest specifically to avoid a `go 1.26` bump the newest version would
have forced — the module now needs 1.26 anyway because of transitive
requirements from `pgx`, so this ended up moot, but the same reasoning
should apply to future dependency choices: don't drag the whole module's
minimum Go version up just to pick up one small package.

**`dashboard/schema.sql`** (embedded into `dashboard/store` via `go:embed`,
applied idempotently on every process start rather than needing a separate
migration step — every statement is `CREATE ... IF NOT EXISTS`) — seven
tables: `tenants`, `users`, `memberships` (user↔tenant↔role), `sessions`,
`agents` (one row per registered `agentguard-forwarder` instance),
`audit_events`, `pending_approvals`. IDs are app-generated random hex
strings (`store/ids.go`), not Postgres `gen_random_uuid()` — keeps the
schema extension-free and portable to any Postgres 13+.

**`dashboard/store`** — the only package that touches Postgres; both API
layers go through it so tenant-scoping logic lives in one place. Every
method takes `tenantID` as an explicit parameter the *caller* must have
already derived from an authenticated identity (session for a user, API
key for an agent) — never from a request body field. High-entropy secrets
(session tokens, agent API keys, registration tokens) are hashed with
plain SHA-256 for storage, not bcrypt — bcrypt's slow salted hashing
defends against brute-forcing a low-entropy human-chosen secret, which a
256-bit random token already isn't vulnerable to; bcrypt is reserved for
the one genuinely low-entropy secret in this system, user passwords.
`TestTenantIsolation` in `store_test.go` is the load-bearing test in this
package: two tenants' events, agents, and pending approvals are proven
mutually invisible, including a negative case (tenant A's session
resolving tenant B's pending approval id must fail).

**Pending-approval relay design** — the trickiest piece, because approving
something in a browser has to actually reach a daemon running on a
customer's machine that the cloud backend can't dial into (no inbound
network path). Resolved with a request/ack split baked into the schema:
a browser click sets `pending_approvals.requested_resolution` (status
stays `'pending'`); the owning agent's `agentguard-forwarder` polls
`GET /v1/pending/resolutions`, relays each one to its local daemon via the
**existing, unmodified** `approve`/`deny` socket commands, and only then
calls `POST /v1/pending/ack` to flip status to `approved`/`denied`. This
makes "the browser click was recorded" distinguishable from "the local
daemon actually enforced it" — collapsing that distinction would mean the
dashboard could show a decision as resolved when nothing on the customer's
machine had actually changed. `SyncPending` also reconciles the reverse
case: if a human resolves something locally via `agentctl approve/deny`
(or it times out) between two of the forwarder's polls, the next sync's
snapshot won't include it, and the row is marked `resolved_elsewhere`
rather than sitting `pending` forever.

**`dashboard/server`** — combines the agent-facing Control API (`/v1/*`,
Bearer API-key auth) and the browser-facing Web API (`/api/*`, session-
cookie auth) into one `http.Handler` from one binary
(`cmd/agentguard-cloud`) for Phase 1. Documented in `server.New`'s doc
comment as a deliberate simplification, not a shortcut: the two route
groups have distinct auth and could split into separate deployables later
without changing either package's code. Web API endpoints take a
`tenant_id` query parameter naming *which* of the caller's tenants they
want (same pattern as switching GitHub organizations) — `withTenantAuth`
always re-checks `store.MembershipRole` against it before touching any
data, so a client can *ask* for any tenant_id but only ever see one it's
actually a member of; that check, not the absence of the parameter, is
what enforces isolation. `GET /api/events` is a real superset of the
existing `agentctl audit query`: adds time-range (`since`/`until`,
RFC3339) and resource-substring (`resource_contains`, `ILIKE`) filtering
that the daemon's in-memory-ring-backed `AuditFilter` has never had.
`TestWebAPIRejectsAccessToForeignTenant` and
`TestPendingApprovalResolveEndToEnd` in `server_test.go` exercise this
over real HTTP (`httptest`) against the real Postgres test database, not
a mock.

**`cmd/agentguard-forwarder`** — the one new component that runs on a
customer's own machine, and the only thing that talks to both the local
daemon and the cloud backend. Tails the local JSONL audit log with a
checkpointed byte offset persisted to a small state file (`state.go`) —
the same technique Filebeat/Promtail use — so a restart never re-sends or
drops events, and so `daemon/audit.go` needed zero changes (no new
"subscribe to new events" socket command; polling `pending_approvals` and
tailing the existing file was enough for everything Phase 1 needs).
Registers once via a one-time `-register-token` flag (from the dashboard's
"Add Agent" flow), then persists its API key locally. Every tick
(default 2s) does three independent, error-isolated steps — relay
resolutions, sync pending, ship new events — so a Control API blip on one
step never blocks the others, and total unreachability of the cloud
backend never affects local enforcement: the daemon keeps evaluating and
logging exactly as before, and `agentctl approve/deny` on the machine
itself always still works as a fallback. Verified against a real local
daemon over a real Unix socket, a real audit log file, and a real
(httptest-backed, real-Postgres) Control API in
`forwarder_test.go` — including a full round trip in
`TestForwarderRelaysBrowserApprovalToLocalDaemon`: a real blocked
`daemon.Evaluate()` call, resolved by simulating a browser click through
the store directly, relayed by the forwarder, and confirmed to actually
unblock the waiting `Evaluate()` call with the browser's decision.

**Manual end-to-end smoke test** (beyond the automated suite): built and
ran all three binaries for real — `agentguard-cloud` against the real dev
Postgres database, a real `agentctl daemon start` using
`policy-spec/examples/coding-agent.yaml`, and `agentguard-forwarder`
bridging them. Signed up a company via `curl`, registered an agent, drove
two allowed writes and one `rm -rf` (which correctly went to
`require_approval` and blocked) directly against the daemon's socket,
confirmed both landed in Postgres and were visible via `GET /api/events`
and `GET /api/pending`, resolved the pending approval via
`POST /api/pending/resolve` (simulating a dashboard click), and confirmed
`agentctl pending` against the *real local daemon* went from showing the
entry to showing none after the next forwarder tick — with the daemon's
own `audit tail` then showing the final `allow` decision. This proves the
full "click Approve in a browser → a real customer machine actually does
the thing" path end-to-end, not just at the database layer.

**Testing note**: `dashboard/store` and `dashboard/server` (and
`cmd/agentguard-forwarder`'s integration tests) all point at the same real
local Postgres database (`agentguard_dashboard_dev`) by default, and each
test truncates every table up front. Running `go test ./...` lets Go run
different packages' tests concurrently, which races these packages'
truncations against each other and produces flaky, spurious failures
unrelated to the code under test — `go test -p 1 ./...` is required
whenever these packages are included. Documented in both
`store_test.go`'s and this note, not just tribal knowledge.

**Deferred past Phase 1** (deliberately not built — see the plan file):
persistent WebSocket/push (upgrade path from the current polling, without
changing any data model or API shape), SSO, Postgres Row-Level Security as
defense-in-depth beyond the app-layer tenant checks, retention/rollup/
archival jobs for `audit_events`, and any role finer-grained than a single
admin/viewer split.

**`dashboard/web`** — a React + TypeScript SPA (Vite), kept deliberately
small: `react`/`react-dom`/`react-router-dom` only, a hand-rolled ~50-line
polling hook instead of pulling in React Query for what turned out to be
simple short-poll needs. Six flows: login/signup, a tenant switcher (a user
can belong to more than one company), a fleet page (add an agent, see its
one-time registration token with copy-to-clipboard, status derived
client-side from whether `last_seen_at` is within the last 60s), an
overview/metrics page, a filterable live-ish events feed, and a pending-
approvals page that shows a distinct "relaying to agent…" state after a
click rather than pretending the click itself was the resolution — matching
the real request/ack split described above. One real bug caught during
verification against the live Go backend: `GET /api/events`,
`/api/agents`, and `/api/pending` all serialize an empty result as JSON
`null` (a nil Go slice), not `[]` — the first draft of each page called
`.length` straight off the response and would have crashed on exactly the
"nothing here yet" state a brand-new tenant starts in. Fixed by normalizing
`?? []` at each fetch site rather than changing the Go API to always emit
`[]`, since a client-side null-check is one line per page and every other
JSON API a browser talks to has the same footgun — not worth a special
case in three handlers for it.

## Contributor conventions — the anti-duplication guardrail becomes a repo artifact

### Why
The next body of work (closing observability gaps identified in a
competitive review on 2026-09-09: outcome capture, anomaly detection, agent
versions, per-agent profiles, run grouping, alerting, two new framework
adapters, and a compliance export) touches every layer of the repo at once.
The review that
preceded it found the codebase already carried three copies of the
"evaluate → maybe await approval → write an audit event" sequence
(`daemon.Daemon.Evaluate`, `proxy/mcp.(*Proxy).evaluate`,
`proxy/network.(*Proxy).evaluate`) and five inline copies of
"check → raise PolicyDenied → call the tool" in the Python SDK. The user asked
for a mechanical guardrail against that drift, not good intentions: every new
symbol must be justified in writing, before it is coded, against the closest
thing that already exists.

### What changed
- New `docs/conventions.md`: the rule, a canonical "one of each" symbol
  registry (audit event shape, decision funnel, socket clients, test fakes,
  ingest endpoint, events table, polling hook, webhook sender, time parser,
  adapter field accessor, nav entries), the end-of-milestone grep check that
  each new name has exactly one definition, and the CHANGELOG entry template
  every entry from here on follows (`### Why`, `### What changed`,
  `### Guardrail: why new code`, `### Deferred / known gaps`,
  `### Verification run at this milestone`).
- `README.md` gains a short "Contributing" section pointing at it;
  this file's preamble points at it too.

### Guardrail: why new code
`docs/conventions.md` is the first contributor-facing document in the repo.
The closest existing things are `README.md` and `docs/sdk-guide.md`, both
user-facing; there is no `CLAUDE.md`, and CHANGELOG entries are per-milestone
narratives rather than a standing rule. A standing rule belongs in one stable
location that is linked from both.

### Deferred / known gaps
The registry names symbols that later milestones will introduce
(`daemon.Decide`, `daemon.AuditLogger.Report`, `daemon.newHexID`). They are
listed now so the milestone that adds each one has a pre-declared home to
check against, not because they exist yet.

### Verification run at this milestone
- `grep -n conventions.md README.md CHANGELOG.md` — both pointers present.
- No code changed; no test run needed.

---

## Audit events carry the full action, run/version identity, and execution outcome — one decision funnel for daemon, MCP proxy, and network proxy

### Why
An audit event today records *that* a decision was made and the flattened
resource string it was about. It does not record the arguments the tool was
called with, what the tool returned, whether it failed, or how long it ran,
and it has no notion of which run of which version of which agent produced
it. Everything the competitive review identified as missing (per-agent
behavioral profiles, version-to-version change detection, anomaly
detection, run grouping, a compliance export) needs those fields, so this
milestone adds them once, at every layer, so no later milestone migrates
the same columns again.

### What changed
- **`daemon.AuditEvent`** grows `event_id`, `kind`, `run_id`,
  `agent_version`, `policy_hash`, `action` (the structured `engine.Action`,
  arguments included, after redaction) and `outcome`. Old log lines still
  parse; the new fields are simply empty. `latency_ms` keeps its original
  meaning (policy evaluation plus any approval wait); tool execution time is
  `outcome.exec_ms`.
- **`daemon.Decide`** is the one decision funnel. `Daemon.Evaluate` takes a
  `DecisionRequest` and delegates to it with the broker-backed `Awaiter`;
  `proxy/mcp` and `proxy/network` call it with `PromptAwaiter(p.Approve)`.
  Their private `evaluate` copies are gone. `grep 'Audit.Log('` outside
  tests now finds exactly one call site.
- **Argument redaction**: new policy section `audit.redact_args: [keys]`
  (schema + `Validate`). `Decide` evaluates the real arguments, then
  redacts before the action reaches an approver or the log, so a condition
  like `password = hunter2` still works while the log shows `[redacted]`.
- **`engine.Policy.Hash`**: first 12 hex of the SHA-256 of the policy text,
  set by `ParsePolicy`, stamped on every event as `policy_hash`.
- **Socket protocol**: `evaluate` accepts `run_id` / `agent_version` and
  returns `event_id`; new `report` command (`id` = that event id, `outcome`
  = `{status, exec_ms, output, output_bytes, output_sha256, error}`).
  `AuditLogger.Report` patches the in-memory ring entry in place and appends
  a `kind:"outcome"` line to the JSONL file; it validates the id and status,
  fills `output_bytes`/`output_sha256` from the full output when the caller
  left `output_bytes` zero, and truncates the stored preview (4 KiB default,
  64 KiB hard cap, never splitting a UTF-8 rune). `audit_query` gains
  `run_id` and `event_id` filters.
- **MCP proxy** now parses `tools/call` `arguments` into `Action.Args`,
  remembers each forwarded call by JSON-RPC id, and — inside the existing
  server→client pump, now `pumpServerToClient` — matches responses (lines
  with an id and no `method`, so a server's own requests are never
  mistaken for responses) to report status, duration, and a preview/size/
  hash of `result`. A JSON-RPC `error` or `result.isError` records an
  error outcome. Denied calls are never in flight and get no outcome.
- **Network proxy** records `{"path": ...}` as the action's args (query
  string deliberately omitted), and after relaying the response reports
  the status line, relayed byte count, round-trip time, and `error` for
  4xx/5xx or a failed upstream dial. Bodies are streamed, never captured.
- **CLI**: `agentctl mcp-proxy` and `agentctl proxy start` take
  `--run-id` / `--agent-version` (defaulting to `$AGENTGUARD_RUN_ID` /
  `$AGENTGUARD_AGENT_VERSION`, which an SDK-wrapped parent exports).
  `agentctl audit tail|query` print an outcome column (`success/17ms`).
- **Forwarder** ships every new field (the action as raw JSON), ships
  outcome patch lines as-is, and now reads at most 500 events per POST,
  looping until the log is drained.
- **Cloud store**: twelve `ALTER TABLE audit_events ADD COLUMN IF NOT
  EXISTS` statements plus three indexes, and `agents.last_agent_version` /
  `last_policy_hash`. `InsertEvents` turns a `kind:"outcome"` event into an
  `UPDATE … WHERE tenant_id AND agent_id AND event_id AND outcome = ''`
  (so a patch can never cross tenants or overwrite a reported outcome) and
  records the batch's last version/policy on the agent row. `QueryEvents`
  scans the new columns via one `scanEvent` helper kept beside its SELECT;
  `EventFilter` gains `RunID`, `AgentVersion`, `Outcome` (`success`,
  `error`, or `none` for not-yet-reported). Ingest is capped at 5000
  events / 16 MiB per request.
- **Web API / frontend**: `GET /api/events` accepts `run_id`,
  `agent_version`, `outcome`; `Agent` carries the last version/policy.
  The Live Feed gains an Outcome column and, in the detail panel, run,
  version, policy hash, outcome with execution time, arguments, error, and
  the output preview (labelled "first N of M bytes" when truncated).
  `DecisionBadge` renders outcome statuses too rather than adding a
  second badge component. The CSV export gains the new columns.

### Guardrail: why new code
Written before the code, per `docs/conventions.md`. Each new symbol, the
closest existing thing, and why that thing could not simply be extended:

- **`daemon.Decide`** — closest: `daemon.Daemon.Evaluate`. It *is* that
  function's body, extracted so `proxy/mcp` and `proxy/network` can call it
  instead of carrying their own copies (they did: `(*Proxy).evaluate` in each
  package was a near byte-for-byte duplicate of `Evaluate` minus the broker).
  `Daemon.Evaluate` becomes a thin wrapper. Net effect is fewer
  implementations, not more.
- **`daemon.DecisionRequest`** — closest: the positional `(actor, action)`
  parameters of `Evaluate`. Two more identity fields (run id, agent version)
  would make a five-argument positional call; a request struct is the
  existing idiom in this package (`Request`, `EvaluateResult`).
- **`daemon.Awaiter`** and **`daemon.PromptAwaiter`** — closest:
  `approval.Func` and `daemon.Notifier`. `Decide` needs to ask "how do I wait
  for a human?" without knowing whether the answer is the daemon's broker or
  a proxy's TTY prompt; `approval.Func` returns no approval id and cannot
  reach the broker, `Notifier` only announces. `PromptAwaiter` is the one
  adapter both proxies use instead of each repeating the
  `if Approve != nil … fall back to on_timeout` block they had.
- **`daemon.Outcome`** — closest: more flat fields on `AuditEvent`. It is
  the payload of the new `report` request *and* the sub-object on the event,
  so one type keeps the wire format and the log format identical by
  construction. It is a parameter bag, not a second event struct.
- **`daemon.AuditLogger.Report`** — closest: `AuditLogger.Log`. `Log` is
  append-only by design and nothing today mutates a recorded event. `Report`
  is the single writer of outcome patch lines and the only code that patches
  the in-memory ring; every enforcement point calls it rather than writing
  its own patch.
- **`daemon.newHexID`** — closest: `newApprovalID`. Same generator with the
  byte count as a parameter; `newApprovalID` is removed, not kept alongside.
- **`engine.Policy.Hash`** and **`engine.AuditPolicy`** — closest: nothing.
  No field records which policy text produced a decision, and no policy
  section governs what the audit log stores. `audit.redact_args` is applied
  inside `Decide` so every surface redacts identically.
- **`proxy/mcp` in-flight map** — closest: nothing; the proxy never
  correlated a request with its response. It lives inside the existing
  server→client pump (renamed `pumpServerToClient`) rather than a second
  goroutine or a second scanner.
- **`proxy/network` counting writer** — closest: nothing counts relayed
  bytes today. Six lines wrapping the existing `resp.Write(conn)`.
- **First `ALTER TABLE … ADD COLUMN IF NOT EXISTS` in `schema.sql`** —
  closest: the existing `CREATE … IF NOT EXISTS` statements. Same
  idempotent, applied-on-every-boot model; no migration runner is added.
- **Socket command `report`** — closest: `evaluate`. The SDK clients are
  connect-per-call and the proxies never use the socket for evaluate at all,
  so holding a connection open to send a second line was rejected; a
  separate command reusing the existing `Request.ID` field (as `approve` and
  `deny` do) is the smallest addition.

Deliberately *not* added: a second event row per call (would double-count
in every existing aggregate), a rollup table, a scheduler, a new socket
client, a new test fake, a new audit logger.

### Deferred / known gaps
- **Hardened mode stays silent.** `agentctl run` emits no audit events;
  kernel-level denials by `sandbox-exec` are not policy decisions and
  synthesising events for them would need a new action type and a fragile
  unified-log tail. A child launched under it inherits `$AGENTGUARD_RUN_ID`,
  so anything it does through the SDK/MCP proxy/network proxy is grouped.
- **Outcome patch lines carry empty decision fields.** The original nine
  fields are not `omitempty`, so a `kind:"outcome"` line prints
  `"decision":""` etc. Readers must key on `kind`; changing those tags would
  alter the JSON of decision lines that older tooling already parses.
- **MCP in-flight map is unbounded.** A call whose response never arrives
  stays until the proxy exits. Proxies are one-per-session processes, so
  this is documented rather than evicted.
- **Network response bodies are never captured**, by decision; an opt-in
  tee for text content types is possible later without a schema change.
- **Redaction is exact-key only** (case-sensitive, top-level). Nested keys
  and pattern matching were not asked for.
- The SDKs do not yet send `run_id`/`agent_version` or report outcomes;
  that is the next milestone. Until then their events have empty identity
  fields and no outcome, exactly like pre-existing log lines.

### Verification run at this milestone
- Toolchain first: `go.mod` requires Go 1.26.0 and the machine's
  `/usr/local/go` is 1.25.5; the cached 1.26.0 toolchain under
  `~/go/pkg/mod/golang.org/toolchain@…` had been half-extracted (no
  `bin/go`), so every `go` command failed before any code was touched.
  Verified the cached zip was intact (`unzip -t`, contains `bin/go`),
  removed only the partial extraction directory, and Go re-extracted it:
  `go version` → `go1.26.0 darwin/arm64`.
- `go test -p 1 ./...` before any change: all 12 packages pass (baseline).
- `go build ./... && go vet ./...` — clean.
- `go test -race -p 1 ./...` after all changes — all packages pass:
  approval, cli, cmd/agentguard-forwarder, daemon, dashboard/server,
  dashboard/store, engine, hardened, proxy/mcp, proxy/network. Extended
  tests: `TestAuditLogPersistsToFile`, `TestSocketAPIEvaluateAllowAndDeny`,
  `TestDaemonEvaluateAllowIsLogged`, `TestProxyForwardsAllowedToolCall`,
  `TestPlainHTTPAllowedRequestIsForwarded`,
  `TestForwarderShipsNewAuditEvents`,
  `TestAgentRegistrationAndEventIngestionEndToEnd`, `TestTenantIsolation`.
  New: `TestRedactArgsAppliedBeforeAudit`,
  `TestAuditReportUnknownEventStillAppendsPatch`,
  `TestAuditReportTruncatesOversizedOutput`,
  `TestSocketAPIReportOutcomeRoundTrip`, `TestParsePolicySetsHash`,
  `TestRedactArgs`, `TestProxyRecordsErrorOutcomeFromJSONRPCError`,
  `TestProxyDeniedCallHasNoOutcome`, `TestReadNewEventsBatches`.
- Two real bugs the tests caught before anything shipped: (1) `Report`
  hashed whatever `Output` it was given whenever the hash was empty, so the
  network proxy's status line ("200 OK") got a SHA-256 that would have
  masqueraded as a hash of the response — fixed by deriving size and hash
  only when the caller left `output_bytes` zero, i.e. sent the whole
  output; the doc comment now states that contract. (2) The forwarder test
  compared the stored `action` JSON as a substring, but Postgres
  re-serialises JSONB with spaces after colons — the data was right, the
  assertion was wrong; it now unmarshals into `engine.Action`.
- `cd sdk-python && pytest` — 36 passed (unchanged SDK against the changed
  protocol; extra response fields are ignored). `cd sdk-ts && npm test` —
  27 passed. `examples/openai-coding-agent` tests against a real built
  `agentctl` daemon — 13 passed.
- `cd dashboard/web && npm run build` — clean; `oxlint` reports only the
  three pre-existing warnings in files this milestone did not touch.
- Guardrail grep: `Audit.Log(` outside tests = 1 (inside `Decide`); one
  definition each of `Decide`, `AuditLogger.Report`, `newHexID`,
  `PromptAwaiter`, `Outcome`, `DecisionRequest`, `Policy.RedactArgs`; zero
  hits for the removed `newApprovalID`, `pumpLines`, `(*Proxy).evaluate`.
- **Manual end-to-end smoke** with freshly built `agentctl`,
  `agentguard-cloud` (against a scratch `agentguard_smoke` Postgres
  database) and `agentguard-forwarder`: signed up a tenant and added an
  agent through the Web API; sent `evaluate` for a `function` action with
  `run_id`/`agent_version` and a `password` argument over the raw socket
  with `nc`, got an `event_id` back; sent `report` for it; sent a denied
  `fs_write`. `agentctl audit tail` showed `success/17ms` on the first row
  and `-` on the denied one. The JSONL held three lines (two decisions,
  one outcome patch) with `"password":"[redacted]"` while the policy
  condition had seen the real value. The forwarder registered with the
  one-time token and shipped in one tick; `GET /api/events` returned two
  rows, the first merged with its outcome (`reported_at` set, hash and
  size present), `args` redacted, `policy_hash` `6dd931d9057a`; the agent
  row showed `last_agent_version=1.0.0` and that hash; Postgres:
  `count(*)=2`, `count(outcome<>'')=1`.

---

## SDKs report tool outcomes, carry run/version identity, and `agentctl policy record` turns audit history into policy tests

### Why
The daemon can now store what a tool returned and how long it ran, but the
two SDKs — the surfaces most agents actually go through — still only ask
"may I?" and never say what happened. They also send no run id or agent
version, so every SDK-originated event is anonymous in the ways the
dashboard is about to care about. Separately, `agentctl policy test` has
always needed hand-written trace files; now that audit events carry the
structured action, real history can become the regression suite.

### What changed
- **Python SDK** (`sdk-python/agentguard/guard.py`): every wrapper now
  goes through one path — `_decide` (the single `evaluate` call, now
  carrying `run_id` and `agent_version`) → `_guarded_call` (raise
  `PolicyDenied` unless allowed) → `_execute` (time the tool, report
  success or the exception, re-raise unchanged) → `_report` (best-effort
  `report`; a dropped or rejected report never touches the tool's result).
  `_wrap_callable` builds the wrapper for `tool`, `checked`, `function`,
  and `_wrap_attr`, producing an `async def` for coroutine functions
  (policy check in a thread via `asyncio.to_thread`, so an approval wait
  never blocks the loop; outcome reported after the await). `check` and
  `evaluate_action` are one-liners over `_decide`; the public surface is
  unchanged. New `Guard(agent_version=, run_id=, capture_output=,
  max_output_bytes=)`; `run_id` is generated when absent and exported to
  `AGENTGUARD_RUN_ID` (as is `AGENTGUARD_AGENT_VERSION`), so children
  such as an MCP server behind `agentctl mcp-proxy` inherit the identity.
- **Arguments on every decision**: `checked`/`function`/`tool`/`wrap_tools`
  bind the call's arguments by parameter name (`_bind_args`, falling back
  to `{args, kwargs}` for non-introspectable callables) and
  `check_and_execute` records its `args` value; string values over 16 KiB
  are cut with a `…[truncated, N chars]` marker (`_capture_args`) so an
  argument can never push an evaluate past the daemon's 1 MiB line limit
  and turn into a blocked tool. `DaemonClient.call` serialises with
  `default=str` so a `Path`/`Decimal`/dataclass argument cannot break the
  request. Output previews are JSON-encoded (`default=str`), sized and
  SHA-256'd in full, then cut on a UTF-8 boundary to `max_output_bytes`.
- **TypeScript SDK** (`sdk-ts/src/guard.ts`): the same collapse —
  `decide` / `guardedCall` / `execute` / `report`, `captureArgs` /
  `positionalArgs` (JavaScript has no parameter names, so positional
  calls record `{args: [...]}` and a single object argument its keys),
  `GuardOptions.agentVersion/runId/captureOutput/maxOutputBytes`, env
  export, `node:crypto` hashing (no new dependency). `wrapAttr` now awaits
  the original so the timing is real. `adapters/vercel.ts` calls
  `guard.checkAndExecute` instead of re-implementing check-and-deny (a
  pre-existing duplication; `throw new PolicyDenied` now has exactly one
  site in `src/`).
- **Test fakes**: `decision_handler` (Python) and `decisionHandler` (TS)
  answer `report`, return an `event_id` on every evaluate, and expose the
  requests they saw (`.reports`, `.evaluates`); `reject_reports` /
  `rejectReports` simulate a daemon that refuses reports.
- **`agentctl policy record`** (`cli/policy_cmd.go`): queries the daemon's
  audit ring (same `audit_query` command and — via the new shared
  `addAuditFilterFlags` in `cli/audit_cmd.go` — the same
  `--type/--decision/--actor/--run` flags as `audit query`, which gains
  `--run`), keeps events that carry a structured action, and writes an
  `engine.TestSuite` YAML with the engine's own decision as `want`
  (`require_approval` for anything that went through an approval,
  regardless of how a human resolved it). `--output` writes a file, else
  stdout; the summary goes to stderr so stdout stays a valid trace file.
- **Docs**: `docs/sdk-guide.md` gains "Outcomes", "Run and version
  identity", the recording workflow under "Testing your integration", the
  three new env vars, and a corrected MCP-arguments limitation
  (arguments are now captured; `mcp` rules still have no conditions).
  `sdk-ts/README.md` mirrors it. `docs/conventions.md` registry updated.

### Guardrail: why new code
Written before the code, per `docs/conventions.md`.

- **Python `Guard._decide` / `_guarded_call` / `_execute` / `_report`** —
  closest: the five inline copies of "evaluate → raise PolicyDenied → call
  the function" in `checked`, `function`, `check_and_execute`, `tool`, and
  `_wrap_attr`, plus the two near-identical `evaluate` request bodies in
  `check` and `evaluate_action`. The new helpers *replace* those copies;
  they are the only code that ever holds a tool's return value, so outcome
  capture has exactly one implementation. `check`/`evaluate_action` become
  one-line wrappers; the public API does not change.
- **Python `Guard._wrap_callable`** — closest: the four decorator bodies
  above. One factory that builds a sync or `async def` wrapper (so
  frameworks that test `inspect.iscoroutinefunction` still see the right
  kind) instead of four hand-rolled closures.
- **TypeScript `Guard.decide` / `guardedCall` / `execute` / `report`** —
  the same collapse of `check`, `checkAndExecute`, `tool`, `wrapAttr`, and
  `adapters/vercel.ts` (which re-implemented check-then-deny on its own and
  now calls `guard.checkAndExecute`).
- **`DaemonClient.call` serialises with `default=str`** (Python) — closest:
  the existing one-line `json.dumps`. Arguments are now sent on every
  evaluate and may contain non-JSON objects; this is a change to the one
  client, not a second serializer.
- **Test fakes** — `decision_handler` / `decisionHandler` learn `report`
  and return an `event_id`; no new fake.
- **`agentctl policy record`** — closest: `agentctl audit query` (same
  socket command, same filters) and `engine.TestSuite` (same YAML shape,
  already the target of `policy test`). The audit filter flags are
  extracted from `audit_cmd.go` into one `addAuditFilterFlags` used by both
  commands; the recorder is a conversion, not a second query path or a
  second file format.

### Deferred / known gaps
- `guard.check()` (name-only, no arguments) and `wrap_tools` on objects
  whose call attribute is a C-implemented callable record no argument
  names — `{args, kwargs}` buckets instead. Frameworks with real Python
  signatures (LangChain tools, plain functions) get named arguments.
- The TypeScript SDK still has no `evaluateAction` (Python has had one
  since the demo-agent milestone); not added here because nothing in this
  milestone needed it, and parity work is its own change.
- `policy record` reads the daemon's in-memory ring (the last 2000
  events), not the JSONL file; recording a longer history means recording
  before the ring rolls, or pointing the cloud export (a later milestone)
  at the same conversion.
- Arguments redacted by `audit.redact_args` replay as `"[redacted]"` in a
  recorded trace, so a `functions` condition on a redacted key will not
  reproduce under `policy test`. Documented in the SDK guide and in the
  command's doc comment.
- No lint/format tooling is configured for the SDKs (unchanged gap);
  `pyflakes` is run by hand.

### Verification run at this milestone
- `cd sdk-python && pytest -q` — 47 passed (36 before). The two
  `@guard.checked` tests whose assertions pinned the exact action sent
  were updated to expect the new `args` field — a deliberate behaviour
  change, not a regression. New: success-with-timing/preview/size/hash,
  exception-reports-error-and-reraises, truncation on a rune boundary,
  `capture_output=False` keeps status+timing, rejected report never
  breaks the call, denied call sends no report, async tool reported after
  await (and still `iscoroutinefunction`), run id/version sent and
  exported, run id inherited from env, long string args capped, non-JSON
  args (a `Path`) do not break evaluate; the LangChain-style wrap test now
  also asserts a report.
- `cd sdk-ts && npm test` — 37 passed (27 before), mirroring the above;
  the Vercel adapter tests pass unchanged on the deduplicated adapter.
- `python3 -m pyflakes agentguard tests` — clean.
- `go test -race ./cli/` — passes in 1.4s, including the new
  `TestRunPolicyRecordProducesSuiteThatPasses` (live daemon: two shell
  commands, a `function` with args, and an approval-gated command that
  the test *denies* — recorded as `want: require_approval` — then the
  recording replayed through `runPolicyTest`: `4 passed, 0 failed`; a
  `--run --decision deny` recording on stdout parses and holds 2 cases).
  One real mistake caught by running it: the first version of that test
  let the approval-gated evaluate wait out the CLI policy's default 300s
  timeout, so the package took 301s; it now resolves the approval the
  way `audit_approve_test.go` does.
- `go test -race -p 1 ./...` — all packages pass.
- `examples/openai-coding-agent` tests against a real built daemon with
  the reporting SDK — 13 passed.
- Guardrail grep: one definition each of `_decide`, `_guarded_call`,
  `_execute`, `_report`, `_wrap_callable`, `_capture_args`, `_bind_args`
  (Python), `decide`, `guardedCall`, `execute`, `report`, `captureArgs`,
  `positionalArgs` (TS), `addAuditFilterFlags`, `runPolicyRecord` (Go);
  `raise PolicyDenied` at two code sites in `guard.py` (the sync and async
  paths) and none in the adapters; `throw new PolicyDenied` at one site
  in `sdk-ts/src`; no hand-built `daemon.AuditFilter{}` outside the
  shared flag builder.
- **Real cross-language interop test** (Python SDK → Go daemon, the
  standard this repo holds every protocol change to): with a freshly
  built `agentctl` daemon and a policy carrying an `mcp` allow/deny pair,
  a `functions` rule with an `amount < 100` condition plus a
  `require_approval` fallback (1s timeout), and `audit.redact_args:
  [card]`, a plain Python script using `@g.tool()`, `@g.function()`, and
  an `async` tool: the exported `AGENTGUARD_RUN_ID` matched `g.run_id`;
  a 5 KB tool result was reported with `output_bytes=5040` and a 4096-byte
  preview; `charge(10, card=…)` allowed and reported; `charge(42, …)`
  raised inside the tool and was reported as `error … RuntimeError: card
  declined` while the exception still reached the caller; `charge(500,
  …)` required approval, timed out to deny, and raised `PolicyDenied`;
  the async `send_email` was denied by the `mcp` rule. `agentctl audit
  tail` showed `success/0ms`, `error/0ms`, and `-` in the outcome column;
  every decision line held `"card":"[redacted]"`. `agentctl policy record
  --output` wrote 5 cases (the approval-gated one as `want:
  require_approval`) and `agentctl policy test` replayed them `5 passed,
  0 failed`; `policy record --run <id> --decision deny` on stdout held
  the two denied cases.

---

## Agent versions, per-agent profiles, scope keys, tool descriptions, and automatic versioning (plan Phase 3)

### Why

A per-agent behavioral profile with task and tool breakdowns and change
detection across agent versions was flagged as a differentiator worth
matching in the competitive review. After
Phases 1–2 every event carries a version, arguments, an outcome, and timing,
but the dashboard only ever aggregated allow/deny counts for a whole tenant.
This milestone makes the same aggregation answer "what does *this agent at
this version* do, and how is that different from the previous version",
and lays down the two inputs the Phase 4 anomaly detector needs: a stable
grouping key for resources and a description for every tool so it can be
classified.

Design revisions agreed on 2026-09-09 before this phase started (recorded
in the plan file): scope keys normalized per action type so file paths and
shell commands do not explode the footprint; tool descriptions captured at
wrap time for a one-time LLM verb classification in Phase 4; automatic
agent versions so version-aware baselines work without customers setting
anything.

### What changed

**Engine.** `engine.ScopeKey(actionType, resource)` (`engine/scope.go`)
normalizes a resource into the footprint key: fs paths → parent directory
with a trailing slash, shell → first token, everything else unchanged,
prefixed with the action type. `engine.Action` gained `Description`
(json/yaml `omitempty`; the evaluator ignores it). `daemon.Decide` caps it
at `daemon.MaxDescriptionBytes` (512) before logging.

**Store.** `audit_events.scope_key` (`ALTER … ADD COLUMN IF NOT EXISTS`) is
computed once in `InsertEvents`; readers use
`COALESCE(NULLIF(scope_key,''), resource)` so rows from before the column
still group. New `tool_catalog` table keyed `(tenant_id, action_type,
resource)` for `mcp_tool` / `function` actions only: `InsertEvents` folds
each batch into one upsert per distinct tool (`observeTool`,
`queueToolCatalogUpserts` in `store/tools.go`), keeping an existing
description when a later batch has none and accumulating argument names.
`Store.ListToolCatalog` reads it. `Store.Metrics` now takes
`MetricsFilter{Since, Until, AgentID, AgentVersion, RunID}` and returns,
besides the original five fields, `TotalCount`, `ReportedCount`,
`ErrorCount`, `DistinctResources` (distinct scope keys), `ByActionType`,
`TopResources` (top 20 scope keys), `ExecP50MS` / `ExecP95MS`
(`percentile_cont`, nil with no samples), `ExecSamples`, `EventsPerHour`,
`FirstSeen` / `LastSeen`, and — only when `AgentID` is set — `Versions`
(every version the agent ever sent, most recent first, ignoring the other
filters so it can drive a selector). One aggregate query with `FILTER`
clauses replaced the `GROUP BY decision` query; `topN` takes a limit.

**Web API.** `GET /api/metrics` reads `agent_id`, `agent_version`,
`run_id`. New `GET /api/tools` (viewer) lists the catalog.

**Frontend.** `api.metrics(tenantId, filters)` takes an options object.
`StatCard` and `RankList` moved to `components/` (RankList gained an
optional `describe` tooltip callback and a `compact` variant). The Fleet
table gained sortable Version and Policy columns; clicking a row opens
`AgentDetailPanel` in the Live Feed's `split-view`: a version selector
(defaulting to the agent's latest), a six-cell stat grid, action-type and
footprint rank lists (tool descriptions from the catalog as tooltips), and
a "current vs. previous version" delta table (events/hour, deny rate,
error rate, p50/p95 exec, distinct resources, new resources). Two
`usePolling` calls, no new page or route.

**MCP proxy.** `handleClientLine` remembers the ids of forwarded
`tools/list` requests; `observeServerLine` reads each tool's description
out of the matching response; the first `tools/call` to each tool carries
it (`descriptionFor`).

**SDKs.** Both wrappers now record, at wrap time, each tool's description
(docstring first paragraph / `.description` / Vercel definition
`description` / explicit argument to `tool()`) and signature. The
description rides on the first evaluate per tool per process
(`_with_description` / `withDescription`). When no `agent_version` is
given and `auto_version` (`autoVersion`) is on — the default — the Guard
derives one: `git:<12 hex>` from the nearest `.git` above the working
directory (`HEAD`, loose refs, packed-refs, worktree `gitdir:` files; no
`git` binary), else `tools:<12 hex>` over the sorted tool signatures,
frozen at the first decision. Derived versions are exported to
`AGENTGUARD_AGENT_VERSION` like explicit ones. `Guard.remember_description`
/ `rememberDescription` is public for adapters whose tool shape the
wrappers do not recognize (the Vercel adapter uses it).

**Docs.** `docs/sdk-guide.md` ("Run and version identity" rewritten, new
"Tool descriptions"), `sdk-ts/README.md`, `docs/conventions.md` registry
(seven new rows; the forbidden list gained "a second tool table, a second
metrics function, a second resource-normalization rule").

### Guardrail: why new code

Every existing symbol named in the plan for this phase was extended rather
than twinned:

- `store.Metrics` grew a `MetricsFilter` parameter and a dozen fields. It
  is still the one aggregation function; the per-agent profile, the version
  comparison, and (in Phase 4) both anomaly windows all call it. There is
  no `Profile` or `AgentStats` function.
- `store.topN` grew a limit parameter instead of a second top-N helper.
- `handleMetrics` reads three more query parameters; `api.metrics` takes an
  options object. No `/api/agents/{id}/profile` endpoint.
- `AgentsPage.tsx` gained a detail panel using the Live Feed's existing
  `split-view` / `detail-panel` CSS and a second `usePolling` call. No new
  page, route, or nav entry.
- `RankList` and `StatCard` **moved** from `OverviewPage.tsx` into
  `components/` because two pages now render them; the Overview page
  imports them from there. Not copied.
- `engine.Action` gained `Description`; `daemon.Decide` and the audit event
  carry it for free because the structured action is already logged and
  shipped verbatim.
- `Guard._wrap_one` / `wrapOne` and `tool()` read the description off the
  shapes they already recognize; `_tool_action` / `toolAction` attach it.
  No new wrapping path.
- The MCP proxy's existing `observeServerLine` picks descriptions out of a
  `tools/list` response; `handleClientLine` attaches them. No second pump
  or parser.

New symbols, and why the closest existing one could not absorb them:

- **`engine.ScopeKey(actionType, resource)`.** Closest: `Action.Resource()`.
  That method is the audit trail's human-readable identity and must stay
  exact (`/etc/passwd`, not `/etc/`); the scope key deliberately loses
  precision to group. Two different contracts, so a second function, placed
  in `engine` next to the action types it switches on. Applied once at
  ingest into a new `audit_events.scope_key` column so the profile query
  and the Phase 4 `EXCEPT` query group on the same stored value.
- **`tool_catalog` table + `Store.ListToolCatalog`.** Closest: storing the
  description on the audit event's `action` JSON (which also happens, once).
  Phase 4 needs "every tool this tenant has, with its description and verb"
  as a lookup keyed by tool, which a scan over event JSON cannot serve. It
  is the one tool table: Phase 4 ALTERs verb columns onto it.
- **`store.MetricsFilter`, `store.VersionSummary`.** Parameter/result
  shapes for the extended `Metrics`; not behavior.
- **`Guard._remember_description` / `rememberDescription`,
  `_git_head_version` / `gitHeadVersion`, `_tool_fingerprint` /
  `toolFingerprint`.** Private helpers in the two SDKs with no prior
  equivalent (nothing read `.git` or hashed the tool set before). Each has
  exactly one definition per language.
- **`GET /api/tools` → `handleListTools`.** Closest: `handleListAgents`
  (same shape, different table). A list endpoint per table is the existing
  convention in `webapi.go`.
- **`components/RankList.tsx`, `components/StatCard.tsx`.** Moves, not
  additions.
- **Private helpers added while landing** (each one definition): store
  `observeTool`, `queueToolCatalogUpserts`, `eventsPerHour`; proxy
  `rememberDescriptions`, `descriptionFor`; Python `_tool_signature`,
  `_with_description`, `_git_version_from_sha`; TS `withDescription`,
  `rememberTool`, `gitVersionFromSha`; frontend `AgentDetailPanel`,
  `DeltaRow`, `shortVersion`, `fmt`, `rate` inside `AgentsPage.tsx`.
- **One thing removed rather than added:** the proxy briefly had its own
  `truncateBytes` for descriptions; it duplicated `daemon.truncateUTF8`,
  so the cap moved into `daemon.Decide` (one place, every enforcement
  point) and the proxy helper was deleted before the phase closed.
- **`Guard(auto_version=)` / `autoVersion`** is a constructor option, not a
  parallel code path: with it off the version resolution simply stops
  after the environment variable, as before this phase.

### Deferred / known gaps

- **Prompt-only changes are invisible to the `tools:` fingerprint**, and a
  dirty working tree still reports the last commit under `git:`. Both are
  stated in the SDK docs; explicit versions remain the recommendation for
  deploys.
- **The tools fingerprint is over the tools wrapped before the first
  decision.** Tools wrapped later in the process do not change it (a
  version must be stable for a run). TS signatures use arity, not
  parameter names (JavaScript has no parameter introspection), so two TS
  tools that differ only in parameter names fingerprint the same.
- **`tool_catalog` is per tenant, not per agent.** Two agents in one
  tenant with a `lookup` tool that means different things share one row;
  the last description written wins. Per-agent catalogs would be one more
  key column if that ever matters.
- **Descriptions are sent once per process**, so a long-lived agent that
  changes a tool's description without restarting never re-sends it. The
  catalog also only learns tools from the SDKs and the MCP proxy;
  `check_and_execute` / `checkAndExecute` and the OpenAI/Anthropic
  dispatch adapters see a call, not a definition, and send none.
- **`scope_key` is not backfilled** for rows ingested before this phase
  (the dev database is the only one that exists); those rows group by raw
  resource via the `COALESCE` fallback.
- **`Versions` ignores the time filter by design**, so the selector can
  list old versions; the per-version stats next to it do honor the
  filter. The panel makes two metrics calls (current + previous version)
  and one tool-catalog call every 20 s while open.
- **No per-run features yet** (calls per run, repeats within a run); they
  are Phase 4's volume kind and will be one more `GROUP BY run_id` in
  `Metrics`.
- **The Fleet table is wide** (seven columns plus a 460 px panel); below
  ~1200 px the existing responsive rule stacks the panel under the table.

### Verification run at this milestone

- `gofmt -l .` — clean. `go vet ./...` — clean.
- `go test -race -p 1 ./...` — all 10 packages with tests pass (engine
  1.4 s, daemon 2.6 s, proxy/mcp 1.6 s, cli 1.5 s, forwarder 5.2 s, store
  15.6 s, server 10.9 s). New: `engine TestScopeKey` (15 cases, one of
  which caught a wrong expectation in the test — `/etc/passwd` groups
  under `/etc/`, not `/`), `store TestMetrics` (rewritten: two versions,
  outcomes, exec percentiles, scope-key grouping, version list ordering,
  open vs. closed time spans, empty result), `store TestToolCatalogUpsert`,
  `TestTenantIsolation` (extended: tool catalog and per-agent metrics are
  tenant-scoped), `server TestMetricsPerAgentVersionAndToolCatalog`,
  `mcp TestProxyAttachesToolDescriptionOnce`.
- `cd sdk-python && pytest -q` — **54 passed** (was 47). `pyflakes
  agentguard tests` — clean. New: description-once, function-decorator and
  LangChain-shape descriptions, description cap, git HEAD (loose ref),
  packed-refs, tools fingerprint (frozen at first decision, order-
  independent, set-sensitive), explicit-wins.
- `cd sdk-ts && npm test` — **42 passed** (was 37). Same five scenarios.
- `cd dashboard/web && npm run build` — clean; `npm run lint` — 5
  warnings, all pre-existing patterns (the one this phase introduced, an
  exported non-component from a page file, was fixed before closing).
- `examples/openai-coding-agent`: `pytest tests/` against a real daemon —
  13 passed in 40 s (the example now runs under an automatic `git:`
  version with no change to its code).
- **End-to-end smoke** (script in the session scratchpad): built
  `agentctl`, `agentguard-cloud`, `agentguard-forwarder`; signed up,
  created and registered an agent; started a daemon; ran a Python agent
  twice — version 1.0 with two read tools, version 1.1 adding a write tool
  and a policy-denied delete — then `agentguard-forwarder -once`. Results
  from the Web API: Fleet row shows version `1.1` and the policy hash;
  `/api/metrics?agent_id=…&agent_version=1.0` → 12 events, 0 denies, 12
  reported, p50 6 ms, 2 distinct resources; `…=1.1` → 18 events, 1 deny,
  17 reported, p50 11 ms, 4 distinct resources, footprint listing the two
  new tools; `versions` = `[1.1 (18), 1.0 (12)]` from both calls;
  `/api/tools` → four rows, each with its docstring and argument names;
  the daemon's audit log carried each description exactly once per
  process. Two script mistakes on the way (a Unix socket path over
  macOS's 104-byte limit; the daemon flag is `--audit`, not
  `--audit-log`) were in the script, not the product.
- Guardrail grep: every new Go/Python/TS/TSX symbol above has exactly one
  definition (`rememberDescription` 1 definition + 2 call sites).

## Rules-free anomaly detection, tool verb classification, and tenant-configurable thresholds (plan Phase 4)

### Why

Phase 3 gave every agent a per-version profile — what it does, and how
that compares to its own previous version — but a human still has to open
the Fleet page and notice a change. Surfacing behavioral deviations without
anyone writing a detection rule was the other differentiator flagged in
the competitive review. This phase adds that on top of the Phase 3 profile data,
using the two inputs Phase 3 laid down for it: `scope_key` for a stable
resource-grouping key, and tool descriptions for a one-time verb
classification.

Design agreed with the user before this phase started (recorded in the
plan file, "Decisions taken" #14/#16 and the revised Phase 4 section):
classification is LLM-based (a one-time job per tool, not per event) with
a heuristic fallback so a missing API key never blocks anything; baselines
are automatic and rolling, derived from the customer's own history, never
hand-defined and never cross-tenant; thresholds are tenant-configurable
from day one via one `tenant_settings` table and one Settings page; the
four deviation kinds are named **system**, **operation**, **scope**, and
**volume** to match the vocabulary the product is being compared against.

### What changed

**Verb classification.** `engine.HeuristicVerb(actionType, resource)`
(`engine/verb.go`) resolves every built-in action type deterministically
(fs_read → read, fs_write → write, secret_env → permission, network by
HTTP method, shell by a short list of common program names) and scores an
mcp_tool/function name by keyword (delete/remove/... → delete, grant/
permission/... → permission, write/create/update/... → write, read/get/
list/... → read); anything it can't read confidently is `unknown` rather
than guessed. `tool_catalog` gained `verb`, `verb_reason`,
`verb_confidence`, `verb_source` (`llm`/`heuristic`/`user`), and
`classified_at`. `server.toolClassifier` (`dashboard/server/classifier.go`)
calls the Anthropic Messages API directly over `net/http` — the one place
this codebase talks to an LLM, and the sanctioned zero-dependency
exception since it runs only in the cloud binary — for every catalog row
with `verb_source = ''`; on any failure, or with no `ANTHROPIC_API_KEY`
configured, it falls back to `engine.HeuristicVerb`. A row an admin sets
via the new `PUT /api/tools/verb` (`verb_source = 'user'`) is never
selected for re-classification.

**Anomaly detection.** `server.anomalyRunner` (`dashboard/server/anomaly.go`)
runs after every ingest, throttled to once per agent per 60s
(`anomalyRunner.maybeRun`, called from `handleIngestEvents` after it
re-fetches the agent so detection sees the version the batch just
advanced to, not the one resolved from the API key before the batch was
inserted). The window is the current hour (or however many minutes the
tenant configures), aligned to the hour so re-running detection within it
upserts the same rows. The baseline is the same version's own prior
`baseline_hours` if that's ≥ `min_baseline_events`, else the previous
version's own last `baseline_hours` of activity (its own lifetime, not the
same clock window — a retired version's "recent" history is whenever it
was last used), else detection skips entirely for that agent this run
(`anomalyRunner.resolveBaseline`) — nobody hand-defines a baseline, and it
never crosses tenants because it is always computed from `store.Metrics`
scoped to the one agent. Four kinds, each a row in the new `anomalies`
table:
- **system** — new scope keys (via the new `store.NewScopeKeys`, a
  set-difference query), capped at 25 per run; plus elevated error rate
  and elevated p50 execution time.
- **operation** — a shift in the read/write/delete/permission share of
  calls (via the new `store.VerbCounts`, which classifies mcp_tool/
  function calls through the tool catalog and everything else through
  `engine.HeuristicVerb` directly — built-ins are never cataloged, so they
  are never classified any other way); plus an elevated deny rate.
- **scope** — a single reported call whose output size is far above the
  baseline's 95th percentile for that scope key (via the new
  `store.ScopeOutputStats`).
- **volume** — an elevated overall call rate (from `store.Metrics`'
  existing `EventsPerHour`); plus an elevated average calls-per-run (via
  the new `store.RunEventCounts`, a thin wrapper over the existing `topN`).

Every ratio/rate comparison goes through one function,
`server.ratioAnomaly`, so "how much bigger than the baseline is enough" is
answered the same way in all four kinds; every rate goes through
`server.rateOf` so a zero denominator is 0, not NaN. `anomalies` is keyed
`UNIQUE (agent_id, kind, key, window_start)`, so `store.UpsertAnomaly`
updates a still-open row in place rather than duplicating it (it does not,
however, delete a row for a deviation that stops reproducing — see gaps).

**Tenant settings.** New `tenant_settings` table (one row per tenant),
`store.TenantSettings` + `DefaultTenantSettings` (the one place the
numbers are named) + `Get/PutTenantSettings` + `(TenantSettings) Validate`,
`GET/PUT /api/settings` (viewer/admin), and `SettingsPage.tsx` — thresholds
in one form, plus a table of every cataloged tool with its verb, source,
and (admin) an override dropdown. New nav group "Configuration" in
`Sidebar.tsx`/`Header.tsx`/`App.tsx`.

**Anomalies UI.** `components/AnomalyList.tsx` (new, shared) renders in two
places: a third panel on `OverviewPage` (tenant-wide, unacknowledged,
newest first, with Ack for admins) and inside the Fleet page's
`AgentDetailPanel` (scoped to that agent). Both call the same
`api.ackAnomaly`.

### Guardrail: why new code

- **`engine/verb.go`, `dashboard/server/classifier.go`,
  `dashboard/server/anomaly.go`.** No verb notion, no LLM caller, and no
  detector existed before this phase; each is the one definition its
  registry row now names.
- **`store.VerbCounts`, `RunEventCounts`, `ScopeOutputStats`,
  `NewScopeKeys`.** The closest existing symbol is `store.Metrics` (the
  one aggregation function) and its private `topN` helper. `RunEventCounts`
  and `VerbCounts` are thin wrappers *over* `topN` — grouped by `run_id`,
  and by a composite `action_type`+`resource` expression respectively —
  not new SQL. `ScopeOutputStats` needs two aggregates (`max` and
  `percentile_cont`) per group, a shape `topN`'s single-count design
  can't express without becoming a much more general (and unused-elsewhere)
  function. `NewScopeKeys` needs a set-difference (`NOT IN` over a second
  filtered scan), which no counting/grouping function can express at all.
  All four take a `store.MetricsFilter` (or the same explicit
  window/baseline parameters `Metrics` uses) rather than inventing a
  second filter shape.
- **`store.GetAgent`.** Closest: `AgentFromAPIKey` (resolves by key, not
  id) and `ListAgents` (every agent in a tenant, not one fresh row). The
  ingest handler needs exactly one fresh row right after `InsertEvents`
  may have just advanced its `last_agent_version`.
- **`tenant_settings`, `anomalies` tables; `store.TenantSettings`,
  `store.Anomaly`, `store.AnomalyFilter`, `store.ScopeOutputStat`.** Named
  in the plan as the one settings table and the one anomalies table before
  any code was written; `docs/conventions.md`'s forbidden list already
  named "a second tenant-settings table" and "a second tool table"
  specifically to head this off.
- **`PUT /api/tools/verb`, `GET/POST /api/anomalies*`, `GET/PUT
  /api/settings`.** Closest: `handleSetToolVerb` extends the existing
  `tool_catalog` row (`SetToolVerb`, one writer of those columns, next to
  `ListToolCatalog` in the same file); the anomaly/settings handlers are
  one-list-one-write-one-ack, following the same shape as
  `handleListPending`/`handleResolvePending`.
- **`components/AnomalyList.tsx`, `pages/SettingsPage.tsx`.** No anomaly
  rendering or settings UI existed. `AnomalyList` is shared rather than
  written twice into `OverviewPage.tsx` and `AgentsPage.tsx`.
- **Private helpers added while landing** (each one definition):
  `verbFor` (store, shared by `VerbCounts`), `metricsWhere` (extracted out
  of `Metrics` so the four new aggregates build the same WHERE clause
  rather than a second copy — a refactor, not new logic), `sumVerbs`,
  `avgCount`, `rateOf`, `ratioAnomaly`, `parseClassifierResponse`
  (isolated so the classifier's JSON parsing has a test that never
  touches the network), `describeAnomaly` (frontend, inside
  `AnomalyList.tsx`).

### Deferred / known gaps

- **Detection runs synchronously inside the ingest request**, bounded by a
  5s context, rather than in a background worker. The plan called for a
  `sync.Map` throttle either way; running synchronously avoided adding any
  new concurrency machinery (no ticker, no queue) and made every new test
  deterministic (no sleeping to wait for a goroutine). The cost is added
  ingest latency roughly once a minute per agent, bounded by the 5s
  timeout. A future move to a background worker would not change the
  detector's logic, only who calls `maybeRun`.
- **A settings-cache-per-tenant-for-60s micro-optimization from the plan
  was skipped.** Detection already runs at most once per agent per minute,
  which already bounds `GetTenantSettings` to that same rate; caching on
  top of an already-throttled call has no material benefit here.
- **`UpsertAnomaly` never deletes a stale row.** A deviation that stops
  reproducing in a later run of the *same* window stays reported; only a
  human acknowledging it, or the window rolling forward, moves past it.
  Documented, not fixed — the plan's `anomalies` schema has no soft-delete
  or "still active" column, and adding one is a bigger decision than this
  phase should make unasked.
- **Scope kind's argument-shape check (single id → list/wildcard) was not
  built.** Only the bulk-output-size check shipped. Detecting a shape
  change generically (across every tool's differently-shaped arguments)
  needs a real design, not a rushed one; recorded here rather than shipped
  half-working.
- **Warm-up starvation is real and untouched.** An agent version with
  fewer than `min_baseline_events` and no usable previous version simply
  never gets checked. No partial/low-confidence detection was added.
- **No feedback from acknowledgement.** Acking a system/operation/scope/
  volume anomaly stops it showing as unacknowledged; it does not raise
  that agent's threshold, silence that specific key, or otherwise change
  future detection. Every one of these was already listed as deferred in
  the plan before this phase started.
- **The classifier prompt and its parsing were exercised via the
  heuristic-fallback path in every automated test** (no `ANTHROPIC_API_KEY`
  in the test/dev environment); `parseClassifierResponse` has direct unit
  coverage for the response-parsing/validation logic, but the live
  Messages API call itself is untested here — a real key would be needed,
  and this repo has none checked in (nor should it).
- **Fixed ratios, not statistical scoring.** A tenant sees the same
  `volume_ratio`/`share_shift`/etc. thresholds until they change them by
  hand; there is no auto-tuning from false-positive/negative feedback.
  Named as a size/risk item in the plan, not attempted here.

### Verification run at this milestone

- `gofmt -l .` — clean. `go vet ./...` — clean.
- `go test -race -p 1 ./...` — all packages with tests pass (engine,
  daemon, proxy/mcp, proxy/network, cli, forwarder, approval, hardened,
  store 16.6s, server 19.6s). New: `engine TestHeuristicVerb` (20 cases);
  `store TestTenantSettingsDefaultsAndRoundTrip`, `TestTenantIsolation`
  (extended: tenant settings and anomalies are tenant-scoped, including
  that acknowledging under the wrong tenant is `ErrNotFound`); `server
  TestDetectAnomaliesAllKinds` (one scenario triggering all four kinds
  plus their sub-checks, and confirming a second detection pass on the
  same window upserts rather than duplicates), `TestDetectAnomaliesFallsBackToPreviousVersion`,
  `TestDetectAnomaliesHonorsTenantThresholds` (the same mild share shift
  flagged under default thresholds and not under a stricter one, run in
  that order on the same window so no upserted row is left over to
  confuse the assertion), `TestSettingsPutRequiresAdmin` (defaults, save,
  round-trip, foreign-tenant 403, validation 400), `TestIngestTriggersAnomalyDetection`
  (a real `POST /v1/events` call triggers detection synchronously, visible
  in `GET /api/anomalies` immediately after), `TestParseClassifierResponse`
  (5 cases, no network), `TestToolClassifierHeuristicFallbackAndUserOverride`.
- `cd dashboard/web && npm run build` — clean; `npm run lint` — the same 5
  pre-existing warnings as Phase 3, none new.
- **End-to-end smoke** against a real running `agentguard-cloud` +
  Postgres (not just the test suite): signed up, created and registered
  an agent, shipped 62 events over HTTP exactly as a forwarder would (a
  41+9-event baseline plus a window with a new directory, a write burst,
  and a new `function` tool). `GET /api/anomalies` returned all five
  expected rows in one detection pass (`volume/events_per_hour`,
  `operation/write`, `operation/read`, `system/function:delete_customer`,
  `system/fs_read:/newdir/`) with correct baseline versions/windows;
  `GET /api/tools` showed `delete_customer` classified `delete` via
  `heuristic fallback (no classifier key configured...)`; `PUT
  /api/tools/verb` then `GET /api/tools` confirmed the override persisted
  as `verb_source: user`; `POST /api/anomalies/ack` dropped the
  unacknowledged count from 5 to 4; `PUT /api/settings` then `GET
  /api/settings` round-tripped a changed `window_minutes`.
- Guardrail grep: every new Go/TS/TSX symbol above has exactly one
  non-test definition.

## Switch the tool classifier's LLM provider to OpenAI, and load local secrets from a `.env` file

### Why

The Phase 4 tool classifier (`dashboard/server/classifier.go`) called
Anthropic's Messages API. The user has an OpenAI key available for this
project and asked to use OpenAI instead, with the key supplied via a
`.env` file rather than an exported shell variable.

### What changed

`classifier.go`'s `askLLM` now calls OpenAI's Chat Completions API
(`https://api.openai.com/v1/chat/completions`) with `response_format:
{"type":"json_object"}` to match the prompt's "JSON only" instruction,
reading `OPENAI_API_KEY` instead of `ANTHROPIC_API_KEY` and defaulting
`AGENTGUARD_CLASSIFIER_MODEL` to `gpt-4o-mini` (the same default model the
`examples/openai-coding-agent` demo already uses, so this repo doesn't
name two different "cheap OpenAI default" models). `parseClassifierResponse`
did not change — it was already provider-agnostic (it parses a JSON blob
out of a text response, not the whole envelope). `verb_source: "llm"`
likewise did not change — it was never provider-specific.

New `loadDotEnv` in `cmd/agentguard-cloud/main.go`, called at the top of
`run()`: reads `KEY=VALUE` lines from a `.env` file in the working
directory (`os.ReadFile`, `strings.Cut` on `=`, quotes trimmed) and
`os.Setenv`s any key not already present in the real environment — a real
exported var always wins. Missing file is a no-op, not an error. New
`.env` at the repo root (gitignored — the existing `.env` pattern in
`.gitignore` already covers it) with `OPENAI_API_KEY=` left blank for the
user to fill in, and a commented-out `AGENTGUARD_CLASSIFIER_MODEL`.

### Guardrail: why new code

- **`askLLM`, `defaultClassifierModel`, the `OPENAI_API_KEY` read.** Not
  new symbols — the same one classifier's one LLM-calling method, edited
  in place; no second classifier was written alongside it.
- **`loadDotEnv`.** No environment-file loader existed anywhere in this
  repo (the Python example agent's `.env` is read by `python-dotenv`, a
  dependency of that example only, not by any code in this codebase).
  Closest candidate to extend: none. Deliberately minimal (no quoting
  edge cases beyond a single trim, no `export` keyword, no multiline
  values) rather than adding a dotenv dependency to the cloud binary for a
  handful of optional local-dev keys — consistent with the zero-unnecessary-
  dependency principle applied everywhere else in this codebase.

### Deferred / known gaps

- The live OpenAI call itself is still untested in this environment: the
  user has not yet filled in `OPENAI_API_KEY` in the new `.env`, so the
  classifier continues to run through `engine.HeuristicVerb`'s fallback
  path, exactly as it did with the Anthropic integration. Once a key is
  added, the classifier will start calling OpenAI on the next tool
  seen with `verb_source = ''` — no restart-triggered backfill of
  already-heuristically-classified rows (those keep their `verb_source =
  'heuristic'` value until a human overrides them; re-classifying
  everything on every provider change was judged out of scope here).
- `loadDotEnv` only looks in the process's current working directory
  (`.env`, relative), matching how the binary has been run in this
  project so far (from the repo root). It does not search parent
  directories or accept a `--env-file` flag.

### Verification run at this milestone

- `gofmt -l .` — clean. `go vet ./...` — clean.
- `go test -race -p 1 ./...` — all packages pass, including the existing
  `dashboard/server` classifier/anomaly tests (unaffected — they exercise
  the provider-agnostic heuristic-fallback and parsing paths) and three
  new `cmd/agentguard-cloud` tests: `TestLoadDotEnv` (sets unset vars,
  trims double and single quotes, skips comments/blank lines/malformed
  lines), `TestLoadDotEnvNeverOverridesARealEnvVar`, `TestLoadDotEnvMissingFileIsANoOp`.
- Guardrail grep: `askLLM`, `loadDotEnv` each have exactly one definition.

# Changelog

Running log of significant implementation decisions and milestones, kept alongside git history so the reasoning behind the code is easy to find later. See `/Users/rangasaiyalaka/.claude/plans/this-is-a-new-glimmering-pretzel.md` for the original product plan this build follows.

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

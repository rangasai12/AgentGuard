# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AgentGuard: a policy-as-code enforcement layer for AI agent tool calls, plus an optional hosted dashboard for fleet-wide behavioral observability (per-agent profiles, anomaly detection, tool classification). Local enforcement runs standalone with no dependency on the cloud piece. Go module path: `github.com/rangasai12/AgentGuard`.

Read `README.md` for the product pitch and `docs/conventions.md` before adding any new function/type/table/endpoint — this repo enforces "no second implementation of anything that already exists" on itself, with a canonical symbol registry and a required `### Guardrail: why new code` section in every `CHANGELOG.md` entry. `CHANGELOG.md` is the authoritative narrative build log (one `## <title>` entry per milestone: Why / What changed / Guardrail / Deferred gaps / Verification) — read the relevant entries before touching a subsystem, and append one (don't rewrite history) after a real change.

## Commands

**Go** (root module):
```bash
go build ./...
go vet ./...
gofmt -l .                                    # should print nothing

export AGENTGUARD_DASHBOARD_TEST_DB=postgres:///agentguard_dashboard_test   # REQUIRED before any Go test run — see below
go test -race -p 1 ./...                      # -p 1: dashboard packages share one real Postgres test DB
go test -race ./engine/... -run TestName -v    # single test
```
**Never run Go tests without `AGENTGUARD_DASHBOARD_TEST_DB` set.** `dashboard/store`/`dashboard/server` tests default to `postgres:///agentguard_dashboard_dev` and every test truncates every table — running against that default wipes a real dev database. Create the test DB once (`createdb agentguard_dashboard_test`).

**Python SDK** (`sdk-python/`):
```bash
cd sdk-python && pytest -q
pytest tests/test_guard.py::test_name -v       # single test
pip install -e ".[dev]" && mypy agentguard     # type check (strict: disallow_untyped_defs)
```

**TypeScript SDK** (`sdk-ts/`, native Node 22.6+ execution — no build step):
```bash
cd sdk-ts && npm test
node --test --test-name-pattern="some test" test/*.test.ts   # single test
```

**Dashboard frontend** (`dashboard/web/`):
```bash
cd dashboard/web && npm run build
npm run lint      # oxlint
npm run dev       # vite dev server, proxies /api (see vite.config.ts)
```

**Example agent** (`examples/openai-coding-agent/`): `pytest -q` — its `tests/conftest.py` builds `agentctl` itself via `go build ./cli/cmd/agentctl` (relative path, not a module-path string, deliberately — see CHANGELOG).

**Running things locally**:
```bash
go build -o bin/agentctl ./cli/cmd/agentctl
./bin/agentctl init                                         # writes a starter policy.yaml
./bin/agentctl daemon start --policy policy.yaml             # local enforcement daemon

# Optional cloud dashboard (needs Postgres):
go run ./cmd/agentguard-cloud                                 # Control API + Web API
cd dashboard/web && npm install && npm run dev                 # frontend
go run ./cmd/agentguard-forwarder -register-token=<token>      # ships one machine's audit log

# Or from the CLI, no browser:
agentctl cloud signup --company NAME --email EMAIL --password PASS
agentctl cloud agents create --register <agent-name>
```

## Architecture

**The policy decision point (`engine/`) is pure and framework-agnostic**: `Evaluate(policy *Policy, action Action) Decision`. `Action.Validate()` runs first and denies any action missing its type's required field(s) before the type-specific matcher in `engine/match.go`/`decision.go` ever runs — this is what makes e.g. `secret_env` (the one default-*allow* action type) safe against a malformed/incomplete action. Six action types, each with its own policy section: `fs_read`/`fs_write`, `network`, `shell`, `mcp_tool`, `secret_env`, `function` (the only type with per-argument conditions — `<`/`<=`/`>`/`>=`/`=`/`!=` — everything else is name/path/domain/command matching only).

**One decision funnel, four enforcement surfaces.** `daemon.Decide` (`daemon/daemon.go`) is the single place a policy decision is made, optionally awaited for approval, and audited — the daemon's socket API, the MCP proxy, and the network proxy all call it rather than each reimplementing "evaluate → maybe wait for approval → write an audit event." The four surfaces an action can be enforced at: an SDK-wrapped tool call (talks to the daemon over a Unix socket), the MCP stdio proxy (intercepts `tools/call` JSON-RPC), the network egress proxy (TLS-intercepting), and OS-level hardened mode (macOS `sandbox-exec` — enforces silently, emits no audit event, a documented gap).

**Default socket/audit-log paths are scoped by policy file**, not one fixed machine-wide location: `cli.DefaultSocketPath(policyPath)` hashes the policy's absolute path, so two agents on one machine running two different policies get two different daemons automatically. The same hash algorithm is reimplemented identically in `sdk-python/agentguard/client.py` and `sdk-ts/src/client.ts` (must stay byte-identical, or a CLI-started daemon and an SDK-started `Guard` for the same policy would land on different sockets). `AGENTGUARD_SOCKET`/`AGENTGUARD_AUDIT_LOG` env vars or an explicit `socket_path=` still override outright. A *second*, unrelated check — `Response.PolicyHash` over `ping`, compared against the policy file's content hash — catches the one thing path-scoping can't: the same policy edited on disk without restarting its daemon (raises `DaemonPolicyMismatch`/`DaemonPolicyMismatchError`).

**The SDKs are thin clients with zero decision logic** — every check is a request over the daemon's line-delimited JSON socket protocol (`daemon/socket_api.go`; reimplemented independently in `sdk-python/agentguard/client.py` and `sdk-ts/src/client.ts`, not a shared binding). `Guard.wrap_tools()`/`.tool()` build an `mcp_tool` action (name-based policy only — allow/deny/require_approval per tool name, no argument conditions); `Guard.function()` builds a `function` action (the one path with per-argument conditions); `Guard.checked(action_type, **field_map)` builds any action type explicitly. `wrap_tools()` duck-types tool shapes (plain callable, LangChain legacy `Tool`, `BaseTool`/`StructuredTool` via `_run`/`_arun` — which also covers LangGraph, since its tools are LangChain tools) with no hard dependency on any framework; `sdk-python/agentguard/adapters/*.py` are thin, optional translation shims over `check_and_execute`/`wrap_tools` for OpenAI/Anthropic/LangChain tool-call shapes, not a second enforcement path.

**The cloud dashboard is a separate, additive concern.** `dashboard/store` (Postgres) + `dashboard/server` (Control API for forwarders, Web API for the browser) + `dashboard/web` (React) form a multi-tenant backend fed by `cmd/agentguard-forwarder`, which tails one machine's local audit log and relays browser approve/deny decisions back to that machine's daemon — the daemon itself is unaware this process exists, and local enforcement keeps working if the cloud is unreachable. Per-agent behavioral profiles, rules-free anomaly detection (`dashboard/server/anomaly.go`, four kinds: system/operation/scope/volume, scored against each agent version's own rolling baseline), and automatic tool verb classification (`dashboard/server/classifier.go`, LLM-backed with a heuristic fallback) run server-side off the same ingested events — no local SDK/daemon change needed to get them.

**Repo layout**: `engine/` (PDP) · `daemon/` (local sidecar) · `proxy/mcp/`, `proxy/network/` (interception surfaces) · `hardened/` (macOS sandbox) · `cli/` (`agentctl`) · `sdk-python/`, `sdk-ts/` (SDKs + adapters) · `dashboard/store/`, `dashboard/server/`, `dashboard/web/` (cloud) · `cmd/` (the two cloud-side binaries) · `policy-spec/` (the YAML policy schema) · `examples/`.

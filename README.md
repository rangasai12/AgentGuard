# AgentGuard

**Observability for AI agents.** See exactly what every agent's tools are
doing — arguments, outputs, timing, and effect — with automatic per-agent
behavioral profiles, version-to-version change detection, and rules-free
anomaly detection the moment behavior drifts. A built-in policy-as-code
enforcement layer (`allow` / `deny` / `require_approval`) lets you act on
what you see, at the point of action, when you're ready to — visibility
doesn't require turning enforcement on.

Everything runs locally by default (no dependency on AgentGuard's infrastructure to
capture or enforce anything) with an optional hosted dashboard for fleet-wide
behavioral visibility across every agent a company runs, across multiple companies.

## Screenshots

<!--
  Drop PNGs into docs/screenshots/ using the filenames below and they'll show up
  here automatically. Suggested shots: the Overview page (hero card + sparkline),
  the Live Feed master-detail view, and the Pending Approvals queue.
-->

![Live Feed](docs/screenshots/live-feed.png)
![Overview dashboard](docs/screenshots/overview.png)



## Why

Most tools for understanding what an AI agent is actually doing are either
raw, unstructured logging with no notion of "normal" for this agent, or a
security sandbox that isolates an agent with no visibility into its behavior
at all. AgentGuard gives every tool call a structured, comparable shape —
action, arguments, output, timing, run, and agent version — the instant it
happens, so you can see what an agent normally does, get told the moment it
deviates, and, if you choose, stop the deviation before it executes rather
than just recording it afterward.

## Key features

- **Per-agent behavioral profiles**: for each agent, and each version of it,
  see what it touches, its read/write/delete/permission mix, error rates,
  and call latency — and how that compares to its previous version.
- **Rules-free anomaly detection**: automatically flags new footprints, shifts
  in what an agent does, abnormal call volume, and abnormally large outputs —
  measured against the agent's own rolling baseline. Nothing to hand-tune to
  get started, though every threshold is tenant-configurable if you want to.
- **Full-fidelity event capture**: every tool call's arguments, output preview,
  execution time, and outcome — not just an allow/deny line — correlated by
  run and by agent version.
- **Automatic tool classification**: tools are classified by effect
  (read/write/delete/permission) from their name and description via an LLM
  with a heuristic fallback, so profiles and anomaly detection work without
  manually tagging every tool.
- **Policy-as-code enforcement, built in when you want it**: one YAML file
  governs filesystem, network, shell, MCP tool, and secret-handling rules,
  enforced at the point of action across four surfaces — an SDK-wrapped tool
  call, an MCP proxy, a network egress proxy, or OS-level hardening — with
  `allow` / `deny` / `require_approval` outcomes and human-in-the-loop
  approval via the CLI, Slack/webhook, or the dashboard.
- **CI-testable policies**: `agentctl policy test` runs a policy against a
  recorded set of traces so a policy change gets regression-tested like code.
- **Multi-tenant cloud dashboard**: fleet-wide live feed, behavioral profiles,
  anomalies, and metrics across every agent a company runs — strictly
  additive, so the local daemon keeps capturing and enforcing even if the
  cloud is unreachable.

## Architecture

```
 Agent process                          AgentGuard (local, always-on capture + enforcement)
 ──────────────                         ─────────────────────────────────────────
 Python/TS SDK  ──┐
 MCP client     ──┼── enforcement ──▶   local daemon (Unix socket)
 shell/network  ──┘     surfaces          │
                                          ├─ policy engine (PDP): Evaluate(policy, action)
                                          ├─ audit log (JSONL) + approval broker
                                          └─ Slack/webhook escalation

                                          │ optional, additive
                                          ▼
                                   agentguard-forwarder (tails the audit log,
                                   relays approvals — one new local process)
                                          │ HTTPS
                                          ▼
                              AgentGuard Cloud (hosted, multi-tenant)
                              Control API + Web API + Postgres + React dashboard
                              behavioral profiles, tool classification, anomaly detection
```

## Repo layout

```
/policy-spec/     # YAML policy DSL schema + example policies
/engine/          # Go: the policy decision point (PDP) — Evaluate(policy, action) -> Decision
/daemon/          # Go: local sidecar daemon (Unix socket API, audit log, approval broker)
/proxy/mcp/       # Go: MCP stdio proxy — intercepts tools/call against policy
/proxy/network/   # Go: TLS-intercepting egress proxy
/hardened/        # Go: OS-level hardened execution (macOS sandbox-exec)
/cli/             # Go: the `agentctl` CLI
/sdk-python/      # Python SDK (agentguard package): Guard, wrap_tools(), framework adapters
/sdk-ts/          # TypeScript SDK (agentguard package), native Node 22.6+ execution
/dashboard/       # Go + Postgres: multi-tenant cloud backend (Control API + Web API)
/dashboard/web/   # React + TypeScript: the cloud dashboard frontend
/cmd/             # Binaries: agentguard-cloud, agentguard-forwarder
/examples/        # Example agents wired to the SDK / MCP proxy
/docs/            # Additional guides (SDK usage, etc.)
```

## Quick start

### Prerequisites

- Go 1.26+
- Python 3.10+ (for the Python SDK / example agent)
- Node.js 22.6+ (for the TypeScript SDK and the dashboard frontend)
- Postgres (only needed for the cloud dashboard — skip if you're only running
  local enforcement)

### 1. Build the CLI

```bash
go build -o bin/agentctl ./cli/cmd/agentctl
```

### 2. Write a policy and start the daemon

```bash
./bin/agentctl init                 # writes a starter policy.yaml
./bin/agentctl daemon start --policy policy.yaml
```

### 3. Wrap your agent

Python:

```python
from agentguard import Guard

guard = Guard(policy="policy.yaml")  # starts the daemon if one isn't already running
tools = guard.wrap_tools([search_tool, file_write_tool, shell_tool])
agent = create_react_agent(llm, tools)  # rest of your agent code is unchanged
```

TypeScript:

```typescript
import { Guard } from "agentguard";

const guard = await Guard.create("policy.yaml");
const tools = guard.wrapTools([searchTool, writeFileTool, shellTool]);
```

Or enforce a command with zero code changes via the network proxy / hardened
runner:

```bash
./bin/agentctl run --policy policy.yaml -- python my_agent.py
```

Anything the policy marks `require_approval` shows up via:

```bash
./bin/agentctl pending
./bin/agentctl approve <id>   # or: agentctl deny <id>
```

### 4. (Optional) Cloud dashboard for fleet visibility

```bash
createdb agentguard_dashboard_dev

# Terminal 1 — backend (Control API + Web API), migrates the schema on boot
go run ./cmd/agentguard-cloud

# Terminal 2 — frontend
cd dashboard/web && npm install && npm run dev

# Terminal 3 — on each machine running an agent: sign up / add an agent in the
# dashboard to get a one-time registration token, then:
go run ./cmd/agentguard-forwarder -register-token=<token from the dashboard>
```

Open the frontend's dev server URL, sign up, and add an agent — the forwarder
ships that machine's audit log and relays browser approve/deny decisions back to
its local daemon. Behavioral profiles, tool classification, and anomaly
detection run automatically as events arrive, no setup required. The cloud is
strictly additive: local capture and enforcement keep working even if it's
unreachable.

## Contributing

Read `docs/conventions.md` before adding code. It records the one rule this repo
enforces on itself: never a second implementation of something that already
exists, and a written justification in `CHANGELOG.md` for every new symbol.

## Testing

```bash
go test -p 1 ./...        # -p 1: dashboard packages share one real Postgres test DB
cd sdk-python && pytest
cd sdk-ts && npm test
cd dashboard/web && npm run build
```

## Status

Actively developed. Local capture and enforcement (policy engine, daemon, MCP
proxy, network proxy, CLI, Python/TS SDKs, macOS hardened mode, CI policy
testing, Slack/webhook approvals) is built and tested. The cloud dashboard's
multi-tenant backend, forwarder, React frontend, full-fidelity event capture,
agent versioning, per-agent behavioral profiles, automatic tool
classification, and rules-free anomaly detection with tenant-configurable
thresholds are built and tested. Run grouping, real-time cloud alerting,
additional framework adapters, and a compliance export are not yet built; see
`CHANGELOG.md` for the full build log and design rationale behind every piece.

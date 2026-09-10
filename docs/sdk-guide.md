# AgentGuard Python SDK — Usage Guide

This is the complete reference for `agentguard`, the Python SDK. It covers
every public entry point, when to use each one, and the one distinction
that matters most: **name-based checks vs. resource-aware checks** — most of
the friction people hit comes from not knowing which one they're using.

For the policy file itself (the YAML you write), see
[`../policy-spec/schema.yaml`](../policy-spec/schema.yaml). For a full
worked example, see [`../examples/openai-coding-agent/`](../examples/openai-coding-agent/).

## How it works, briefly

`agentguard` is a thin client. Every check it does is really a request over
a Unix domain socket to a local daemon (`agentctl daemon start`), which runs
the actual policy engine and returns `allow` / `deny` / `require_approval`.
The SDK has no decision logic of its own — this means the Python SDK, the
TypeScript SDK, the MCP proxy, and the network proxy all enforce identically,
because they're all asking the same engine the same question.

`Guard` auto-starts that daemon for you the first time you construct it, as
long as `agentctl` is on your `PATH`:

```python
from agentguard import Guard

guard = Guard(policy="policy.yaml")
```

## Installation

```bash
pip install -e /path/to/AgentInfra/sdk-python   # not yet published to PyPI

# agentctl must be on PATH for Guard to auto-start the daemon:
go build -o /usr/local/bin/agentctl ./cli/cmd/agentctl   # from the repo root
```

## Quickstart

```python
from agentguard import Guard

guard = Guard(policy="policy.yaml")
tools = guard.wrap_tools([github_search_tool, file_write_tool, shell_tool])
agent = create_react_agent(llm, tools)  # the rest of your agent code is unchanged
```

That's the whole adoption story for tools shaped like LangChain `Tool`/
`BaseTool` objects or plain functions. Everything past this point is about
what `wrap_tools` does and doesn't check, and what to reach for when it
isn't enough.

## The two kinds of check — read this before wiring anything up

| | checks by | can see | used by |
|---|---|---|---|
| **Name-based** | tool *name* only | nothing about the call's arguments | `wrap_tools()`, `@guard.tool()`, `check()`, `check_and_execute()`, both framework adapters |
| **Resource-aware** | a fully-typed action | the actual path / domain / command / env var | `evaluate_action()` |

Name-based checks answer "is a tool called `write_file` allowed to run at
all," matched against your policy's `mcp.servers[<namespace>].tools[]`
section. They **cannot** tell a write to `/workspace/notes.txt` apart from a
write to `/etc/passwd` — both are the same tool name. If your policy's real
teeth are in the `filesystem`/`network`/`shell`/`secrets` sections (as the
example policies are), name-based checks alone won't enforce them —
`evaluate_action()` is what actually asks those sections a question they
can answer. Most real integrations end up using both together: see
[Combining both layers](#combining-both-layers-recommended-pattern) below.

## `Guard`

```python
Guard(
    policy: str,
    socket_path: str | None = None,
    actor: str = "python-sdk",
    namespace: str = "local-tools",
    agentctl_path: str = "agentctl",
    auto_start: bool = True,
    start_timeout: float = 5.0,
    client: DaemonClient | None = None,
)
```

- **`policy`** — path to your `policy.yaml`. Passed straight through to
  `agentctl daemon start --policy` if `Guard` has to spawn the daemon itself.
- **`actor`** — a free-form string recorded on every audit event and passed
  to approval prompts/webhooks. Use something that identifies *this agent
  process/session* (e.g. a user id or run id), not a constant, if you want
  audit logs to be useful across concurrent agents.
- **`namespace`** — groups every tool this `Guard` checks by name under one
  server name in the policy's `mcp.servers` section. Two `Guard`s with
  different namespaces can have independent tool-name rules even if the
  tool names collide. Use a different namespace per logical tool group if
  you want that isolation; otherwise the default (`"local-tools"`) is fine.
- **`auto_start`** — if `True` (default) and no `client` is supplied, `Guard`
  pings the daemon at `socket_path` and, if nothing answers, spawns
  `agentctl daemon start --policy <policy> --socket <socket_path>` itself
  and waits up to `start_timeout` seconds for it to come up. Set to `False`
  if you're managing the daemon's lifecycle yourself (e.g. it's already
  running as a long-lived service).
- **`client`** — pass your own `DaemonClient` (or a test double) to skip
  auto-start entirely; this is how the SDK's own tests, and this repo's
  example tests, run against either a fake or a real pre-started daemon.

### `guard.check(tool_name: str) -> dict`

Name-based check. Returns the raw decision dict:
`{"result": "allow" | "deny" | "require_approval", "matched_rule": "...", "reason": "..."}`.
Blocks until resolved if the result requires approval (see
[Approvals](#approvals-and-timeouts) below). Prefer `check_and_execute`
unless you specifically need to inspect the decision before deciding what
to do.

### `guard.check_and_execute(tool_name, args, execute_fn) -> Any`

The primitive every other name-based wrapper (`wrap_tools`, `@guard.tool`,
both adapters) is built on: calls `check(tool_name)`, and if the result is
`"allow"`, calls `execute_fn(args)` and returns its result. Otherwise raises
`PolicyDenied` — `execute_fn` is never called on anything but an allow.

```python
result = guard.check_and_execute(
    "charge_customer", {"amount": 4200}, execute_fn=lambda args: billing.charge(args["amount"])
)
```

### `@guard.tool(name: str | None = None)`

Decorator form of `check_and_execute`, for a plain function:

```python
@guard.tool()               # tool name defaults to the function's __name__
def charge_customer(amount: int) -> str:
    return billing.charge(amount)

@guard.tool("charge_customer")   # or name it explicitly
def do_the_charge(amount: int) -> str:
    ...
```

Raises `PolicyDenied` on call if not allowed; the wrapped function's body
never runs otherwise. Name-based only — see the caveat above.

### `guard.wrap_tools(tools: list) -> list`

Wraps a list of tool objects so every call is checked by name first. Accepts,
by duck typing:
- a plain function with `__name__`
- an object with `.name` + `.func` (LangChain's legacy `Tool`)
- an object with `.name` + `._run` (LangChain `BaseTool`/`StructuredTool`)

Anything else raises `TypeError` at wrap time (loud failure, not a silently
unprotected tool). Returns new wrapped objects — the originals are
untouched; every other attribute (`.description`, `.args_schema`, ...) is
preserved so framework introspection keeps working.

```python
tools = guard.wrap_tools([search_tool, file_write_tool, my_plain_function])
```

### `@guard.checked(action_type, **field_map)` — the recommended way to gate a tool

The resource-aware counterpart to `@guard.tool()`. Where `@guard.tool()`
only ever checks a *name*, `@guard.checked(...)` builds a fully-typed action
from the function's **own arguments** and checks that — with **no `guard`
parameter added to the function's signature**, and no policy-check code
inside its body:

```python
@guard.checked("fs_write", path="path")
def write_file(path: str, content: str) -> str:
    Path(path).write_text(content)
    return f"wrote {len(content)} bytes to {path}"

@guard.checked("network", domain="domain", method="method",
                is_ip_literal=lambda args: _is_ip_literal(args["domain"]))
def http_request(method: str, domain: str, path: str = "/") -> str:
    ...

@guard.checked("shell", command="command")
def run_shell(command: str) -> str:
    ...

@guard.checked("secret_env", env_var="env_var")
def read_secret(env_var: str) -> str:
    ...
```

Each `field_map` value is either the name of one of the function's own
parameters, or a `callable(call_args: dict) -> value` for a computed field
(`call_args` is the bound arguments by name, defaults already applied — see
`is_ip_literal` above). Raises `PolicyDenied` *before* the function body
runs if the decision isn't `allow`; the function itself is never touched.

This is the actual "under 10 minutes" adoption path for anything gated by
the `filesystem`/`network`/`shell`/`secrets` sections: existing plain
functions gain one decorator line each, nothing else about them changes —
see [`examples/openai-coding-agent/tools.py`](../examples/openai-coding-agent/tools.py)
for the full worked version, where `guard` is constructed once at module
level (the same pattern as `app = Flask(__name__)` then `@app.route(...)`)
and never appears in a tool's parameter list.

### `@guard.function(name: str | None = None)` — argument-condition policy, zero config

`@guard.checked` still requires you to write a `field_map`. `@guard.function()`
needs none at all: it passes *every* argument the function is called with
straight through as the action's `args`, checked against the policy's
`functions` section — which supports per-argument conditions with
`<`, `<=`, `>`, `>=`, `=`, `!=`, not just an all-or-nothing name gate:

```python
@guard.function()
def charge_customer(amount: int, currency: str = "USD") -> str:
    return billing.charge(amount, currency)
```

```yaml
functions:
  default: deny
  rules:
    - name: "charge_customer"
      conditions:
        - {arg: "amount", op: "<", value: 1000}
      allow: true
    - name: "charge_customer"
      conditions:
        - {arg: "amount", op: ">=", value: 1000}
      require_approval: true
      reason: "large charges need a human"
```

This is the answer to "our own tool takes an argument the built-in
`filesystem`/`network`/`shell`/`secrets` sections have no concept of (an
amount, a replica count, a currency) — how do we gate *that*": give the
function a name, add one decorator, write conditions in policy.yaml. Nothing
in Python changes when the threshold changes — that's a `policy.yaml` diff,
not a code change. It also directly closes the gap noted at the bottom of
this guide for generic multi-purpose tools: give each distinct operation its
own function (and thus its own name to write rules against) rather than one
argument-driven dispatcher, and `functions` rules can now actually see the
arguments that distinguish them.

`functions` rules are evaluated as a single ordered list — like
`filesystem` — so the first rule whose `name` matches and whose conditions
*all* hold (AND) wins; put narrower ranges before broader ones. A rule with
no `conditions` matches any call to that name regardless of arguments (pure
name-based, like an `mcp` tool rule). See
[`policy-spec/examples/billing-functions.yaml`](../policy-spec/examples/billing-functions.yaml)
for a complete worked policy, verified via `agentctl policy test`.

#### Action field reference

| `type` | fields | governed by policy section |
|---|---|---|
| `fs_read` / `fs_write` | `path` | `filesystem` |
| `network` | `domain`, `method`, `is_ip_literal` (bool) | `network` |
| `shell` | `command` (the full command string) | `shell` |
| `secret_env` | `env_var` | `secrets` |
| `mcp_tool` | `server`, `tool` | `mcp` (this is what `check()` builds for you) |
| `function` | `name`, `args` (dict of the call's own arguments) | `functions` (this is what `@guard.function()` builds for you) |

### `guard.evaluate_action(action: dict) -> dict`

The lower-level primitive `@guard.checked` is built on — call it directly
only when the action can't be expressed as a static field-to-parameter
mapping (e.g. you need to branch on something outside the function's
arguments, or you're not decorating a function at all — the MCP proxy and
network proxy construct actions this way internally, just in Go). Evaluates
a fully-typed action and returns the same decision dict shape as `check()`,
but does **not** raise on denial — check `decision["result"]` yourself.

```python
decision = guard.evaluate_action({"type": "shell", "command": "rm -rf /"})
if decision["result"] != "allow":
    ...
```

All fields other than `type` are optional in the action dict — omit
whatever doesn't apply to that action type.

## Combining both layers (optional)

`@guard.checked` and the name-based checks are independent and composable.
If you also want an outer per-tool-name gate (e.g. to disable a whole tool
by name regardless of its arguments), route the same call through
`check_and_execute`/an adapter as well — see
[`examples/openai-coding-agent/policy.yaml`](../examples/openai-coding-agent/policy.yaml)'s
`mcp.servers[].default: allow` plus `agent.py`'s use of
`agentguard.adapters.openai.dispatch()` on top of the `@guard.checked`-decorated
tools in `tools.py`: the outer check is a permissive name gate, and the real
enforcement is the decorator underneath it.

## Handling denials: `PolicyDenied`

Raised by `check_and_execute`, `@guard.tool`, wrapped tools, and both
adapters whenever the decision is anything but `"allow"` — including a
`require_approval` that a human denied, or that timed out
(`escalation.on_timeout` in policy.yaml).

```python
from agentguard import PolicyDenied

try:
    result = guard.check_and_execute("refund_customer", args, execute_fn=do_refund)
except PolicyDenied as exc:
    print(exc.tool_name)          # "refund_customer"
    print(exc.decision["reason"]) # e.g. "refunds are handled through the support console"
    print(str(exc))               # a ready-to-use human-readable message
```

If you're driving a model in a loop (OpenAI/Anthropic tool-use), the usual
pattern is to catch this and feed the reason back as the tool result so the
model can react instead of crashing the loop — see
[`examples/openai-coding-agent/agent.py`](../examples/openai-coding-agent/agent.py):

```python
try:
    result = openai_adapter.dispatch(guard, tool_call, handlers)
    content = str(result)
except PolicyDenied as exc:
    content = f"blocked by agentguard policy: {exc}"
messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": content})
```

## Framework adapters

Both adapters are name-based only (they call `check_and_execute` under the
hood) — put your `evaluate_action` calls inside the handler functions you
pass them, as shown above.

### `agentguard.adapters.openai.dispatch(guard, tool_call, handlers)`

```python
from agentguard.adapters import openai as openai_adapter

handlers = {"write_file": lambda args: tools.write_file(guard, args["path"], args["content"])}

for tool_call in response.choices[0].message.tool_calls:
    result = openai_adapter.dispatch(guard, tool_call, handlers)
```

Accepts an SDK `ChatCompletionMessageToolCall` object or the equivalent raw
dict. Parses `tool_call.function.name`/`.arguments` (JSON), looks up
`handlers[name]`, and calls `guard.check_and_execute(name, args, handlers[name])`.
Raises `KeyError` if no handler is registered for that name, `ValueError`
if the tool call has no name.

### `agentguard.adapters.anthropic.dispatch(guard, tool_use_block, handlers)`

Same shape, for a Claude `tool_use` content block (SDK object or dict):

```python
from agentguard.adapters import anthropic as anthropic_adapter

for block in response.content:
    if block.type == "tool_use":
        result = anthropic_adapter.dispatch(guard, block, handlers)
```

### LangChain

No separate adapter module — `wrap_tools()` already duck-types LangChain's
`Tool`/`BaseTool` shapes directly (see above).

## Outcomes: what the tool returned, and how long it took

Every wrapper above does two things, not one. Before the tool runs it asks
the daemon for a decision; after the tool returns (or raises) it *reports
the outcome* against that same decision, so the audit event ends up with:

| Field | Meaning |
|---|---|
| `outcome.status` | `success`, or `error` if the tool raised. |
| `outcome.exec_ms` | Wall-clock time of the tool itself (the event's `latency_ms` is the policy decision plus any approval wait — a different thing). |
| `outcome.output` | A preview of the return value, JSON-encoded for anything that isn't already a string. `max_output_bytes` (default 4096) bounds it; the daemon caps it at 64 KiB regardless. |
| `outcome.output_bytes`, `outcome.output_sha256` | Size and hash of the *full* return value, so a truncated preview is still verifiable. |
| `outcome.error` | `ExceptionType: message` when the tool raised. |

The call's arguments are recorded on the event too (`action.args`), bound
by parameter name where the function's signature allows it. String
arguments longer than 16 KiB are cut with a `…[truncated, N chars]` marker
so a tool that takes a whole file's contents can never push an evaluate
request past the daemon's line limit. Keys listed in the policy's
`audit.redact_args` are stored as `"[redacted]"` — policy conditions still
see the real values.

Reporting is best-effort and asynchronous to the tool's result: a report
the daemon rejects or never receives is dropped, and the tool's return
value or exception reaches your code unchanged. Turn the output preview
off with `Guard(capture_output=False)` or `AGENTGUARD_CAPTURE_OUTPUT=0`;
status and timing are still reported. A denied call never runs, so it
never has an outcome.

Async tools work: a `@guard.tool()` / `@guard.checked()` / `@guard.function()`
on an `async def` yields an `async def` wrapper (so frameworks that check
`inspect.iscoroutinefunction` still see one), the policy check runs in a
thread so an approval wait never blocks the event loop, and the outcome is
reported once the awaited result resolves.

## Run and version identity

Two identifiers ride along on every decision:

- **`run_id`** — one execution of the agent. `Guard` takes it from the
  `run_id` argument, else `AGENTGUARD_RUN_ID`, else generates one; either
  way it is exported back into the process environment, so anything the
  agent launches (an MCP server behind `agentctl mcp-proxy`, a command
  under `agentctl run`) tags its own events with the same run. In the
  dashboard this is what groups a task's tool calls together.
- **`agent_version`** — the build of the agent. The dashboard's Fleet
  page profiles each version separately and shows how version N differs
  from N-1, and the anomaly detector baselines per version. The value
  comes from, in order:
  1. the `agent_version` argument;
  2. `AGENTGUARD_AGENT_VERSION`;
  3. `git:<12-char commit>` — the commit `HEAD` points at in the nearest
     `.git` at or above the working directory, read directly (no `git`
     binary needed);
  4. `tools:<12-char hash>` — a SHA-256 over the names and parameter names
     of every tool this `Guard` wrapped, frozen at the first decision.
  Explicit always wins. A derived version is exported to
  `AGENTGUARD_AGENT_VERSION` so child processes share it. Pass
  `auto_version=False` to record no version when none is given.
  Two things the automatic values cannot see: a **prompt-only change**
  leaves the tools fingerprint unchanged, and an uncommitted working tree
  still reports the last commit. Set the version explicitly from your
  deploy when either matters.

```python
guard = Guard(policy="policy.yaml", agent_version=os.environ.get("GIT_SHA", "dev"))
```

## Tool descriptions

Every wrapper also records what a tool says about itself — the first
paragraph of a function's docstring for `@guard.tool()` / `@guard.function()`,
`.description` for LangChain-style objects — and sends it on the **first**
decision for that tool in each process (capped at 512 bytes). The
dashboard keeps a per-tenant tool catalog from these (`GET /api/tools`,
and tooltips on an agent's footprint), and the anomaly detector uses them
to classify each tool as a read, write, delete, or permission operation
without any configuration from you. Nothing is sent for tools with no
description; `guard.remember_description(name, text)` supplies one for a
tool shape the wrappers do not recognize.

## Approvals and timeouts

Any check whose decision is `require_approval` **blocks the calling thread**
inside the daemon until a human resolves it (`agentctl approve <id>` /
`agentctl deny <id>`, discoverable via `agentctl pending`) or
`escalation.approval_timeout_seconds` elapses, in which case
`escalation.on_timeout` (`allow` or `deny`) decides it. There is no
async/polling API on the Python side — the call you made (`check`,
`check_and_execute`, `evaluate_action`, any wrapped tool) simply doesn't
return until then.

Two things follow from this:
- Pick a `DaemonClient` timeout longer than your policy's
  `approval_timeout_seconds`, or the socket call will raise
  `DaemonUnavailable`/`DaemonStartError` before the daemon even finishes
  waiting. The default `DaemonClient` timeout is 30s; `Guard` doesn't expose
  a shorter path to override it than constructing your own
  `DaemonClient(socket_path, timeout=...)` and passing it as `client=`.
- If your agent runs on a single thread with no way to be interrupted, a
  pending approval will visibly hang that thread — usually fine for a CLI
  demo, worth knowing about for a server handling concurrent requests (run
  the check in a worker thread/executor if so).

## Error handling reference

| Exception | Raised when |
|---|---|
| `PolicyDenied` | The decision was `deny`, or `require_approval` resolved to deny/timeout-deny. Not raised by `evaluate_action` itself — only by the wrappers built on `check_and_execute`; check `evaluate_action`'s return value yourself. |
| `DaemonStartError` | No daemon is reachable and `Guard` couldn't start one (`agentctl` not found on `PATH`), or it didn't come up within `start_timeout`. |
| `agentguard.client.DaemonUnavailable` | A socket call couldn't reach the daemon at all (crashed mid-session, wrong socket path). Surfaces as `DaemonStartError` when raised from inside `Guard`'s own methods. |
| `RuntimeError` | The daemon responded but with `{"ok": false, ...}` — a malformed request, not a policy decision. |

## Configuration reference

| Env var | Effect |
|---|---|
| `AGENTGUARD_SOCKET` | Overrides the default daemon socket path (`~/.agentguard/agentguard.sock`) for both the SDK and `agentctl`. |
| `AGENTGUARD_AUDIT_LOG` | Overrides the default JSONL audit log path used by `agentctl daemon start`. |
| `AGENTGUARD_RUN_ID` | Run id to tag decisions with; set by `Guard` if absent and inherited by child processes. |
| `AGENTGUARD_AGENT_VERSION` | Agent version to tag decisions with (`Guard(agent_version=...)` overrides). |
| `AGENTGUARD_CAPTURE_OUTPUT` | `0`/`false`/`no` disables the output preview in outcome reports (status and timing are still reported). |

`Guard(socket_path=...)` overrides the env var for that instance only.

## Testing your integration

- **Policy correctness** (no Python needed): write cases in a
  `*.traces.yaml` file and run `agentctl policy test policy.yaml traces.yaml`
  — see `policy-spec/examples/coding-agent.traces.yaml`.
- **Or record them instead of writing them**: run your agent, then
  `agentctl policy record --output traces.yaml` turns the daemon's recent
  audit events (the real actions, with their real arguments) into that
  same trace format with the engine's decision as each case's `want`.
  Review the expectations, commit the file, and later policy changes are
  regression-tested against what the agent actually did. It accepts the
  same `--type/--decision/--actor/--run` filters as `agentctl audit query`
  (`--run $AGENTGUARD_RUN_ID` records just the last run). Redacted
  arguments replay as `"[redacted]"`, so a `functions` condition on a
  redacted key will not reproduce.
- **Your tool wiring, against the real engine**: if your module builds its
  own `Guard` at import time the way `@guard.checked` is meant to be used
  (see `tools.py`), your test setup needs a real daemon *already listening*
  before that module is imported — `Guard`'s auto-start otherwise reaches
  for the real default socket path instead of an isolated test one. See
  [`examples/openai-coding-agent/tests/conftest.py`](../examples/openai-coding-agent/tests/conftest.py)
  for a working example: it builds `agentctl`, starts a daemon against a
  throwaway socket, points `AGENTGUARD_SOCKET` at it, and only then imports
  `tools`. If instead you construct `Guard` inside a function/fixture (not
  at import time), the simpler pattern from earlier SDK code still works:
  pass a pre-started daemon's `DaemonClient` into `Guard(client=...)`.
- **Fast unit tests of SDK behavior itself**: `sdk-python/tests/conftest.py`'s
  `FakeDaemon` fixture implements the same wire protocol in-process, if you
  want to unit test call sites without a real daemon at all.

## Current limitations to design around

- Building `Guard` at module import time (so `@guard.checked` never needs a
  `guard` parameter) means the daemon it connects to must already exist, or
  be startable via `agentctl` on `PATH`, at the moment that module is first
  imported — plan your test setup and process startup order accordingly
  (see [Testing your integration](#testing-your-integration)).
- `mcp_tool` actions (real MCP `tools/call` interception via
  `agentctl mcp-proxy`, and the plain name-based `check()`/`wrap_tools()`
  path) are *decided* on `server`+`tool` only. Their arguments are now
  captured on the audit event (and redacted per `audit.redact_args`), but
  the `mcp` policy section has no argument conditions. For SDK-wrapped
  functions this is fully solved by `@guard.function()` + the `functions`
  policy section above; a generic MCP tool exposed by a *server* you don't
  control still needs to be split into distinctly named tools (or checked
  explicitly via `evaluate_action` inside a proxy-side handler) to get
  argument-aware *enforcement*.

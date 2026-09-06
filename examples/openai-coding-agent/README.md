# Example: a real OpenAI agent, fully policy-checked

A small coding agent — read/write files, run shell commands, make HTTPS
calls, read env-var "secrets", scale a service — driven by a real OpenAI
tool-use loop (`agent.py`), where every tool call is checked against
`policy.yaml` before it runs. The policy scopes the agent to a dev workspace
and explicitly blocks anything that reaches toward production: writes to
`workspace/prod/`, network calls to `deploy.prod.internal` or a raw IP, and
reads of `PROD_DEPLOY_TOKEN`/`AWS_SECRET_ACCESS_KEY` — no matter how the
request for that resource is phrased or disguised, since what's checked is
the actual path/domain/command/env-var, not the tool name or the model's
wording. It also gates `scale_service` on its `replicas` argument
(`<= 5` allowed outright, `> 5` needs human approval) — a policy dimension
none of `filesystem`/`network`/`shell`/`secrets` has a concept of.

Look at `tools.py`: each tool is a plain function with one decorator line —
no `guard` parameter threaded through the function, no manual policy-check
code inside it:
- `@guard.checked("fs_write", path="path")`-style for the four tools
  gated by `filesystem`/`network`/`shell`/`secrets` — builds a fully-typed
  action (the same primitive the MCP proxy and network proxy use
  internally) from a `field_map` you declare once.
- `@guard.function()` for `scale_service` — needs no field mapping at all;
  every argument the function is called with is checked as-is against the
  `functions` policy section's `<`/`<=`/`>`/`>=`/`=`/`!=` conditions.

Together these demonstrate the full policy DSL directly, not just the
per-tool-name `mcp` gating that `Guard.wrap_tools()` alone would give you.
See `docs/sdk-guide.md` for the full decorator reference.

## Setup

```bash
cd examples/openai-coding-agent
pip install -e ../../sdk-python
pip install -r requirements.txt

# Build agentctl and put it on PATH (Guard auto-starts the daemon via this).
go build -o /tmp/agentctl ../../cli/cmd/agentctl
export PATH="/tmp:$PATH"
```

Export your own key — never paste it into a file or pass it as a command
argument:

```bash
export OPENAI_API_KEY=sk-...
```

## Run modes

**1. Plain run** — SDK-level enforcement only, interactive by default:

```bash
python agent.py
```

Type your own requests at the `you>` prompt — e.g. "read workspace/config.txt",
"copy it into workspace/prod/config.txt", "run rm -rf workspace/tmp" — and
watch each tool call come back `[allowed]` or `[BLOCKED by policy]` against
`policy.yaml` in real time. `quit`/`exit`/Ctrl-D to stop.

Pass `--scripted` instead to run the fixed multi-step `USER_TASK` in
`agent.py` once, non-interactively (it deliberately includes a prod write, a
prod network call, and a prod secret read, so you see a representative mix
of allow/deny without typing anything):

```bash
python agent.py --scripted
```

**2. With the real network egress proxy** — `http_request` calls get
TLS-intercepted and checked at the actual socket layer, not just by the SDK:

```bash
/tmp/agentctl proxy ca --export /tmp/agentguard-ca.pem
/tmp/agentctl proxy start --policy policy.yaml --addr 127.0.0.1:8091 &

HTTPS_PROXY=http://127.0.0.1:8091 REQUESTS_CA_BUNDLE=/tmp/agentguard-ca.pem python agent.py
```

`requests` honors `HTTPS_PROXY`/`REQUESTS_CA_BUNDLE` natively — no code
change needed in `tools.py`.

**3. Wrapped in macOS hardened mode** (this repo's dev machine is
macOS-only; see `hardened/unsupported.go` for other platforms) — OS-level
enforcement holds even if the Python-level check were somehow bypassed:

```bash
/tmp/agentctl run --policy policy.yaml --proxy-addr 127.0.0.1:8091 -- python agent.py
```

**4. Approval walkthrough** — trigger the `rm -rf` step and resolve it by
hand instead of letting it deny on the 20-second timeout in `policy.yaml`:

```bash
# terminal 1
python agent.py
# terminal 2, once the rm -rf step is pending:
/tmp/agentctl pending
/tmp/agentctl approve <id>   # or `deny <id>`
```

## Checking the audit trail

```bash
/tmp/agentctl audit tail -n 20
```

## Automated tests

`tests/test_tools_policy.py` exercises every allow/deny/require_approval
path in `policy.yaml` against the real daemon (not a mock) — no API key
needed, since it calls the tool functions directly instead of going through
the OpenAI loop:

```bash
python -m pytest tests/
```

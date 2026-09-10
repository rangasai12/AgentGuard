# agentguard (TypeScript SDK)

Thin client for the AgentGuard daemon: wrap an agent's tools so every call is
policy-checked before it runs. All decision logic lives in the Go daemon —
this SDK only translates a tool call into a request over the daemon's Unix
socket and enforces the response. Mirrors `../sdk-python/agentguard` — see
that package and `../CHANGELOG.md` for the shared design rationale.

## Requirements

Node.js **22.6+** (native TypeScript execution via type-stripping — no
build step, no `ts-node`, no compiled output yet). This SDK deliberately
ships source `.ts` files directly rather than a `dist/` build for v0.2;
packaging for npm distribution (a compiled JS + `.d.ts` output, or a
documented minimum-Node-version constraint for consumers) is a later step.

## Quickstart

```typescript
import { Guard } from "agentguard";

// Starts the local daemon automatically if one isn't already running
// (requires `agentctl` on PATH — see ../cli).
const guard = await Guard.create("policy.yaml");
const tools = guard.wrapTools([searchTool, writeFileTool, shellTool]);
// rest of your agent code is unchanged
```

Or for a manual dispatch loop (raw OpenAI/Anthropic tool calling):

```typescript
const result = await guard.checkAndExecute(toolName, toolArgs, myDispatchFn);
```

## Outcomes and identity

Every wrapper reports what the tool returned after it runs: `status`
(`success`/`error`), `exec_ms`, a preview of the return value (JSON-encoded,
`maxOutputBytes` default 4096) with the full value's size and SHA-256, and
the error message if it threw. The call's arguments are recorded on the
decision too (an object argument by its keys, positional arguments as
`{args: [...]}`, strings over 16 KiB cut with a `…[truncated]` marker).
Reporting is best-effort: a lost report never changes what the tool
returns or throws. `captureOutput: false` (or `AGENTGUARD_CAPTURE_OUTPUT=0`)
keeps status and timing but drops the preview.

Decisions carry `runId` (from the option, `$AGENTGUARD_RUN_ID`, or a fresh
id — exported to `process.env` so child processes such as an MCP server
behind `agentctl mcp-proxy` share it) and `agentVersion`: from the option,
else `$AGENTGUARD_AGENT_VERSION`, else `git:<commit>` read from the nearest
`.git` above the working directory, else `tools:<hash>` over the names and
arities of the wrapped tools, frozen at the first decision (`autoVersion:
false` disables the derived values). Set it explicitly from your deploy if
prompt-only changes need their own version.

Tool descriptions are sent on a tool's first decision so the dashboard can
catalog and classify it: `wrapTools` reads `.description` off duck-typed
tools, `guard.tool(fn, name, description)` takes one explicitly (JS
functions have no docstring), the Vercel adapter reads the tool
definition's `description`, and `guard.rememberDescription(name, text)`
covers anything else. See `../docs/sdk-guide.md` for the full field
reference; the semantics are identical.

Framework-specific adapters live in `src/adapters/`: `langchain.ts`,
`openai.ts`, `anthropic.ts`, and `vercel.ts` (the Vercel AI SDK's `tools` is
a name-keyed record with an `execute` function rather than an array of named
objects, so it gets its own small adapter rather than reusing `wrapTools`).

## Development

```bash
npm test   # node --test test/*.test.ts
```

No lint/format tooling (prettier/eslint) is configured yet — noted as a gap
rather than silently skipped; add before this ships more broadly.

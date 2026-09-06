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

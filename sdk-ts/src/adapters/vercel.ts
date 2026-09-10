/**
 * Adapter for the Vercel AI SDK, whose tool shape is genuinely different
 * from LangChain's — `tools` is a `Record<name, ToolDefinition>` keyed by
 * name rather than an array of named objects, and each definition exposes
 * an `execute` function rather than `.name`. No dependency on the `ai`
 * package.
 */
import type { Guard } from "../guard.ts";

interface VercelToolLike {
  description?: unknown;
  execute?: (args: unknown, options?: unknown) => unknown;
  [key: string]: unknown;
}

export function wrapTools<T extends Record<string, VercelToolLike>>(guard: Guard, tools: T): T {
  const wrapped: Record<string, VercelToolLike> = {};

  for (const [name, tool] of Object.entries(tools)) {
    if (typeof tool.execute !== "function") {
      // Not every Vercel AI SDK tool defines execute (some are
      // client-side/provider-executed); pass those through unchanged rather
      // than pretending to guard something with nothing to intercept.
      wrapped[name] = tool;
      continue;
    }
    const original = tool.execute;
    guard.rememberDescription(name, tool.description);
    wrapped[name] = {
      ...tool,
      // Route through the Guard's one check-then-execute primitive so this
      // adapter gets argument capture and outcome reporting for free
      // instead of re-implementing the check-and-deny step.
      execute: (args: unknown, options?: unknown) => guard.checkAndExecute(name, args, (a) => original(a, options)),
    };
  }

  return wrapped as T;
}

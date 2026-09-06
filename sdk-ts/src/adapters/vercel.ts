/**
 * Adapter for the Vercel AI SDK, whose tool shape is genuinely different
 * from LangChain's — `tools` is a `Record<name, ToolDefinition>` keyed by
 * name rather than an array of named objects, and each definition exposes
 * an `execute` function rather than `.name`. No dependency on the `ai`
 * package.
 */
import { PolicyDenied } from "../exceptions.ts";
import type { Guard } from "../guard.ts";

interface VercelToolLike {
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
    wrapped[name] = {
      ...tool,
      execute: async (args: unknown, options?: unknown) => {
        const decision = await guard.check(name);
        if (decision.result !== "allow") {
          throw new PolicyDenied(name, decision);
        }
        return original(args, options);
      },
    };
  }

  return wrapped as T;
}

/**
 * Explicit LangChain.js entry point. No import-time dependency on
 * @langchain/core — duck-types on the same `.name`/`.func`/`.call`/`.invoke`
 * shapes Guard.wrapTools already handles generically. Prefer
 * `guard.wrapTools(tools)` directly; this exists so LangChain.js users can
 * find the integration by name.
 */
import type { Guard } from "../guard.ts";

export function wrapTools(guard: Guard, tools: unknown[]): unknown[] {
  return guard.wrapTools(tools);
}

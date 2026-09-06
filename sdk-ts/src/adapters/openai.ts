/**
 * Adapter for raw OpenAI-style function/tool calling. No dependency on the
 * `openai` package — accepts either its SDK objects or plain objects parsed
 * from the API response, since both shapes are common depending on how a
 * caller consumes the API.
 */
import type { Guard } from "../guard.ts";
import { getField } from "./compat.ts";

export async function dispatch(guard: Guard, toolCall: unknown, handlers: Record<string, (args: unknown) => unknown>): Promise<unknown> {
  const fn = getField<Record<string, unknown>>(toolCall, "function");
  if (!fn) {
    throw new Error(`tool_call has no 'function' field: ${JSON.stringify(toolCall)}`);
  }

  const name = getField<string>(fn, "name");
  if (!name) {
    throw new Error(`tool_call.function has no 'name': ${JSON.stringify(toolCall)}`);
  }
  const handler = handlers[name];
  if (!handler) {
    throw new Error(`no handler registered for tool '${name}'`);
  }

  const rawArgs = getField<string | Record<string, unknown>>(fn, "arguments") ?? "{}";
  const args = typeof rawArgs === "string" ? JSON.parse(rawArgs) : rawArgs;

  return guard.checkAndExecute(name, args, handler);
}

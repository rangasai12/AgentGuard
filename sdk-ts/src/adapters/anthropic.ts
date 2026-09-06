/**
 * Adapter for Claude tool use. No dependency on the `@anthropic-ai/sdk`
 * package — accepts either its SDK `ToolUseBlock` objects or the equivalent
 * raw object content block, since both shapes are common depending on how a
 * caller consumes the API.
 */
import type { Guard } from "../guard.ts";
import { getField } from "./compat.ts";

export async function dispatch(guard: Guard, toolUseBlock: unknown, handlers: Record<string, (args: unknown) => unknown>): Promise<unknown> {
  const name = getField<string>(toolUseBlock, "name");
  if (!name) {
    throw new Error(`tool_use_block has no 'name': ${JSON.stringify(toolUseBlock)}`);
  }
  const handler = handlers[name];
  if (!handler) {
    throw new Error(`no handler registered for tool '${name}'`);
  }

  const args = getField<Record<string, unknown>>(toolUseBlock, "input") ?? {};

  return guard.checkAndExecute(name, args, handler);
}

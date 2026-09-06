import { test } from "node:test";
import assert from "node:assert/strict";

import { Guard } from "../src/guard.ts";
import { PolicyDenied } from "../src/exceptions.ts";
import { DaemonClient } from "../src/client.ts";
import { FakeDaemon, decisionHandler } from "./fakeDaemon.ts";
import * as langchainAdapter from "../src/adapters/langchain.ts";
import * as openaiAdapter from "../src/adapters/openai.ts";
import * as anthropicAdapter from "../src/adapters/anthropic.ts";
import * as vercelAdapter from "../src/adapters/vercel.ts";

async function makeGuard(decisions: Record<string, Record<string, unknown>>): Promise<{ guard: Guard; daemon: FakeDaemon }> {
  const daemon = await FakeDaemon.start(decisionHandler(decisions));
  const client = new DaemonClient(daemon.socketPath);
  const guard = await Guard.create("unused.yaml", { client });
  return { guard, daemon };
}

test("langchain adapter delegates to guard.wrapTools", async () => {
  const { guard, daemon } = await makeGuard({ search: { result: "allow" } });
  try {
    const tool = { name: "search", func: (q: string) => `results for ${q}` };
    const [wrapped] = langchainAdapter.wrapTools(guard, [tool]) as [{ func: (q: string) => Promise<string> }];
    assert.equal(await wrapped.func("cats"), "results for cats");
  } finally {
    daemon.stop();
  }
});

test("openai adapter: plain-object tool call shape, allowed", async () => {
  const { guard, daemon } = await makeGuard({ get_weather: { result: "allow" } });
  try {
    const toolCall = { id: "call_1", function: { name: "get_weather", arguments: JSON.stringify({ city: "SF" }) } };
    const result = await openaiAdapter.dispatch(guard, toolCall, {
      get_weather: (args) => `sunny in ${(args as { city: string }).city}`,
    });
    assert.equal(result, "sunny in SF");
  } finally {
    daemon.stop();
  }
});

test("openai adapter: object-shape tool call, denied", async () => {
  const { guard, daemon } = await makeGuard({ delete_account: { result: "deny", reason: "never" } });
  try {
    class FunctionCall {
      name: string;
      args: string;
      constructor(name: string, args: string) {
        this.name = name;
        this.args = args;
      }
      get arguments() {
        return this.args;
      }
    }
    const toolCall = { function: new FunctionCall("delete_account", "{}") };
    await assert.rejects(() => openaiAdapter.dispatch(guard, toolCall, { delete_account: () => "gone" }), PolicyDenied);
  } finally {
    daemon.stop();
  }
});

test("openai adapter: unregistered handler throws", async () => {
  const { guard, daemon } = await makeGuard({ anything: { result: "allow" } });
  try {
    const toolCall = { function: { name: "not_registered", arguments: "{}" } };
    await assert.rejects(() => openaiAdapter.dispatch(guard, toolCall, {}));
  } finally {
    daemon.stop();
  }
});

test("anthropic adapter: plain-object tool_use block, allowed", async () => {
  const { guard, daemon } = await makeGuard({ list_transactions: { result: "allow" } });
  try {
    const block = { type: "tool_use", name: "list_transactions", input: { limit: 5 } };
    const result = await anthropicAdapter.dispatch(guard, block, {
      list_transactions: (args) => `${(args as { limit: number }).limit} transactions`,
    });
    assert.equal(result, "5 transactions");
  } finally {
    daemon.stop();
  }
});

test("anthropic adapter: require_approval reaching the SDK is treated as not-allowed", async () => {
  const { guard, daemon } = await makeGuard({ charge_customer: { result: "require_approval" } });
  try {
    const block = { name: "charge_customer", input: { amount: 100 } };
    await assert.rejects(() => anthropicAdapter.dispatch(guard, block, { charge_customer: () => "charged" }), PolicyDenied);
  } finally {
    daemon.stop();
  }
});

test("vercel adapter: wraps execute and allows", async () => {
  const { guard, daemon } = await makeGuard({ get_weather: { result: "allow" } });
  try {
    const tools = {
      get_weather: {
        description: "gets weather",
        execute: async (args: { city: string }) => `sunny in ${args.city}`,
      },
    };
    const wrapped = vercelAdapter.wrapTools(guard, tools);
    assert.equal(await wrapped.get_weather.execute!({ city: "SF" }), "sunny in SF");
  } finally {
    daemon.stop();
  }
});

test("vercel adapter: wraps execute and denies", async () => {
  const { guard, daemon } = await makeGuard({ charge_customer: { result: "deny", reason: "nope" } });
  try {
    const tools = {
      charge_customer: { execute: async () => "charged" },
    };
    const wrapped = vercelAdapter.wrapTools(guard, tools);
    await assert.rejects(() => wrapped.charge_customer.execute!({}), PolicyDenied);
  } finally {
    daemon.stop();
  }
});

test("vercel adapter: passes through tools with no execute unchanged", async () => {
  const { guard, daemon } = await makeGuard({});
  try {
    const tools = { client_side_tool: { description: "no execute here" } };
    const wrapped = vercelAdapter.wrapTools(guard, tools);
    assert.equal(wrapped.client_side_tool, tools.client_side_tool);
  } finally {
    daemon.stop();
  }
});

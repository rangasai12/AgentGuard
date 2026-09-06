import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";

import { Guard, DaemonStartError } from "../src/guard.ts";
import { PolicyDenied } from "../src/exceptions.ts";
import { DaemonClient } from "../src/client.ts";
import { FakeDaemon, decisionHandler } from "./fakeDaemon.ts";

async function makeGuard(decisions: Record<string, Record<string, unknown>>): Promise<{ guard: Guard; daemon: FakeDaemon }> {
  const daemon = await FakeDaemon.start(decisionHandler(decisions));
  const client = new DaemonClient(daemon.socketPath);
  const guard = await Guard.create("unused.yaml", { client });
  return { guard, daemon };
}

test("check returns an allow decision", async () => {
  const { guard, daemon } = await makeGuard({ list_transactions: { result: "allow", matched_rule: "r" } });
  try {
    const decision = await guard.check("list_transactions");
    assert.equal(decision.result, "allow");
  } finally {
    daemon.stop();
  }
});

test("checkAndExecute allows", async () => {
  const { guard, daemon } = await makeGuard({ list_transactions: { result: "allow" } });
  try {
    const result = await guard.checkAndExecute("list_transactions", { x: 1 }, (args: { x: number }) => args.x * 2);
    assert.equal(result, 2);
  } finally {
    daemon.stop();
  }
});

test("checkAndExecute denies and never calls executeFn", async () => {
  const { guard, daemon } = await makeGuard({ refund_customer: { result: "deny", reason: "no refunds" } });
  try {
    let called = false;
    await assert.rejects(
      () =>
        guard.checkAndExecute("refund_customer", {}, () => {
          called = true;
        }),
      PolicyDenied,
    );
    assert.equal(called, false);
  } finally {
    daemon.stop();
  }
});

test("unlisted tool defaults to deny", async () => {
  const { guard, daemon } = await makeGuard({});
  try {
    await assert.rejects(() => guard.checkAndExecute("anything_unlisted", {}, () => "ran"), PolicyDenied);
  } finally {
    daemon.stop();
  }
});

test("tool() wraps a plain function and allows", async () => {
  const { guard, daemon } = await makeGuard({ add: { result: "allow" } });
  try {
    function add(a: number, b: number): number {
      return a + b;
    }
    const wrapped = guard.tool(add);
    assert.equal(await wrapped(2, 3), 5);
  } finally {
    daemon.stop();
  }
});

test("tool() with an explicit name denies", async () => {
  const { guard, daemon } = await makeGuard({ dangerous: { result: "deny" } });
  try {
    const wrapped = guard.tool(() => "did it", "dangerous");
    await assert.rejects(() => wrapped(), PolicyDenied);
  } finally {
    daemon.stop();
  }
});

test("wrapTools wraps a plain function", async () => {
  const { guard, daemon } = await makeGuard({ my_func: { result: "allow" } });
  try {
    function my_func(x: number): number {
      return x + 1;
    }
    const [wrapped] = guard.wrapTools([my_func]) as [(x: number) => Promise<number>];
    assert.equal(await wrapped(41), 42);
  } finally {
    daemon.stop();
  }
});

class FakeLangChainTool {
  name: string;
  func: (query: string) => string;
  description: string;

  constructor(name: string, func: (query: string) => string, description: string = "") {
    this.name = name;
    this.func = func;
    this.description = description;
  }
}

test("wrapTools handles the .name + .func shape and preserves other properties", async () => {
  const { guard, daemon } = await makeGuard({ search: { result: "allow" } });
  try {
    const calls: string[] = [];
    const tool = new FakeLangChainTool(
      "search",
      (q) => {
        calls.push(q);
        return `results for ${q}`;
      },
      "searches things",
    );
    const [wrapped] = guard.wrapTools([tool]) as [FakeLangChainTool];
    assert.equal(wrapped.description, "searches things");
    assert.equal(await (wrapped.func as unknown as (q: string) => Promise<string>)("cats"), "results for cats");
    assert.deepEqual(calls, ["cats"]);
    // The wrapped object must still be `instanceof` the original class —
    // proves the prototype chain survived the clone, not just own properties.
    assert.ok(wrapped instanceof FakeLangChainTool);
  } finally {
    daemon.stop();
  }
});

test("wrapTools .name + .func shape denies", async () => {
  const { guard, daemon } = await makeGuard({ delete_everything: { result: "deny", reason: "no" } });
  try {
    const tool = new FakeLangChainTool("delete_everything", () => "boom");
    const [wrapped] = guard.wrapTools([tool]) as [FakeLangChainTool];
    await assert.rejects(() => (wrapped.func as unknown as () => Promise<string>)(), PolicyDenied);
  } finally {
    daemon.stop();
  }
});

test("wrapTools handles the .name + .invoke shape", async () => {
  const { guard, daemon } = await makeGuard({ lookup: { result: "allow" } });
  try {
    const tool = { name: "lookup", invoke: (q: string) => `found ${q}` };
    const [wrapped] = guard.wrapTools([tool]) as [{ invoke: (q: string) => Promise<string> }];
    assert.equal(await wrapped.invoke("thing"), "found thing");
  } finally {
    daemon.stop();
  }
});

test("wrapTools rejects an unsupported shape with TypeError", async () => {
  const { guard, daemon } = await makeGuard({});
  try {
    assert.throws(() => guard.wrapTools([{ notAToolShape: true }]), TypeError);
  } finally {
    daemon.stop();
  }
});

test("Guard.create skips spawning agentctl when the daemon is already reachable", async () => {
  const daemon = await FakeDaemon.start(decisionHandler({}));
  try {
    // agentctlPath is a nonexistent binary; if Guard tried to spawn it and
    // that mattered, this would throw. It must not even try, because
    // ping() already succeeds against the fake daemon's real socket path.
    const guard = await Guard.create("unused.yaml", {
      socketPath: daemon.socketPath,
      autoStart: true,
      agentctlPath: "definitely-not-a-real-binary-xyz",
    });
    const decision = await guard.check("anything");
    assert.equal(decision.result, "deny");
  } finally {
    daemon.stop();
  }
});

test("Guard.create throws DaemonStartError when agentctl is missing and nothing is listening", async () => {
  await assert.rejects(
    () =>
      Guard.create("unused.yaml", {
        socketPath: path.join(os.tmpdir(), `ag-nothing-${crypto.randomBytes(4).toString("hex")}.sock`),
        autoStart: true,
        agentctlPath: "definitely-not-a-real-binary-xyz",
        startTimeoutMs: 300,
      }),
    DaemonStartError,
  );
});

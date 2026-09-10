import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import { createHash } from "node:crypto";

import * as fs from "node:fs";
import { Guard, DaemonStartError, gitHeadVersion } from "../src/guard.ts";
import { PolicyDenied } from "../src/exceptions.ts";
import { DaemonClient } from "../src/client.ts";
import { FakeDaemon, decisionHandler } from "./fakeDaemon.ts";

async function makeGuard(decisions: Record<string, Record<string, unknown>>): Promise<{ guard: Guard; daemon: FakeDaemon }> {
  const daemon = await FakeDaemon.start(decisionHandler(decisions));
  const client = new DaemonClient(daemon.socketPath);
  // Tests run inside this repository, so automatic git versioning would
  // otherwise tag every request with the checkout's commit; the tests for
  // that feature opt back in with an explicit working directory.
  const guard = await Guard.create("unused.yaml", { client, autoVersion: false });
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

// ---------------------------------------------------------------------------
// Outcome reporting and run/version identity (mirrors the Python tests)
// ---------------------------------------------------------------------------

async function makeRecordingGuard(
  decisions: Record<string, Record<string, unknown>>,
  opts: { rejectReports?: boolean; captureOutput?: boolean; maxOutputBytes?: number; agentVersion?: string; autoVersion?: boolean } = {},
) {
  const handler = decisionHandler(decisions, opts.rejectReports ?? false);
  const daemon = await FakeDaemon.start(handler);
  const client = new DaemonClient(daemon.socketPath);
  const guard = await Guard.create("unused.yaml", {
    client,
    captureOutput: opts.captureOutput,
    maxOutputBytes: opts.maxOutputBytes,
    agentVersion: opts.agentVersion,
    autoVersion: opts.autoVersion ?? false,
  });
  return { guard, daemon, handler };
}

test("checkAndExecute reports success with timing, output preview, size and hash", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ lookup: { result: "allow" } });
  try {
    const result = await guard.checkAndExecute("lookup", { id: 7 }, (args: { id: number }) => ({ found: true, id: args.id }));
    assert.deepEqual(result, { found: true, id: 7 });
    assert.equal(handler.evaluates.length, 1);
    assert.deepEqual((handler.evaluates[0].action as Record<string, unknown>).args, { id: 7 });
    assert.equal(handler.reports.length, 1);
    assert.equal(handler.reports[0].id, "0000000000000001");
    const outcome = handler.reports[0].outcome as Record<string, unknown>;
    assert.equal(outcome.status, "success");
    assert.ok(typeof outcome.exec_ms === "number" && outcome.exec_ms >= 0);
    assert.equal(outcome.output, '{"found":true,"id":7}');
    assert.equal(outcome.output_bytes, Buffer.byteLength('{"found":true,"id":7}'));
    assert.equal((outcome.output_sha256 as string).length, 64);
  } finally {
    daemon.stop();
  }
});

test("a throwing tool reports an error outcome and rethrows", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ boom: { result: "allow" } });
  try {
    await assert.rejects(
      () =>
        guard.checkAndExecute("boom", {}, () => {
          throw new RangeError("kaboom");
        }),
      RangeError,
    );
    const outcome = handler.reports[0].outcome as Record<string, unknown>;
    assert.equal(outcome.status, "error");
    assert.equal(outcome.error, "RangeError: kaboom");
    assert.equal(outcome.output, undefined);
  } finally {
    daemon.stop();
  }
});

test("output is truncated on a UTF-8 boundary and hashed in full", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ big: { result: "allow" } }, { maxOutputBytes: 10 });
  try {
    const big = "é".repeat(100); // 200 bytes
    await guard.checkAndExecute("big", {}, () => big);
    const outcome = handler.reports[0].outcome as Record<string, unknown>;
    assert.equal(outcome.output_bytes, 200);
    assert.equal(outcome.output, "é".repeat(5));
    assert.equal(outcome.output_sha256, createHash("sha256").update(big, "utf8").digest("hex"));
  } finally {
    daemon.stop();
  }
});

test("captureOutput=false still reports status and timing", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ quiet: { result: "allow" } }, { captureOutput: false });
  try {
    await guard.checkAndExecute("quiet", {}, () => "secret result");
    const outcome = handler.reports[0].outcome as Record<string, unknown>;
    assert.equal(outcome.status, "success");
    assert.ok("exec_ms" in outcome);
    assert.equal(outcome.output, undefined);
    assert.equal(outcome.output_sha256, undefined);
  } finally {
    daemon.stop();
  }
});

test("a rejected report never affects the tool call", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ ok: { result: "allow" } }, { rejectReports: true });
  try {
    assert.equal(await guard.checkAndExecute("ok", {}, () => 42), 42);
    assert.equal(handler.reports.length, 1);
  } finally {
    daemon.stop();
  }
});

test("a denied call sends no report", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ nope: { result: "deny" } });
  try {
    await assert.rejects(() => guard.checkAndExecute("nope", {}, () => "never"), PolicyDenied);
    assert.equal(handler.reports.length, 0);
  } finally {
    daemon.stop();
  }
});

test("an async tool is reported after it resolves", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ fetch: { result: "allow" } });
  try {
    const fetch = guard.tool(async (url: unknown) => {
      await new Promise((r) => setTimeout(r, 5));
      return `body of ${url}`;
    }, "fetch");
    assert.equal(await fetch("http://x"), "body of http://x");
    const outcome = handler.reports[0].outcome as Record<string, unknown>;
    assert.equal(outcome.output, "body of http://x");
    assert.ok((outcome.exec_ms as number) >= 4, `expected the await to be timed, got ${outcome.exec_ms}ms`);
    assert.deepEqual((handler.evaluates[0].action as Record<string, unknown>).args, { args: ["http://x"] });
  } finally {
    daemon.stop();
  }
});

test("run id and agent version are sent on every evaluate and exported to the environment", async () => {
  const savedRun = process.env.AGENTGUARD_RUN_ID;
  const savedVer = process.env.AGENTGUARD_AGENT_VERSION;
  delete process.env.AGENTGUARD_RUN_ID;
  delete process.env.AGENTGUARD_AGENT_VERSION;
  const { guard, daemon, handler } = await makeRecordingGuard({ t: { result: "allow" } }, { agentVersion: "2.3.4" });
  try {
    await guard.check("t");
    assert.equal(handler.evaluates[0].agent_version, "2.3.4");
    assert.equal(handler.evaluates[0].run_id, guard.runId);
    assert.equal(guard.runId.length, 16);
    assert.equal(process.env.AGENTGUARD_RUN_ID, guard.runId);
    assert.equal(process.env.AGENTGUARD_AGENT_VERSION, "2.3.4");
  } finally {
    daemon.stop();
    if (savedRun === undefined) delete process.env.AGENTGUARD_RUN_ID;
    else process.env.AGENTGUARD_RUN_ID = savedRun;
    if (savedVer === undefined) delete process.env.AGENTGUARD_AGENT_VERSION;
    else process.env.AGENTGUARD_AGENT_VERSION = savedVer;
  }
});

test("run id is inherited from the environment", async () => {
  const saved = process.env.AGENTGUARD_RUN_ID;
  process.env.AGENTGUARD_RUN_ID = "run-from-parent";
  const { guard, daemon } = await makeRecordingGuard({ t: { result: "allow" } });
  try {
    assert.equal(guard.runId, "run-from-parent");
  } finally {
    daemon.stop();
    if (saved === undefined) delete process.env.AGENTGUARD_RUN_ID;
    else process.env.AGENTGUARD_RUN_ID = saved;
  }
});

test("long string arguments are capped before evaluate", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ write: { result: "allow" } });
  try {
    const content = "x".repeat(50 * 1024);
    await guard.checkAndExecute("write", { path: "/tmp/x", content }, (a: { content: string }) => a.content.length);
    const sent = (handler.evaluates[0].action as Record<string, unknown>).args as Record<string, string>;
    assert.equal(sent.path, "/tmp/x");
    assert.ok(sent.content.length < 17 * 1024 && sent.content.endsWith("chars]"));
  } finally {
    daemon.stop();
  }
});

// ---------------------------------------------------------------------------
// Tool descriptions and automatic agent versions (mirrors the Python tests)
// ---------------------------------------------------------------------------

test("a tool description is sent on the first call only", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ lookup: { result: "allow" } });
  try {
    const lookup = guard.tool((id: unknown) => id, "lookup", "Look up one CRM customer by id.\n\nLonger text that must not be sent.");
    await lookup("c1");
    await lookup("c2");
    const actions = handler.evaluates.map((e) => e.action as Record<string, unknown>);
    assert.equal(actions[0].description, "Look up one CRM customer by id.");
    assert.equal(actions[1].description, undefined);
  } finally {
    daemon.stop();
  }
});

test("wrapTools reads .description off duck-typed tools and caps its length", async () => {
  const { guard, daemon, handler } = await makeRecordingGuard({ search: { result: "allow" }, big: { result: "allow" } });
  try {
    const [search, big] = guard.wrapTools([
      { name: "search", description: "Full-text search.", func: (q: unknown) => q },
      { name: "big", description: "x".repeat(5000), func: () => 1 },
    ]) as { func: (...a: unknown[]) => unknown }[];
    await search.func("q");
    await big.func();
    const actions = handler.evaluates.map((e) => e.action as Record<string, unknown>);
    assert.equal(actions[0].description, "Full-text search.");
    assert.equal((actions[1].description as string).length, 512);
  } finally {
    daemon.stop();
  }
});

function makeFakeRepo(): string {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ag-repo-"));
  fs.mkdirSync(path.join(repo, ".git", "refs", "heads"), { recursive: true });
  fs.writeFileSync(path.join(repo, ".git", "HEAD"), "ref: refs/heads/main\n");
  fs.writeFileSync(path.join(repo, ".git", "refs", "heads", "main"), "0123456789abcdef0123456789abcdef01234567\n");
  fs.mkdirSync(path.join(repo, "src"));
  return repo;
}

test("gitHeadVersion reads loose and packed refs and walks up from a subdirectory", () => {
  const repo = makeFakeRepo();
  assert.equal(gitHeadVersion(path.join(repo, "src")), "git:0123456789ab");
  fs.unlinkSync(path.join(repo, ".git", "refs", "heads", "main"));
  fs.writeFileSync(path.join(repo, ".git", "packed-refs"), "# pack-refs\nfedcba9876543210fedcba9876543210fedcba98 refs/heads/main\n");
  assert.equal(gitHeadVersion(repo), "git:fedcba987654");
});

test("the agent version is derived from git when not given, and an explicit one wins", async () => {
  const repo = makeFakeRepo();
  const cwd = process.cwd();
  const savedEnv = process.env.AGENTGUARD_AGENT_VERSION;
  delete process.env.AGENTGUARD_AGENT_VERSION;
  process.chdir(path.join(repo, "src"));
  try {
    const { guard, daemon, handler } = await makeRecordingGuard({ t: { result: "allow" } }, { autoVersion: true });
    try {
      assert.equal(guard.agentVersion, "git:0123456789ab");
      assert.equal(process.env.AGENTGUARD_AGENT_VERSION, "git:0123456789ab");
      await guard.check("t");
      assert.equal(handler.evaluates[0].agent_version, "git:0123456789ab");
    } finally {
      daemon.stop();
    }
    delete process.env.AGENTGUARD_AGENT_VERSION;
    const explicit = await makeRecordingGuard({ t: { result: "allow" } }, { autoVersion: true, agentVersion: "2.0" });
    try {
      assert.equal(explicit.guard.agentVersion, "2.0");
    } finally {
      explicit.daemon.stop();
    }
  } finally {
    process.chdir(cwd);
    if (savedEnv === undefined) delete process.env.AGENTGUARD_AGENT_VERSION;
    else process.env.AGENTGUARD_AGENT_VERSION = savedEnv;
  }
});

test("without git the version is a fingerprint of the wrapped tool set, frozen at the first decision", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ag-nogit-"));
  if (gitHeadVersion(dir) !== undefined) return; // a repository sits above the temp dir; nothing to test here
  const cwd = process.cwd();
  const savedEnv = process.env.AGENTGUARD_AGENT_VERSION;
  delete process.env.AGENTGUARD_AGENT_VERSION;
  process.chdir(dir);
  try {
    const make = async (names: string[]) => {
      delete process.env.AGENTGUARD_AGENT_VERSION;
      const r = await makeRecordingGuard({ a: { result: "allow" } }, { autoVersion: true });
      for (const n of names) r.guard.tool((x: unknown) => x, n);
      assert.equal(r.guard.agentVersion, undefined);
      await r.guard.check("a");
      r.daemon.stop();
      return { version: r.guard.agentVersion, sent: r.handler.evaluates[0].agent_version };
    };
    const first = await make(["a", "b"]);
    assert.ok(first.version?.startsWith("tools:") && first.version.length === "tools:".length + 12, String(first.version));
    assert.equal(first.sent, first.version);
    assert.equal((await make(["b", "a"])).version, first.version);
    assert.notEqual((await make(["a"])).version, first.version);
  } finally {
    process.chdir(cwd);
    if (savedEnv === undefined) delete process.env.AGENTGUARD_AGENT_VERSION;
    else process.env.AGENTGUARD_AGENT_VERSION = savedEnv;
  }
});

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";

import { DaemonClient, DaemonUnavailable } from "../src/client.ts";
import { FakeDaemon, decisionHandler } from "./fakeDaemon.ts";

function nowhereSocket(): string {
  return path.join(os.tmpdir(), `ag-nowhere-${crypto.randomBytes(4).toString("hex")}.sock`);
}

test("ping succeeds against a live fake daemon", async () => {
  const daemon = await FakeDaemon.start(decisionHandler({}));
  try {
    const client = new DaemonClient(daemon.socketPath);
    assert.equal(await client.ping(), true);
  } finally {
    daemon.stop();
  }
});

test("ping fails when nothing is listening", async () => {
  const client = new DaemonClient(nowhereSocket());
  assert.equal(await client.ping(), false);
});

test("call evaluate returns a decision", async () => {
  const daemon = await FakeDaemon.start(decisionHandler({ charge_customer: { result: "allow", matched_rule: "r1" } }));
  try {
    const client = new DaemonClient(daemon.socketPath);
    const resp = await client.call("evaluate", { actor: "a", action: { type: "mcp_tool", server: "s", tool: "charge_customer" } });
    assert.equal(resp.ok, true);
    assert.equal(resp.decision?.result, "allow");
  } finally {
    daemon.stop();
  }
});

test("call rejects with DaemonUnavailable when nothing is listening", async () => {
  const client = new DaemonClient(nowhereSocket());
  await assert.rejects(() => client.call("ping"), DaemonUnavailable);
});

test("call surfaces an {ok: false} response as a plain object, not a throw", async () => {
  const daemon = await FakeDaemon.start(decisionHandler({}));
  try {
    const client = new DaemonClient(daemon.socketPath);
    const resp = await client.call("not_a_real_cmd");
    assert.equal(resp.ok, false);
    assert.ok(resp.error);
  } finally {
    daemon.stop();
  }
});

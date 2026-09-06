/**
 * A from-scratch fake daemon implementing the same line-delimited JSON
 * protocol as the real Go daemon (see daemon/socket_api.go), so the
 * TypeScript SDK can be tested fully without building or running the Go
 * binary. Mirrors sdk-python/tests/conftest.py.
 */
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";

export type Handler = (req: Record<string, unknown>) => Record<string, unknown>;

export class FakeDaemon {
  public readonly socketPath: string;
  private readonly handler: Handler;
  private readonly server: net.Server;

  private constructor(handler: Handler) {
    this.handler = handler;
    this.socketPath = path.join(os.tmpdir(), `ag-fake-ts-${crypto.randomBytes(4).toString("hex")}.sock`);
    this.server = net.createServer((conn) => this.handleConn(conn));
  }

  /** `net.Server.listen()` is asynchronous — the socket file may not exist
   * yet immediately after construction — so this is the only way to obtain
   * a FakeDaemon, guaranteeing callers can never forget to wait for it. */
  static async start(handler: Handler): Promise<FakeDaemon> {
    const daemon = new FakeDaemon(handler);
    await new Promise<void>((resolve) => daemon.server.listen(daemon.socketPath, resolve));
    return daemon;
  }

  private handleConn(conn: net.Socket): void {
    let buffer = "";
    conn.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      let idx: number;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        const req = JSON.parse(line);
        const resp = this.handler(req);
        conn.write(JSON.stringify(resp) + "\n");
      }
    });
  }

  stop(): void {
    this.server.close();
    try {
      fs.unlinkSync(this.socketPath);
    } catch {
      /* already gone */
    }
  }
}

/** Builds a handler that answers `evaluate` requests by looking up the
 * action's tool name in `decisions` (defaulting to deny for anything
 * unlisted, matching the real engine's default-deny posture), and answers
 * `ping` unconditionally. */
export function decisionHandler(decisions: Record<string, Record<string, unknown>>): Handler {
  return (req) => {
    if (req.cmd === "ping") {
      return { ok: true };
    }
    if (req.cmd === "evaluate") {
      const action = (req.action as Record<string, unknown>) ?? {};
      const tool = action.tool as string;
      const decision = decisions[tool] ?? { result: "deny", matched_rule: "default-deny" };
      return { ok: true, decision };
    }
    return { ok: false, error: `fake daemon: unhandled cmd ${JSON.stringify(req.cmd)}` };
  };
}

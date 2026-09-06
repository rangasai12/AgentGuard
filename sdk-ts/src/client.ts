/**
 * Low-level client for the AgentGuard daemon's line-delimited JSON protocol
 * over a Unix domain socket (see ../../daemon/socket_api.go for the Go side
 * of this protocol — this is a from-scratch reimplementation of the same
 * wire format, not a binding). Deliberately zero runtime dependencies.
 */
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

/** Mirrors cli.DefaultSocketPath on the Go side and client.py's
 * default_socket_path: AGENTGUARD_SOCKET env var, else
 * ~/.agentguard/agentguard.sock, else a temp-dir fallback. */
export function defaultSocketPath(): string {
  const env = process.env.AGENTGUARD_SOCKET;
  if (env) return env;
  const home = os.homedir();
  if (home) return path.join(home, ".agentguard", "agentguard.sock");
  return path.join(os.tmpdir(), "agentguard.sock");
}

/** Raised when the daemon cannot be reached at all (not running, wrong
 * socket path, etc.) — distinct from a {"ok": false} response so callers can
 * tell "the daemon is down" apart from "the daemon rejected this request". */
export class DaemonUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DaemonUnavailable";
  }
}

export interface Decision {
  result: "allow" | "deny" | "require_approval";
  matched_rule: string;
  reason?: string;
}

export interface DaemonResponse {
  ok: boolean;
  error?: string;
  decision?: Decision;
  approval_id?: string;
  latency_ms?: number;
  events?: unknown[];
  pending?: unknown[];
}

/**
 * A connect-per-call client: each call opens a fresh Unix socket connection,
 * sends one JSON line, and reads one JSON line back. This trades a little
 * latency for much simpler error handling than a long-lived connection — no
 * state to recover if the daemon restarts between calls. Mirrors
 * sdk-python/agentguard/client.py exactly.
 */
export class DaemonClient {
  private readonly socketPath: string;
  private readonly timeoutMs: number;

  // Node's strip-only TypeScript execution doesn't support constructor
  // parameter properties (`constructor(private x: T)`) since assigning them
  // requires real code generation, not just type erasure — so fields are
  // declared and assigned explicitly throughout this SDK.
  constructor(socketPath: string = defaultSocketPath(), timeoutMs: number = 30_000) {
    this.socketPath = socketPath;
    this.timeoutMs = timeoutMs;
  }

  call(cmd: string, fields: Record<string, unknown> = {}): Promise<DaemonResponse> {
    const payload = JSON.stringify({ cmd, ...fields }) + "\n";

    return new Promise<DaemonResponse>((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = "";
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(new DaemonUnavailable(`timed out waiting for the agentguard daemon at ${this.socketPath}`));
      }, this.timeoutMs);

      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        fn();
      };

      socket.on("connect", () => socket.write(payload));

      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const idx = buffer.indexOf("\n");
        if (idx === -1) return;
        const line = buffer.slice(0, idx);
        socket.end();
        finish(() => {
          try {
            resolve(JSON.parse(line) as DaemonResponse);
          } catch {
            reject(new DaemonUnavailable(`daemon sent an unparseable response: ${line}`));
          }
        });
      });

      socket.on("error", (err) => {
        finish(() => reject(new DaemonUnavailable(`could not reach the agentguard daemon at ${this.socketPath}: ${err.message}`)));
      });

      socket.on("close", () => {
        finish(() => reject(new DaemonUnavailable("daemon closed the connection without responding")));
      });
    });
  }

  async ping(): Promise<boolean> {
    try {
      const resp = await this.call("ping");
      return !!resp.ok;
    } catch {
      return false;
    }
  }
}

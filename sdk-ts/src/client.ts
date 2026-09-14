/**
 * Low-level client for the AgentGuard daemon's line-delimited JSON protocol
 * over a Unix domain socket (see ../../daemon/socket_api.go for the Go side
 * of this protocol — this is a from-scratch reimplementation of the same
 * wire format, not a binding). Deliberately zero runtime dependencies.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

/**
 * Mirrors cli.DefaultSocketPath on the Go side and client.py's
 * default_socket_path: AGENTGUARD_SOCKET env var, else a path under
 * ~/.agentguard (or a temp-dir fallback), scoped by policyPath so two
 * Guards pointed at two different policy files land on two different
 * sockets with nothing to configure.
 *
 * policyPath is optional (default undefined, matching pre-scoping
 * behavior) only for backward compatibility with any existing direct
 * caller of this exported helper; Guard always passes its own policyPath.
 *
 * Must stay byte-for-byte in sync with policyScope in cli/paths.go and
 * _policy_scope in sdk-python/agentguard/client.py — see that Go
 * function's docstring for why (a plain `agentctl daemon start --policy
 * foo.yaml` and a plain `Guard(policy="foo.yaml")` must land on the same
 * socket with neither one told the other's path).
 */
export function defaultSocketPath(policyPath?: string): string {
  const env = process.env.AGENTGUARD_SOCKET;
  if (env) return env;
  return defaultPath(policyPath, "agentguard.sock");
}

/**
 * Mirrors cli.DefaultAuditLogPath on the Go side. See defaultSocketPath —
 * the two are scoped identically. Guard itself never needs this (it only
 * ever dials a socket; a daemon it spawns computes its own audit-log
 * default from the --policy flag it's given), but it's exported for parity
 * with the Go side's public surface.
 */
export function defaultAuditLogPath(policyPath?: string): string {
  const env = process.env.AGENTGUARD_AUDIT_LOG;
  if (env) return env;
  return defaultPath(policyPath, "audit.log");
}

function defaultPath(policyPath: string | undefined, name: string): string {
  const home = os.homedir();
  const base = home || os.tmpdir();
  if (!policyPath) {
    return home ? path.join(base, ".agentguard", name) : path.join(base, name);
  }
  const scope = policyScope(policyPath);
  return home ? path.join(base, ".agentguard", "daemons", scope, name) : path.join(base, "daemons", scope, name);
}

/** First 12 hex chars of sha256(absolute policy path) — see policyScope
 * in cli/paths.go for why this must match exactly. */
function policyScope(policyPath: string): string {
  return createHash("sha256").update(path.resolve(policyPath)).digest("hex").slice(0, 12);
}

/**
 * First 12 hex chars of sha256(the policy file's raw bytes) — mirrors
 * engine.Policy.Hash on the Go side exactly (no YAML parsing/
 * normalization: whitespace and comments change this hash). undefined if
 * the file cannot be read, so a caller can skip a comparison it has no
 * data for rather than guessing.
 */
export function policyContentHash(policyPath: string): string | undefined {
  try {
    return createHash("sha256").update(fs.readFileSync(policyPath)).digest("hex").slice(0, 12);
  } catch {
    return undefined;
  }
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
  event_id?: string;
  events?: unknown[];
  pending?: unknown[];
  /** Set on a "ping" response — see Response.PolicyHash/PolicyPath in
   * daemon/socket_api.go and Guard.ensureDaemon's stale-policy check. */
  policy_hash?: string;
  policy_path?: string;
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

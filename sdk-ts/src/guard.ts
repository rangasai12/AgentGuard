/**
 * Guard: the main entry point developers import. Wraps an agent's tools so
 * every call is checked against policy — evaluated by the Go daemon, not
 * this module — before it runs. Mirrors sdk-python/agentguard/guard.py;
 * see that file's docstring for the shared design rationale (notably why
 * SDK-wrapped tool calls reuse the `mcp` policy section).
 */
import { spawn } from "node:child_process";
import { DaemonClient, defaultSocketPath, type Decision } from "./client.ts";
import { PolicyDenied } from "./exceptions.ts";

export class DaemonStartError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DaemonStartError";
  }
}

export interface GuardOptions {
  socketPath?: string;
  actor?: string;
  /** Groups the tools this Guard wraps under one name in the policy's
   * `mcp.servers` section (reused for any named tool call, not only real
   * MCP servers — see policy-spec/schema.yaml). */
  namespace?: string;
  agentctlPath?: string;
  autoStart?: boolean;
  startTimeoutMs?: number;
  /** Inject a client directly (tests). Bypasses auto-start entirely. */
  client?: DaemonClient;
}

/** Anything with a `.name` and a callable in one of these slots — the shapes
 * LangChain.js's DynamicTool (`.func`), StructuredTool/legacy Tool
 * (`.call`), and modern Runnable-based tools (`.invoke`) expose. */
interface DuckTypedTool {
  name: string;
  func?: (...args: unknown[]) => unknown;
  call?: (...args: unknown[]) => unknown;
  invoke?: (...args: unknown[]) => unknown;
  [key: string]: unknown;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class Guard {
  public readonly policyPath: string;
  public readonly actor: string;
  public readonly namespace: string;
  public readonly socketPath: string;
  private readonly client: DaemonClient;

  constructor(policyPath: string, opts: GuardOptions = {}) {
    this.policyPath = policyPath;
    this.actor = opts.actor ?? "typescript-sdk";
    this.namespace = opts.namespace ?? "local-tools";
    this.socketPath = opts.socketPath ?? defaultSocketPath();
    this.client = opts.client ?? new DaemonClient(this.socketPath);
  }

  /**
   * Construct a Guard and, unless a client was injected or autoStart is
   * false, ensure a daemon is reachable — starting one via `agentctl daemon
   * start` if nothing answers a ping. A static async factory rather than
   * async work in the constructor, since JS constructors can't be async.
   */
  static async create(policyPath: string, opts: GuardOptions = {}): Promise<Guard> {
    const guard = new Guard(policyPath, opts);
    if (!opts.client && (opts.autoStart ?? true)) {
      await guard.ensureDaemon(opts.agentctlPath ?? "agentctl", opts.startTimeoutMs ?? 5000);
    }
    return guard;
  }

  private async ensureDaemon(agentctlPath: string, timeoutMs: number): Promise<void> {
    if (await this.client.ping()) return;

    // Unlike Python's subprocess.Popen (which raises synchronously on
    // ENOENT), Node's spawn() returns immediately and only reports a
    // missing binary via an async "error" event — a try/catch around the
    // spawn() call itself never fires for that case. Racing the error
    // event against the ping loop lets a missing binary fail fast with a
    // clear message instead of silently waiting out the full timeout.
    const spawnFailed = new Promise<never>((_, reject) => {
      const child = spawn(agentctlPath, ["daemon", "start", "--policy", this.policyPath, "--socket", this.socketPath], {
        detached: true,
        stdio: "ignore",
      });
      child.once("error", (err) => {
        reject(
          new DaemonStartError(
            `no agentguard daemon is running at '${this.socketPath}' and spawning '${agentctlPath}' failed: ${err.message}. ` +
              `Install agentctl, or start the daemon yourself: \`agentctl daemon start --policy ${this.policyPath}\`.`,
          ),
        );
      });
      child.unref();
    });

    const pingUntilUp = (async () => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (await this.client.ping()) return;
        await sleep(50);
      }
      throw new DaemonStartError(`agentguard daemon did not come up within ${timeoutMs}ms at '${this.socketPath}'`);
    })();

    await Promise.race([spawnFailed, pingUntilUp]);
  }

  /** Evaluate one tool call against policy and return the raw decision.
   * Prefer checkAndExecute unless you need to inspect the decision itself. */
  async check(toolName: string): Promise<Decision> {
    const resp = await this.client.call("evaluate", {
      actor: this.actor,
      action: { type: "mcp_tool", actor: this.actor, server: this.namespace, tool: toolName },
    });
    if (!resp.ok) {
      throw new Error(`agentguard daemon error: ${resp.error}`);
    }
    return resp.decision as Decision;
  }

  /** Check toolName against policy, then call executeFn(args) if allowed.
   * Throws PolicyDenied otherwise. The primitive every higher-level wrapper
   * (wrapTools, the tool() decorator-equivalent, the adapters) builds on. */
  async checkAndExecute<Args, Result>(toolName: string, args: Args, executeFn: (args: Args) => Result | Promise<Result>): Promise<Result> {
    const decision = await this.check(toolName);
    if (decision.result !== "allow") {
      throw new PolicyDenied(toolName, decision);
    }
    return await executeFn(args);
  }

  /** Wraps a plain async/sync function so every call is policy-checked
   * first, under `name` (defaulting to the function's own `.name`). */
  tool<F extends (...args: unknown[]) => unknown>(fn: F, name?: string): F {
    const toolName = name ?? fn.name;
    if (!toolName) {
      throw new TypeError("agentguard.tool: function has no name; pass one explicitly");
    }
    const wrapped = async (...args: Parameters<F>): Promise<ReturnType<F>> => {
      const decision = await this.check(toolName);
      if (decision.result !== "allow") {
        throw new PolicyDenied(toolName, decision);
      }
      return (await fn(...args)) as ReturnType<F>;
    };
    return wrapped as unknown as F;
  }

  /**
   * Wrap a list of tool objects so each call is policy-checked first.
   *
   * Supports, by duck typing (no hard dependency on any agent framework):
   *   - a plain function
   *   - an object with `.name` and `.func` — LangChain.js's DynamicTool shape
   *   - an object with `.name` and `.call` — LangChain.js's legacy Tool shape
   *   - an object with `.name` and `.invoke` — modern Runnable-based tools
   *
   * Anything else throws TypeError with the supported shapes listed, so an
   * unsupported tool type fails loudly at wrap time rather than silently
   * skipping enforcement.
   */
  wrapTools(tools: unknown[]): unknown[] {
    return tools.map((t) => this.wrapOne(t));
  }

  private wrapOne(tool: unknown): unknown {
    if (typeof tool === "function") {
      return this.tool(tool as (...args: unknown[]) => unknown, (tool as { name?: string }).name);
    }
    if (tool && typeof tool === "object") {
      const t = tool as DuckTypedTool;
      for (const key of ["func", "call", "invoke"] as const) {
        if (typeof t.name === "string" && typeof t[key] === "function") {
          return this.wrapAttr(t, key);
        }
      }
    }
    throw new TypeError(
      `agentguard.wrapTools: don't know how to wrap ${JSON.stringify(tool)}. Supported shapes: a plain ` +
        "function, or an object with `.name` + one of `.func`/`.call`/`.invoke`. See agentguard/adapters for framework-specific helpers.",
    );
  }

  /** Returns a shallow copy of tool with callAttr replaced by a
   * policy-checked wrapper, preserving every other property *and* the
   * original prototype chain — a plain `{...tool}` spread only copies own
   * enumerable properties, which would silently drop any prototype methods
   * a real framework's tool class defines (e.g. an actual LangChain.js
   * `DynamicTool` instance), breaking exactly the class-instance case this
   * duck-typed wrapping exists to support. */
  private wrapAttr(tool: DuckTypedTool, callAttr: "func" | "call" | "invoke"): DuckTypedTool {
    const toolName = tool.name;
    const original = tool[callAttr] as (...args: unknown[]) => unknown;
    const wrapped = async (...args: unknown[]) => {
      const decision = await this.check(toolName);
      if (decision.result !== "allow") {
        throw new PolicyDenied(toolName, decision);
      }
      return original.apply(tool, args);
    };
    const clone = Object.assign(Object.create(Object.getPrototypeOf(tool)), tool);
    clone[callAttr] = wrapped;
    return clone;
  }
}

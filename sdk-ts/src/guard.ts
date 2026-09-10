/**
 * Guard: the main entry point developers import. Wraps an agent's tools so
 * every call is checked against policy — evaluated by the Go daemon, not
 * this module — before it runs, and reports what the tool returned (and
 * how long it took) afterwards so the audit trail records outcomes, not
 * just decisions. Mirrors sdk-python/agentguard/guard.py; see that file's
 * docstring for the shared design rationale (notably why SDK-wrapped tool
 * calls reuse the `mcp` policy section).
 */
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { DaemonClient, defaultSocketPath, type Decision } from "./client.ts";
import { PolicyDenied } from "./exceptions.ts";

/** Longest string argument value forwarded to the daemon, per argument —
 * see MAX_ARG_BYTES in the Python SDK for why. */
const MAX_ARG_BYTES = 16 * 1024;
const MAX_ERROR_BYTES = 4 * 1024;
/** Longest tool description attached to a tool's first evaluate (the
 * daemon caps at the same size). */
const MAX_DESCRIPTION_BYTES = 512;

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
  /** The build of the agent, recorded on every decision. Defaults to
   * $AGENTGUARD_AGENT_VERSION, else (unless autoVersion is false) a
   * derived value: `git:<commit>` from the nearest .git above the working
   * directory, else `tools:<hash>` over the names and arities of the tools
   * this Guard wrapped, frozen at the first decision. A derived version is
   * exported to the environment too. A prompt-only change does not change
   * the tools fingerprint; set the version explicitly if that matters. */
  agentVersion?: string;
  /** Derive agentVersion when none is given (default true). */
  autoVersion?: boolean;
  /** One execution of the agent. Defaults to $AGENTGUARD_RUN_ID, else a
   * fresh id; exported to the environment either way so child processes
   * (an MCP server behind `agentctl mcp-proxy`) inherit it. */
  runId?: string;
  /** Report a preview of each tool's return value (default true;
   * AGENTGUARD_CAPTURE_OUTPUT=0 disables). Status and timing are always
   * reported. */
  captureOutput?: boolean;
  /** Size of that preview in bytes (default 4096). */
  maxOutputBytes?: number;
}

/** Anything with a `.name` and a callable in one of these slots — the shapes
 * LangChain.js's DynamicTool (`.func`), StructuredTool/legacy Tool
 * (`.call`), and modern Runnable-based tools (`.invoke`) expose. */
interface DuckTypedTool {
  name: string;
  description?: unknown;
  func?: (...args: unknown[]) => unknown;
  call?: (...args: unknown[]) => unknown;
  invoke?: (...args: unknown[]) => unknown;
  [key: string]: unknown;
}

type Action = Record<string, unknown>;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class Guard {
  public readonly policyPath: string;
  public readonly actor: string;
  public readonly namespace: string;
  public readonly socketPath: string;
  public readonly runId: string;
  /** Mutable only until the first decision, when a pending tools:<hash>
   * version is frozen — see GuardOptions.agentVersion. */
  public agentVersion: string | undefined;
  public readonly captureOutput: boolean;
  public readonly maxOutputBytes: number;
  private readonly client: DaemonClient;

  // Tool metadata gathered at wrap time: descriptions (sent once per tool)
  // and signatures (for the tools:<hash> version fallback).
  private readonly descriptions = new Map<string, string>();
  private readonly described = new Set<string>();
  private readonly toolSignatures: string[] = [];
  private versionPending: boolean;

  constructor(policyPath: string, opts: GuardOptions = {}) {
    this.policyPath = policyPath;
    this.actor = opts.actor ?? "typescript-sdk";
    this.namespace = opts.namespace ?? "local-tools";
    this.socketPath = opts.socketPath ?? defaultSocketPath();
    this.client = opts.client ?? new DaemonClient(this.socketPath);

    this.agentVersion = opts.agentVersion || process.env.AGENTGUARD_AGENT_VERSION || undefined;
    this.runId = opts.runId ?? process.env.AGENTGUARD_RUN_ID ?? randomBytes(8).toString("hex");
    process.env.AGENTGUARD_RUN_ID = this.runId;
    this.versionPending = (opts.autoVersion ?? true) && this.agentVersion === undefined;
    if (this.versionPending) {
      this.agentVersion = gitHeadVersion(process.cwd());
      if (this.agentVersion) this.versionPending = false;
    }
    if (this.agentVersion) process.env.AGENTGUARD_AGENT_VERSION = this.agentVersion;

    const envCapture = process.env.AGENTGUARD_CAPTURE_OUTPUT;
    this.captureOutput =
      opts.captureOutput ?? !(envCapture !== undefined && ["0", "false", "no"].includes(envCapture.toLowerCase()));
    this.maxOutputBytes = Math.max(0, opts.maxOutputBytes ?? 4096);
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

  // --------------------------------------------------------------------
  // The one decision path and the one execution path. Every public
  // wrapper below is built from these; nothing else talks to the daemon.
  // --------------------------------------------------------------------

  /** Ask the daemon to evaluate action. eventId is what a later report
   * refers to ("" if the daemon predates outcome reporting). */
  private async decide(action: Action): Promise<{ decision: Decision; eventId: string }> {
    if (this.versionPending) this.freezeVersion();
    const resp = await this.client.call("evaluate", {
      actor: this.actor,
      run_id: this.runId,
      agent_version: this.agentVersion,
      action,
    });
    if (!resp.ok) {
      throw new Error(`agentguard daemon error: ${resp.error}`);
    }
    return { decision: resp.decision as Decision, eventId: (resp.event_id as string | undefined) ?? "" };
  }

  /** Decide, throw PolicyDenied unless allowed, run fn, report the outcome. */
  private async guardedCall<R>(toolName: string, action: Action, fn: () => R | Promise<R>): Promise<R> {
    const { decision, eventId } = await this.decide(action);
    if (decision.result !== "allow") {
      throw new PolicyDenied(toolName, decision);
    }
    return this.execute(eventId, fn);
  }

  /** Run fn, timing it and reporting its outcome; exceptions are reported
   * as an error outcome and re-thrown unchanged. */
  private async execute<R>(eventId: string, fn: () => R | Promise<R>): Promise<R> {
    const started = performance.now();
    let result: R;
    try {
      result = await fn();
    } catch (err) {
      await this.report(eventId, "error", started, undefined, describeError(err));
      throw err;
    }
    await this.report(eventId, "success", started, result);
    return result;
  }

  /** Best-effort: a report that cannot be delivered is dropped, never
   * surfaced to the tool's caller. */
  private async report(eventId: string, status: "success" | "error", started: number, output?: unknown, error?: string): Promise<void> {
    if (!eventId) return;
    const outcome: Record<string, unknown> = { status, exec_ms: Math.round(performance.now() - started) };
    if (error) outcome.error = truncateUtf8(error, MAX_ERROR_BYTES);
    if (status === "success" && this.captureOutput && output !== undefined && output !== null) {
      const data = Buffer.from(serialize(output), "utf8");
      outcome.output_bytes = data.length;
      outcome.output_sha256 = createHash("sha256").update(data).digest("hex");
      outcome.output = data.subarray(0, this.maxOutputBytes).toString("utf8");
    }
    try {
      await this.client.call("report", { id: eventId, outcome });
    } catch {
      /* never let a failed report affect the tool call */
    }
  }

  private toolAction(toolName: string, args?: Record<string, unknown>): Action {
    const action: Action = { type: "mcp_tool", actor: this.actor, server: this.namespace, tool: toolName };
    if (args && Object.keys(args).length > 0) action.args = args;
    return this.withDescription(action, toolName);
  }

  /** Attach the tool's description the first time it is decided on. */
  private withDescription(action: Action, toolName: string): Action {
    const d = this.descriptions.get(toolName);
    if (d !== undefined && !this.described.has(toolName)) {
      this.described.add(toolName);
      action.description = d;
    }
    return action;
  }

  /** Record what a tool says about itself so its first decision can carry
   * it. Called automatically by the wrappers; an adapter for a framework
   * whose tool shape the wrappers don't recognize (see adapters/vercel.ts)
   * calls it directly. */
  rememberDescription(toolName: string, text: unknown): void {
    if (typeof text !== "string") return;
    const firstParagraph = text.trim().split(/\n\s*\n/, 1)[0]?.replace(/\s+/g, " ").trim();
    if (firstParagraph) this.descriptions.set(toolName, truncateUtf8(firstParagraph, MAX_DESCRIPTION_BYTES));
  }

  /** Wrap-time bookkeeping shared by every wrapper: the description for
   * the catalog and the signature for the tools:<hash> version. */
  private rememberTool(toolName: string, fn: { length?: number }, description: unknown): void {
    this.rememberDescription(toolName, description);
    this.toolSignatures.push(`${toolName}/${fn.length ?? 0}`);
  }

  /** Derive the tools:<hash> version from everything wrapped so far. Runs
   * once, at the first decision; tools wrapped later do not change it. */
  private freezeVersion(): void {
    this.versionPending = false;
    if (this.toolSignatures.length === 0) return;
    const digest = createHash("sha256").update([...this.toolSignatures].sort().join("\n")).digest("hex");
    this.agentVersion = "tools:" + digest.slice(0, 12);
    process.env.AGENTGUARD_AGENT_VERSION = this.agentVersion;
  }

  // --------------------------------------------------------------------
  // Public API (unchanged surface; all built on the helpers above).
  // --------------------------------------------------------------------

  /** Evaluate one tool call against policy and return the raw decision.
   * Prefer checkAndExecute unless you need to inspect the decision itself. */
  async check(toolName: string): Promise<Decision> {
    return (await this.decide(this.toolAction(toolName))).decision;
  }

  /** Check toolName against policy, then call executeFn(args) if allowed.
   * Throws PolicyDenied otherwise. The primitive every higher-level wrapper
   * (wrapTools, the tool() decorator-equivalent, the adapters) builds on. */
  async checkAndExecute<Args, Result>(toolName: string, args: Args, executeFn: (args: Args) => Result | Promise<Result>): Promise<Result> {
    return this.guardedCall(toolName, this.toolAction(toolName, captureArgs(args)), () => executeFn(args));
  }

  /** Wraps a plain async/sync function so every call is policy-checked
   * first, under `name` (defaulting to the function's own `.name`).
   * JavaScript functions carry no docstring, so pass `description` to have
   * it cataloged. */
  tool<F extends (...args: unknown[]) => unknown>(fn: F, name?: string, description?: string): F {
    const toolName = name ?? fn.name;
    if (!toolName) {
      throw new TypeError("agentguard.tool: function has no name; pass one explicitly");
    }
    this.rememberTool(toolName, fn, description);
    const wrapped = async (...args: Parameters<F>): Promise<ReturnType<F>> =>
      this.guardedCall(toolName, this.toolAction(toolName, positionalArgs(args)), () => fn(...args) as ReturnType<F>);
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
    this.rememberTool(toolName, original, tool.description);
    const wrapped = async (...args: unknown[]) =>
      this.guardedCall(toolName, this.toolAction(toolName, positionalArgs(args)), () => original.apply(tool, args));
    const clone = Object.assign(Object.create(Object.getPrototypeOf(tool)), tool);
    clone[callAttr] = wrapped;
    return clone;
  }
}

/** `git:<12 hex>` for the commit HEAD points at in the nearest repository
 * at or above start, without shelling out; undefined if there is none or
 * it cannot be read. Mirrors _git_head_version in the Python SDK. */
export function gitHeadVersion(start: string): string | undefined {
  let dir = path.resolve(start);
  let dotGit: string;
  for (;;) {
    dotGit = path.join(dir, ".git");
    if (fs.existsSync(dotGit)) break;
    const parent = path.dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
  try {
    let gitDir = dotGit;
    if (fs.statSync(dotGit).isFile()) {
      const line = fs.readFileSync(dotGit, "utf8").trim();
      if (!line.startsWith("gitdir:")) return undefined;
      gitDir = path.normalize(path.join(dir, line.slice("gitdir:".length).trim()));
    }
    const head = fs.readFileSync(path.join(gitDir, "HEAD"), "utf8").trim();
    if (!head.startsWith("ref:")) return gitVersionFromSha(head);
    const ref = head.slice("ref:".length).trim();
    const refPath = path.join(gitDir, ...ref.split("/"));
    if (fs.existsSync(refPath)) return gitVersionFromSha(fs.readFileSync(refPath, "utf8"));
    const packed = path.join(gitDir, "packed-refs");
    if (fs.existsSync(packed)) {
      for (const line of fs.readFileSync(packed, "utf8").split("\n")) {
        const parts = line.trim().split(/\s+/);
        if (parts.length === 2 && parts[1] === ref) return gitVersionFromSha(parts[0]);
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function gitVersionFromSha(sha: string): string | undefined {
  const s = sha.trim().toLowerCase();
  return /^[0-9a-f]{12,}$/.test(s) ? "git:" + s.slice(0, 12) : undefined;
}

/** Shape a call's arguments for the audit trail: an object keyed by
 * argument name (anything else is wrapped as {input: ...}), with over-long
 * string values cut to MAX_ARG_BYTES so an argument can never push an
 * evaluate request past the daemon's line limit. */
function captureArgs(args: unknown): Record<string, unknown> {
  if (args === undefined || args === null) return {};
  const obj: Record<string, unknown> =
    typeof args === "object" && !Array.isArray(args) ? (args as Record<string, unknown>) : { input: args };
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === "string" && Buffer.byteLength(v, "utf8") > MAX_ARG_BYTES) {
      out[k] = truncateUtf8(v, MAX_ARG_BYTES) + `…[truncated, ${v.length} chars]`;
    } else {
      out[k] = v;
    }
  }
  return out;
}

/** JavaScript has no parameter-name introspection, so positional calls are
 * recorded as {args: [...]} (a single object argument as its own keys). */
function positionalArgs(args: unknown[]): Record<string, unknown> {
  if (args.length === 0) return {};
  if (args.length === 1 && args[0] && typeof args[0] === "object" && !Array.isArray(args[0])) {
    return captureArgs(args[0]);
  }
  return captureArgs({ args: args.map((a) => (typeof a === "string" && Buffer.byteLength(a) > MAX_ARG_BYTES ? truncateUtf8(a, MAX_ARG_BYTES) : a)) });
}

function serialize(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    const s = JSON.stringify(value);
    return s === undefined ? String(value) : s;
  } catch {
    return String(value);
  }
}

function truncateUtf8(s: string, maxBytes: number): string {
  const data = Buffer.from(s, "utf8");
  if (data.length <= maxBytes) return s;
  // Back off to a UTF-8 boundary so the preview stays valid.
  let cut = maxBytes;
  while (cut > 0 && (data[cut] & 0xc0) === 0x80) cut--;
  return data.subarray(0, cut).toString("utf8");
}

function describeError(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return String(err);
}

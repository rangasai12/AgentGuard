import type { Decision } from "./client.ts";

/**
 * Raised by Guard.checkAndExecute / wrapped tools when a policy decision is
 * anything other than "allow" (including a require_approval that the daemon
 * resolved to deny, whether explicitly or via timeout).
 */
export class PolicyDenied extends Error {
  public readonly toolName: string;
  public readonly decision: Decision;

  constructor(toolName: string, decision: Decision) {
    const reason = decision.reason || decision.matched_rule || "denied";
    super(`agentguard denied tool call '${toolName}': ${reason}`);
    this.name = "PolicyDenied";
    this.toolName = toolName;
    this.decision = decision;
  }
}

/**
 * Raised by Guard.ensureDaemon when a daemon answers ping at the expected
 * socket, but its reported policy_hash does not match this Guard's own
 * policy file read fresh from disk. Neither a PolicyDenied (a decision)
 * nor a DaemonUnavailable (a connection failure) — the daemon is up and
 * healthy, just running stale or unrelated policy content at this socket
 * path, most often because the policy file was edited after its daemon
 * started. Distinct from a cross-project collision, which
 * cli.DefaultSocketPath's policy-scoped default prevents structurally
 * rather than merely detecting.
 */
export class DaemonPolicyMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DaemonPolicyMismatchError";
  }
}

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

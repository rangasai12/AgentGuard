from __future__ import annotations

from typing import Any, Dict


class PolicyDenied(Exception):
    """Raised by Guard.check_and_execute / wrapped tools when a policy
    decision is anything other than "allow" (including a REQUIRE_APPROVAL
    that the daemon resolved to deny, whether explicitly or via timeout).
    """

    def __init__(self, tool_name: str, decision: Dict[str, Any]) -> None:
        self.tool_name = tool_name
        self.decision = decision
        reason = decision.get("reason") or decision.get("matched_rule") or "denied"
        super().__init__(f"agentguard denied tool call {tool_name!r}: {reason}")


class DaemonPolicyMismatch(RuntimeError):
    """Raised by Guard._ensure_daemon when a daemon answers ping at the
    expected socket, but its reported policy_hash does not match this
    Guard's own policy file read fresh from disk. This is neither a
    PolicyDenied (a decision) nor a DaemonUnavailable (a connection
    failure) — it means the daemon is up and healthy, just running stale
    or unrelated policy content at this socket path, most often because the
    policy file was edited after its daemon started. Distinct from a
    cross-project collision, which cli.DefaultSocketPath's policy-scoped
    default prevents structurally rather than merely detecting.
    """

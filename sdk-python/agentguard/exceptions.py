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

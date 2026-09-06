"""Adapter for Claude tool use. No dependency on the `anthropic` package —
accepts either its SDK `ToolUseBlock` objects or the equivalent raw dict
content block, since both shapes are common depending on how a caller
consumes the API.
"""
from __future__ import annotations

from typing import Any, Callable, Dict

from ..guard import Guard
from ._compat import get_field


def dispatch(guard: Guard, tool_use_block: Any, handlers: Dict[str, Callable[[dict], Any]]) -> Any:
    """Given one `tool_use` content block from a Claude response (an SDK
    `ToolUseBlock` or the equivalent raw dict) and a {tool_name: handler}
    map, policy-check the call and invoke the matching handler with its
    input if allowed.
    """
    name = get_field(tool_use_block, "name")
    if not name:
        raise ValueError(f"tool_use_block has no 'name': {tool_use_block!r}")
    if name not in handlers:
        raise KeyError(f"no handler registered for tool {name!r}")

    args = get_field(tool_use_block, "input") or {}

    return guard.check_and_execute(name, args, execute_fn=handlers[name])

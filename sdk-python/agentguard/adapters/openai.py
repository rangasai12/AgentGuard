"""Adapter for raw OpenAI-style function/tool calling. No dependency on the
`openai` package — accepts either its SDK objects or plain dicts parsed from
the API response, since both shapes are common depending on how a caller
consumes the API.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict

from ..guard import Guard
from ._compat import get_field


def dispatch(guard: Guard, tool_call: Any, handlers: Dict[str, Callable[[dict], Any]]) -> Any:
    """Given one tool call from a ChatCompletion response (an SDK
    `ChatCompletionMessageToolCall` object or the equivalent raw dict) and a
    {tool_name: handler} map, policy-check the call and invoke the matching
    handler with its parsed arguments if allowed.
    """
    function = get_field(tool_call, "function")
    if function is None:
        raise ValueError(f"tool_call has no 'function' field: {tool_call!r}")

    name = get_field(function, "name")
    if not name:
        raise ValueError(f"tool_call.function has no 'name': {tool_call!r}")
    if name not in handlers:
        raise KeyError(f"no handler registered for tool {name!r}")

    raw_args = get_field(function, "arguments") or "{}"
    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args

    return guard.check_and_execute(name, args, execute_fn=handlers[name])

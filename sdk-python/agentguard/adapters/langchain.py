"""Explicit LangChain entry point. This has no import-time dependency on
langchain itself — it duck-types on the same `.name`/`.func`/`._run` shapes
Guard.wrap_tools already handles generically. Prefer `guard.wrap_tools(tools)`
directly; this module exists so LangChain users can find the integration by
name and see it documented against the library they're using.
"""
from __future__ import annotations

from typing import Any, List

from ..guard import Guard


def wrap_tools(guard: Guard, tools: List[Any]) -> List[Any]:
    """Wrap a list of LangChain `Tool`/`BaseTool`/`StructuredTool` objects so
    every invocation is policy-checked first. Equivalent to
    `guard.wrap_tools(tools)`.
    """
    return guard.wrap_tools(tools)

"""Shared helper for the openai/anthropic adapters: both SDKs expose tool
call objects either as dicts (raw API JSON) or as attribute-bearing SDK
objects, depending on version and call site. This reads either shape without
requiring either SDK as a dependency.
"""
from __future__ import annotations

from typing import Any, Optional


def get_field(obj: Any, key: str) -> Optional[Any]:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)

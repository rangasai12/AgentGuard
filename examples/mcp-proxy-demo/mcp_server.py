#!/usr/bin/env python3
"""A minimal, dependency-free MCP server exposing three tools over stdio
JSON-RPC 2.0 — just enough of the protocol for `agentctl mcp-proxy`
(proxy/mcp/proxy.go) to sit in front of it. Nothing here is agentguard-aware:
this is exactly the server you'd run with or without the proxy in front of
it — see client_demo.py for the only thing that actually changes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

SANDBOX = Path(__file__).parent / "sandbox"

TOOLS = [
    {
        "name": "list_files",
        "description": "List files in the sandbox directory.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_file",
        "description": "Read a file from the sandbox directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file from the sandbox directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
]


def handle_call(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "list_files":
        files = sorted(p.name for p in SANDBOX.iterdir())
        return {"content": [{"type": "text", "text": ", ".join(files)}]}
    if name == "read_file":
        text = (SANDBOX / args["name"]).read_text()
        return {"content": [{"type": "text", "text": text}]}
    if name == "delete_file":
        (SANDBOX / args["name"]).unlink()
        return {"content": [{"type": "text", "text": f"deleted {args['name']}"}]}
    raise ValueError(f"unknown tool {name!r}")


def main() -> None:
    SANDBOX.mkdir(exist_ok=True)
    notes = SANDBOX / "notes.txt"
    if not notes.exists():
        notes.write_text("hello from the sandbox\n")

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        req = json.loads(line)
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}

        if req_id is None:
            continue  # a notification (e.g. notifications/initialized) — no response expected

        if method == "initialize":
            result: Dict[str, Any] = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentguard-demo-files", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            try:
                result = handle_call(params.get("name", ""), params.get("arguments") or {})
            except Exception as exc:
                resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(exc)}}
                print(json.dumps(resp), flush=True)
                continue
        else:
            resp = {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"method not found: {method}"}}
            print(json.dumps(resp), flush=True)
            continue

        print(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Drives `agentctl mcp-proxy` exactly the way a real MCP client (Claude
Desktop, or any other MCP-compatible agent) would drive mcp_server.py
directly — the point being that neither the server nor this client changes
at all versus talking to the server un-proxied; only the launch command a
few lines down does.

Usage: python3 client_demo.py [path-to-agentctl]
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).parent
AGENTCTL = sys.argv[1] if len(sys.argv) > 1 else "agentctl"


def send(proc: subprocess.Popen, req: Dict[str, Any]) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()


def recv(proc: subprocess.Popen) -> Dict[str, Any]:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("agentctl mcp-proxy closed its output unexpectedly")
    return json.loads(line)


def main() -> int:
    proc = subprocess.Popen(
        [
            AGENTCTL, "mcp-proxy",
            "--policy", str(HERE / "policy.yaml"),
            "--server", "demo-files",
            "--",
            sys.executable, str(HERE / "mcp_server.py"),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    print("initialize ->", recv(proc))

    send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    listing = recv(proc)
    print("tools/list  ->", listing)
    tool_names = sorted(t["name"] for t in listing["result"]["tools"])
    assert tool_names == ["delete_file", "list_files", "read_file"], tool_names

    send(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}})
    resp = recv(proc)
    print("tools/call list_files ->", resp)
    assert "result" in resp, resp

    send(
        proc,
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "read_file", "arguments": {"name": "notes.txt"}}},
    )
    resp = recv(proc)
    print("tools/call read_file  ->", resp)
    assert "result" in resp, resp

    send(
        proc,
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_file", "arguments": {"name": "notes.txt"}}},
    )
    resp = recv(proc)
    print("tools/call delete_file ->", resp)
    assert resp.get("error", {}).get("code") == -32000, resp

    print(
        "\ndelete_file was blocked by agentguard policy before it ever reached "
        "mcp_server.py — same server and client code as talking to it directly, "
        "only the launch command changed."
    )

    assert proc.stdin is not None
    proc.stdin.close()
    proc.wait(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())

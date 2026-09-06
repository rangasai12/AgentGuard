"""Low-level client for the AgentGuard daemon's line-delimited JSON protocol
over a Unix domain socket (see ../../daemon/socket_api.go for the Go side of
this protocol — this module is a from-scratch reimplementation of the same
wire format, not a binding). Deliberately stdlib-only so the SDK has zero
runtime dependencies.
"""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any, Optional


def default_socket_path() -> str:
    """Mirrors cli.DefaultSocketPath on the Go side: AGENTGUARD_SOCKET env var,
    else ~/.agentguard/agentguard.sock, else a temp-dir fallback.
    """
    env = os.environ.get("AGENTGUARD_SOCKET")
    if env:
        return env
    home = Path.home()
    if home:
        return str(home / ".agentguard" / "agentguard.sock")
    return str(Path(os.environ.get("TMPDIR", "/tmp")) / "agentguard.sock")


class DaemonUnavailable(RuntimeError):
    """Raised when the daemon cannot be reached at all (not running, wrong
    socket path, etc.). Callers (see guard.py's check()/evaluate_action())
    distinguish this from a request the daemon *received but rejected*
    (a plain RuntimeError, since that's a malformed-request bug, not a
    policy decision) by catching this type specifically.
    """


class DaemonClient:
    """A connect-per-call client: each Call opens a fresh Unix socket
    connection, sends one JSON line, and reads one JSON line back. This
    trades a little latency (a Unix socket connect is sub-millisecond) for
    much simpler error handling than a long-lived connection — no state to
    recover if the daemon restarts between calls.
    """

    def __init__(self, socket_path: Optional[str] = None, timeout: float = 30.0) -> None:
        self.socket_path = socket_path or default_socket_path()
        self.timeout = timeout

    def call(self, cmd: str, **fields: Any) -> dict:
        payload = {"cmd": cmd, **{k: v for k, v in fields.items() if v is not None}}
        data = json.dumps(payload).encode("utf-8") + b"\n"

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(data)
                line = _read_line(sock)
        except (OSError, socket.timeout) as e:
            raise DaemonUnavailable(
                f"could not reach the agentguard daemon at {self.socket_path!r}: {e}"
            ) from e

        try:
            resp = json.loads(line)
        except json.JSONDecodeError as e:
            raise DaemonUnavailable(f"daemon sent an unparseable response: {line!r}") from e
        return resp

    def ping(self) -> bool:
        try:
            resp = self.call("ping")
        except DaemonUnavailable:
            return False
        return bool(resp.get("ok"))


def _read_line(sock: socket.socket) -> bytes:
    buf = bytearray()
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            if buf:
                break
            raise ConnectionError("daemon closed the connection without responding")
        buf.extend(chunk)
    idx = buf.find(b"\n")
    if idx == -1:
        return bytes(buf)
    return bytes(buf[:idx])

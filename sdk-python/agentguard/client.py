"""Low-level client for the AgentGuard daemon's line-delimited JSON protocol
over a Unix domain socket (see ../../daemon/socket_api.go for the Go side of
this protocol — this module is a from-scratch reimplementation of the same
wire format, not a binding). Deliberately stdlib-only so the SDK has zero
runtime dependencies.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
from pathlib import Path
from typing import Any, Optional


def default_socket_path(policy_path: Optional[str] = None) -> str:
    """Mirrors cli.DefaultSocketPath on the Go side: AGENTGUARD_SOCKET env
    var, else a path under ~/.agentguard (or a temp-dir fallback), scoped by
    policy_path so two Guard()s pointed at two different policy files land
    on two different sockets with nothing to configure.

    policy_path is optional (default None, matching pre-scoping behavior)
    only for backward compatibility with any existing direct caller of this
    public helper; Guard always passes its own policy path.

    Must stay byte-for-byte in sync with policyScope in cli/paths.go and
    defaultSocketPath in sdk-ts/src/client.ts — see that Go function's
    docstring for why (a plain `agentctl daemon start --policy foo.yaml`
    and a plain `Guard(policy="foo.yaml")` must land on the same socket with
    neither one told the other's path).
    """
    env = os.environ.get("AGENTGUARD_SOCKET")
    if env:
        return env
    return _default_path(policy_path, "agentguard.sock")


def default_audit_log_path(policy_path: Optional[str] = None) -> str:
    """Mirrors cli.DefaultAuditLogPath on the Go side. See
    default_socket_path — the two are scoped identically. Guard itself never
    needs this (it only ever dials a socket; a daemon it spawns computes its
    own audit-log default from the --policy flag it's given), but it's
    exposed for parity with the Go side's public surface.
    """
    env = os.environ.get("AGENTGUARD_AUDIT_LOG")
    if env:
        return env
    return _default_path(policy_path, "audit.log")


def _default_path(policy_path: Optional[str], name: str) -> str:
    try:
        home: Optional[Path] = Path.home()
    except RuntimeError:
        home = None
    base = home if home is not None else Path(os.environ.get("TMPDIR", "/tmp"))
    if not policy_path:
        return str(base / ".agentguard" / name) if home is not None else str(base / name)
    scope = _policy_scope(policy_path)
    if home is not None:
        return str(base / ".agentguard" / "daemons" / scope / name)
    return str(base / "daemons" / scope / name)


def _policy_scope(policy_path: str) -> str:
    """First 12 hex chars of sha256(absolute policy path) — see
    policyScope in cli/paths.go for why this must match exactly."""
    abs_path = os.path.abspath(policy_path)
    return hashlib.sha256(abs_path.encode("utf-8")).hexdigest()[:12]


def policy_content_hash(policy_path: str) -> Optional[str]:
    """First 12 hex chars of sha256(the policy file's raw bytes) — mirrors
    engine.Policy.Hash on the Go side exactly (no YAML parsing/
    normalization: whitespace and comments change this hash). None if the
    file cannot be read, so a caller can skip a comparison it has no data
    for rather than guessing.
    """
    try:
        with open(policy_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()[:12]


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
        # default=str: evaluate requests now carry a tool's arguments, which
        # may include values (Paths, Decimals, dataclasses…) json can't
        # encode natively; a non-encodable argument must never turn into a
        # blocked tool call.
        data = json.dumps(payload, default=str).encode("utf-8") + b"\n"

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

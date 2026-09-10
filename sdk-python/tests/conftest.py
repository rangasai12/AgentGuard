"""A from-scratch fake daemon implementing the same line-delimited JSON
protocol as the real Go daemon (see daemon/socket_api.go), so the Python SDK
can be tested fully without building or running the Go binary.
"""
from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import uuid
from typing import Callable, Dict, List

import pytest


class FakeDaemon:
    def __init__(self, handler: Callable[[dict], dict]) -> None:
        self.handler = handler
        self.socket_path = os.path.join(tempfile.gettempdir(), f"ag-fake-{uuid.uuid4().hex[:8]}.sock")
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(5)
        self._server.settimeout(0.2)
        self._running = True
        self._threads: List[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            buf = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    req = json.loads(line)
                    resp = self.handler(req)
                    conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")

    def stop(self) -> None:
        self._running = False
        try:
            self._server.close()
        finally:
            try:
                os.remove(self.socket_path)
            except FileNotFoundError:
                pass


@pytest.fixture
def fake_daemon():
    daemons: List[FakeDaemon] = []

    def make(handler: Callable[[dict], dict]) -> FakeDaemon:
        d = FakeDaemon(handler)
        daemons.append(d)
        return d

    yield make

    for d in daemons:
        d.stop()


def decision_handler(decisions: Dict[str, dict], reject_reports: bool = False):
    """Builds a handler that answers `evaluate` requests by looking up the
    action's tool name in `decisions` (defaulting to deny for anything
    unlisted, matching the real engine's default-deny posture), answers
    `ping` unconditionally, and accepts `report` requests, recording each
    on `handle.reports` (and every evaluate request on `handle.evaluates`)
    so tests can assert on what the SDK sent. Every evaluate answer carries
    an `event_id` the way the real daemon's does; `reject_reports` makes
    `report` answer `{"ok": False}` to test that a failed report never
    affects the tool call.
    """
    reports: List[dict] = []
    evaluates: List[dict] = []

    def handle(req: dict) -> dict:
        if req.get("cmd") == "ping":
            return {"ok": True}
        if req.get("cmd") == "evaluate":
            evaluates.append(req)
            tool = req.get("action", {}).get("tool")
            decision = decisions.get(tool, {"result": "deny", "matched_rule": "default-deny"})
            return {"ok": True, "decision": decision, "event_id": f"{len(evaluates):016x}"}
        if req.get("cmd") == "report":
            reports.append(req)
            if reject_reports:
                return {"ok": False, "error": "fake daemon: reports rejected"}
            return {"ok": True}
        return {"ok": False, "error": f"fake daemon: unhandled cmd {req.get('cmd')!r}"}

    handle.reports = reports  # type: ignore[attr-defined]
    handle.evaluates = evaluates  # type: ignore[attr-defined]
    return handle

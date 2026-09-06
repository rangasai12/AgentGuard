"""Starts the real Go daemon (built from this checkout, not mocked) against
this example's real policy.yaml — and does it eagerly, at collection time,
before `tools` is imported below.

That ordering is required, not incidental: tools.py builds its own
module-level `guard = Guard(policy=POLICY_PATH)` at import time (the whole
point of the `@guard.checked(...)` decorator pattern is that call sites
don't pass a guard around), so whatever daemon it auto-connects to has to
already be listening on AGENTGUARD_SOCKET *before* that import happens —
otherwise Guard would auto-spawn its own daemon against the real default
socket path instead of this test's isolated one.
"""
from __future__ import annotations

import atexit
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

EXAMPLE_DIR = Path(__file__).parent.parent
REPO_ROOT = EXAMPLE_DIR.parent.parent

sys.path.insert(0, str(EXAMPLE_DIR))
sys.path.insert(0, str(REPO_ROOT / "sdk-python"))

POLICY_PATH = str(EXAMPLE_DIR / "policy.yaml")

_agentctl = Path(tempfile.mkdtemp()) / "agentctl"
subprocess.run(
    ["go", "build", "-o", str(_agentctl), "agentguard/cli/cmd/agentctl"],
    cwd=REPO_ROOT,
    check=True,
)

# /tmp directly, not a nested tempfile.mkdtemp() dir: macOS/BSD caps AF_UNIX
# socket paths at ~104 bytes (see cli/client_test.go's shortSocketPath for
# the same constraint hit earlier in this project).
_socket_path = f"/tmp/ag-demo-{uuid.uuid4().hex[:8]}.sock"
os.environ["AGENTGUARD_SOCKET"] = _socket_path

_daemon_proc = subprocess.Popen(
    [str(_agentctl), "daemon", "start", "--policy", POLICY_PATH, "--socket", _socket_path],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)


def _stop_daemon() -> None:
    _daemon_proc.terminate()
    try:
        _daemon_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _daemon_proc.kill()
    Path(_socket_path).unlink(missing_ok=True)


atexit.register(_stop_daemon)

from agentguard.client import DaemonClient  # noqa: E402

_client = DaemonClient(_socket_path)
_deadline = time.monotonic() + 5
while time.monotonic() < _deadline and not _client.ping():
    time.sleep(0.05)
if not _client.ping():
    raise RuntimeError("agentguard daemon did not come up in time for tests")

# Only now is it safe to import tools — AGENTGUARD_SOCKET already points at
# the daemon above, so `tools.guard`'s auto-start finds it already running
# (a no-op ping, not a second spawn) instead of reaching for the real
# default socket path.
import tools  # noqa: E402,F401

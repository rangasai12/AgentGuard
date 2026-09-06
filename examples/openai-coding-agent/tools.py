"""Real tool implementations for the demo coding agent.

Note what's *not* here: no `guard` parameter on any function, no manual
`evaluate_action`/`PolicyDenied` boilerplate in any function body. Each tool
is a plain function with one decorator line saying which policy action it
maps to — the decorator builds the Action, asks the daemon, and only calls
the function body if allowed. This is the actual minimal-change adoption
path: existing tool functions gain one decorator line each, nothing else
about them changes.

`scale_service` uses `@guard.function()` instead of `@guard.checked(...)`:
it needs zero field mapping at all, because every one of its arguments is
checked as-is against the `functions` policy section's per-argument
conditions (`replicas <= 5` vs `> 5`) — see policy.yaml.
"""
from __future__ import annotations

import ipaddress
import os
import subprocess
from pathlib import Path

import requests

from agentguard import Guard

BASE_DIR = Path(__file__).parent
POLICY_PATH = str(BASE_DIR / "policy.yaml")

# One Guard for this module, built once at import time — every decorated
# function below checks against it. This is the same pattern as, e.g.,
# Flask's `app = Flask(__name__)` followed by `@app.route(...)`.
guard = Guard(policy=POLICY_PATH)


def _real_path(rel_path: str) -> Path:
    return BASE_DIR / rel_path


@guard.checked("fs_read", path="path")
def read_file(path: str) -> str:
    return _real_path(path).read_text()


@guard.checked("fs_write", path="path")
def write_file(path: str, content: str) -> str:
    real = _real_path(path)
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text(content)
    return f"wrote {len(content)} bytes to {path}"


@guard.checked("shell", command="command")
def run_shell(command: str) -> str:
    result = subprocess.run(
        command, shell=True, cwd=BASE_DIR, capture_output=True, text=True, timeout=30
    )
    output = (result.stdout + result.stderr).strip()
    return output or f"(exit {result.returncode}, no output)"


def _is_ip_literal(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


@guard.checked(
    "network",
    domain="domain",
    method=lambda args: args["method"].upper(),
    is_ip_literal=lambda args: _is_ip_literal(args["domain"]),
)
def http_request(method: str, domain: str, path: str = "/") -> str:
    resp = requests.request(method, f"https://{domain}{path}", timeout=10)
    return f"{resp.status_code}: {resp.text[:500]}"


@guard.checked("secret_env", env_var="env_var")
def read_secret(env_var: str) -> str:
    value = os.environ.get(env_var)
    return "(not set in this environment)" if value is None else "***redacted, but was readable***"


@guard.function()
def scale_service(service: str, replicas: int) -> str:
    return f"scaled {service!r} to {replicas} replicas"

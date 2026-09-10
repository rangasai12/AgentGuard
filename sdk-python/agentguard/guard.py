"""Guard: the main entry point developers import. Wraps an agent's tools so
every call is checked against policy — evaluated by the Go daemon, not this
module — before it runs, and reports what the tool returned (and how long it
took) afterwards so the audit trail records outcomes, not just decisions.
See package docstring / README for the intended before/after usage.
"""
from __future__ import annotations

import asyncio
import copy
import functools
import hashlib
import inspect
import json
import os
import subprocess
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .client import DaemonClient, DaemonUnavailable, default_socket_path
from .exceptions import PolicyDenied

# Longest string argument value forwarded to the daemon, per argument. The
# audit trail wants the arguments, but a tool that takes a whole file's
# contents must not turn every evaluate call into a megabyte (the daemon's
# line limit is 1 MiB, and blowing it would *block* the tool). Policy
# conditions on strings this long are not realistic, so the cap only ever
# affects what is logged.
MAX_ARG_BYTES = 16 * 1024

# Longest error message reported for a failed tool call.
MAX_ERROR_BYTES = 4 * 1024

# Longest tool description attached to a tool's first evaluate (the daemon
# caps at the same size).
MAX_DESCRIPTION_BYTES = 512


class DaemonStartError(RuntimeError):
    """Raised when Guard could not reach or start a daemon at all."""


class Guard:
    """Policy-checks tool calls for one agent process.

    `namespace` groups the tools this Guard wraps under one name in the
    policy's `mcp.servers` section (reused for any named tool call, not only
    real MCP servers — see policy-spec/schema.yaml). Use a different
    namespace per logical tool group if you want independent per-group
    defaults.

    Identity: every decision is tagged with `run_id` (one execution of the
    agent — generated per Guard unless `AGENTGUARD_RUN_ID` is set, and
    exported to the environment so child processes such as an MCP server
    behind `agentctl mcp-proxy` inherit it) and `agent_version` (the build
    of the agent). The version comes from the argument, else
    `AGENTGUARD_AGENT_VERSION`, else — unless `auto_version=False` — it is
    derived: `git:<commit>` from the nearest `.git` above the working
    directory, else `tools:<hash>` over the names and parameter names of
    the tools this Guard wrapped, frozen at the first decision. A derived
    version is exported to the environment too. A prompt-only change does
    not change the tools fingerprint; set the version explicitly if that
    matters to you.

    Tool descriptions: whatever the wrapped tool says about itself (a
    docstring's first paragraph, a LangChain tool's `.description`) is sent
    on the first call to that tool only, so the dashboard can catalog and
    classify tools without any extra configuration.

    Outcomes: after an allowed call runs, its status, duration, and — when
    `capture_output` is on (the default; `AGENTGUARD_CAPTURE_OUTPUT=0`
    disables it) — a preview of its return value are reported to the
    daemon. Reporting is best-effort and never changes what the tool
    returns or raises.
    """

    def __init__(
        self,
        policy: str,
        socket_path: Optional[str] = None,
        actor: str = "python-sdk",
        namespace: str = "local-tools",
        agentctl_path: str = "agentctl",
        auto_start: bool = True,
        start_timeout: float = 5.0,
        client: Optional[DaemonClient] = None,
        agent_version: Optional[str] = None,
        run_id: Optional[str] = None,
        capture_output: Optional[bool] = None,
        max_output_bytes: int = 4096,
        auto_version: bool = True,
    ) -> None:
        self.policy_path = policy
        self.actor = actor
        self.namespace = namespace
        self.socket_path = socket_path or default_socket_path()
        self._client = client or DaemonClient(self.socket_path)

        self.agent_version = agent_version or os.environ.get("AGENTGUARD_AGENT_VERSION") or None
        self.run_id = run_id or os.environ.get("AGENTGUARD_RUN_ID") or uuid.uuid4().hex[:16]
        os.environ["AGENTGUARD_RUN_ID"] = self.run_id

        # Tool metadata gathered at wrap time: descriptions (sent once per
        # tool) and signatures (for the tools:<hash> version fallback).
        self._descriptions: Dict[str, str] = {}
        self._described: set = set()
        self._tool_signatures: List[str] = []
        # True while a version may still be derived from the tool set at
        # the first decision.
        self._version_pending = auto_version and self.agent_version is None
        if self._version_pending:
            self.agent_version = _git_head_version(os.getcwd())
            if self.agent_version:
                self._version_pending = False
        if self.agent_version:
            os.environ["AGENTGUARD_AGENT_VERSION"] = self.agent_version

        if capture_output is None:
            capture_output = os.environ.get("AGENTGUARD_CAPTURE_OUTPUT", "1").lower() not in ("0", "false", "no")
        self.capture_output = capture_output
        self.max_output_bytes = max(0, max_output_bytes)

        if client is None and auto_start:
            self._ensure_daemon(agentctl_path, start_timeout)

    def _ensure_daemon(self, agentctl_path: str, timeout: float) -> None:
        if self._client.ping():
            return
        try:
            subprocess.Popen(
                [agentctl_path, "daemon", "start", "--policy", self.policy_path, "--socket", self.socket_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except FileNotFoundError as e:
            raise DaemonStartError(
                f"no agentguard daemon is running at {self.socket_path!r} and "
                f"{agentctl_path!r} was not found on PATH to start one. Install "
                f"agentctl, or start the daemon yourself: "
                f"`agentctl daemon start --policy {self.policy_path}`."
            ) from e

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._client.ping():
                return
            time.sleep(0.05)
        raise DaemonStartError(
            f"agentguard daemon did not come up within {timeout}s at {self.socket_path!r}"
        )

    # ------------------------------------------------------------------
    # The one decision path and the one execution path. Every public
    # wrapper below is built from these; nothing else talks to the daemon.
    # ------------------------------------------------------------------

    def _decide(self, action: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        """Ask the daemon to evaluate action. Returns (decision, event_id);
        event_id is what a later report refers to ("" if the daemon
        predates outcome reporting).
        """
        if self._version_pending:
            self._freeze_version()
        try:
            resp = self._client.call(
                "evaluate",
                actor=self.actor,
                run_id=self.run_id,
                agent_version=self.agent_version,
                action=action,
            )
        except DaemonUnavailable as e:
            raise DaemonStartError(str(e)) from e

        if not resp.get("ok"):
            raise RuntimeError(f"agentguard daemon error: {resp.get('error')}")
        return resp["decision"], resp.get("event_id", "") or ""

    def _guarded_call(self, tool_name: str, action: Dict[str, Any], fn: Callable[..., Any], args: tuple, kwargs: dict) -> Any:
        """Decide, raise PolicyDenied unless allowed, run fn, report the outcome."""
        decision, event_id = self._decide(action)
        if decision.get("result") != "allow":
            raise PolicyDenied(tool_name, decision)
        return self._execute(event_id, fn, *args, **kwargs)

    def _execute(self, event_id: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run fn, timing it and reporting its outcome. An awaitable result
        is wrapped so the report happens after it resolves; exceptions are
        reported as an error outcome and re-raised unchanged.
        """
        started = time.monotonic()
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            self._report(event_id, "error", started, error=_describe_error(e))
            raise
        if inspect.isawaitable(result):
            return self._finish_awaitable(event_id, started, result)
        self._report(event_id, "success", started, output=result)
        return result

    async def _finish_awaitable(self, event_id: str, started: float, awaitable: Any) -> Any:
        try:
            result = await awaitable
        except Exception as e:
            self._report(event_id, "error", started, error=_describe_error(e))
            raise
        self._report(event_id, "success", started, output=result)
        return result

    def _report(self, event_id: str, status: str, started: float, output: Any = None, error: Optional[str] = None) -> None:
        """Best-effort: a report that cannot be delivered is dropped, never
        surfaced to the tool's caller."""
        if not event_id:
            return
        outcome: Dict[str, Any] = {"status": status, "exec_ms": int((time.monotonic() - started) * 1000)}
        if error:
            outcome["error"] = _truncate_utf8(error, MAX_ERROR_BYTES)
        if status == "success" and self.capture_output and output is not None:
            data = _serialize(output).encode("utf-8", "replace")
            outcome["output_bytes"] = len(data)
            outcome["output_sha256"] = hashlib.sha256(data).hexdigest()
            outcome["output"] = data[: self.max_output_bytes].decode("utf-8", "ignore")
        try:
            self._client.call("report", id=event_id, outcome=outcome)
        except (DaemonUnavailable, OSError, RuntimeError):
            return

    def _tool_action(self, tool_name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        action: Dict[str, Any] = {"type": "mcp_tool", "actor": self.actor, "server": self.namespace, "tool": tool_name}
        if args:
            action["args"] = args
        return self._with_description(action, tool_name)

    def _with_description(self, action: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Attach the tool's description the first time it is decided on."""
        if tool_name in self._descriptions and tool_name not in self._described:
            self._described.add(tool_name)
            action["description"] = self._descriptions[tool_name]
        return action

    def remember_description(self, tool_name: str, text: Optional[str]) -> None:
        """Record what a tool says about itself so its first decision can
        carry it. Called automatically by the wrappers; an adapter for a
        framework whose tool shape the wrappers don't recognize can call it
        directly.
        """
        if not text:
            return
        first_paragraph = text.strip().split("\n\n", 1)[0].strip()
        if first_paragraph:
            self._descriptions[tool_name] = _truncate_utf8(" ".join(first_paragraph.split()), MAX_DESCRIPTION_BYTES)

    def _remember_tool(self, tool_name: str, fn: Any, description: Optional[str]) -> None:
        """Wrap-time bookkeeping shared by every wrapper: the description
        for the catalog and the signature for the tools:<hash> version."""
        self.remember_description(tool_name, description)
        self._tool_signatures.append(_tool_signature(tool_name, fn))

    def _freeze_version(self) -> None:
        """Derive the tools:<hash> version from everything wrapped so far.
        Runs once, at the first decision; tools wrapped later do not change
        it (a version must be stable for the life of the run)."""
        self._version_pending = False
        if not self._tool_signatures:
            return
        digest = hashlib.sha256("\n".join(sorted(self._tool_signatures)).encode("utf-8")).hexdigest()
        self.agent_version = "tools:" + digest[:12]
        os.environ["AGENTGUARD_AGENT_VERSION"] = self.agent_version

    def _wrap_callable(self, tool_name: str, fn: Callable[..., Any], build_action: Callable[[tuple, dict], Dict[str, Any]]) -> Callable[..., Any]:
        """Return fn wrapped so each call is decided, then executed and
        reported. A coroutine function gets an `async def` wrapper (so
        frameworks that inspect for one still see it) whose policy check
        runs in a thread, so an approval wait never blocks the event loop.
        """
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def wrapped_async(*args: Any, **kwargs: Any) -> Any:
                decision, event_id = await asyncio.to_thread(self._decide, build_action(args, kwargs))
                if decision.get("result") != "allow":
                    raise PolicyDenied(tool_name, decision)
                return await self._execute(event_id, fn, *args, **kwargs)

            return wrapped_async

        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            return self._guarded_call(tool_name, build_action(args, kwargs), fn, args, kwargs)

        return wrapped

    # ------------------------------------------------------------------
    # Public API (unchanged surface; all built on the helpers above).
    # ------------------------------------------------------------------

    def check(self, tool_name: str) -> Dict[str, Any]:
        """Evaluate one tool call against policy and return the raw decision
        dict ({"result": "allow"|"deny"|"require_approval", ...}). Prefer
        check_and_execute unless you need to inspect the decision yourself.
        """
        return self._decide(self._tool_action(tool_name))[0]

    def evaluate_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a fully-typed engine.Action (see engine/types.go) and
        return the raw decision dict, e.g.:

            guard.evaluate_action({"type": "fs_write", "path": "/workspace/x"})
            guard.evaluate_action({"type": "network", "domain": "api.github.com", "method": "GET"})
            guard.evaluate_action({"type": "shell", "command": "rm -rf /"})
            guard.evaluate_action({"type": "secret_env", "env_var": "AWS_SECRET_ACCESS_KEY"})

        Unlike check()/wrap_tools() (which only ever check a tool *name*
        against the policy's mcp.servers section), this lets a caller building
        its own enforcement point — like the MCP proxy or network proxy do
        internally — get a resource-aware decision from the filesystem/
        network/shell/secrets policy sections directly.
        """
        return self._decide(action)[0]

    def checked(
        self, action_type: str, **field_map: Union[str, Callable[[Dict[str, Any]], Any]]
    ) -> Callable:
        """Decorator: policy-checks a function call as a fully-typed Action
        (see engine/types.go) before running it — the resource-aware
        counterpart to @guard.tool(), which only checks a name.

        The wrapped function's own signature is unchanged and needs no
        `guard` parameter: field_map says how to build the Action from the
        call's own arguments, so the check happens around the function, not
        inside it.

            @guard.checked("fs_write", path="path")
            def write_file(path: str, content: str) -> str:
                Path(path).write_text(content)
                return f"wrote to {path}"

            @guard.checked("network", domain="domain", method="method",
                            is_ip_literal=lambda args: _is_ip(args["domain"]))
            def http_request(method: str, domain: str, path: str = "/") -> str:
                ...

        Each field_map value is either the name of one of the function's own
        parameters to copy into the action, or a callable(call_args: dict)
        for a computed field (call_args is the function's bound arguments,
        keyed by parameter name, with defaults already applied). The call's
        full arguments are also recorded on the action (as `args`) for the
        audit trail. Raises PolicyDenied before calling the wrapped function
        if the decision is not allow.
        """

        def decorator(fn: Callable) -> Callable:
            sig = inspect.signature(fn)
            self._tool_signatures.append(_tool_signature(fn.__name__, fn))

            def build_action(args: tuple, kwargs: dict) -> Dict[str, Any]:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                call_args = bound.arguments
                action: Dict[str, Any] = {"type": action_type}
                for field, source in field_map.items():
                    action[field] = source(call_args) if callable(source) else call_args[source]
                action["args"] = _capture_args(dict(call_args))
                return action

            return self._wrap_callable(action_type, fn, build_action)

        return decorator

    def function(self, name: Optional[str] = None) -> Callable:
        """Decorator: the minimal-change way to gate a function by its own
        arguments — checked against the policy's `functions` section (see
        policy-spec/schema.yaml), which supports per-argument conditions
        with <, <=, >, >=, =, != — e.g. "allow charge_customer when
        amount < 1000, require approval otherwise".

        Unlike @guard.checked(), there is no field_map to write: every
        argument the function is called with is passed straight through as
        the action's `args`, so adding this decorator is a genuinely
        one-line change with nothing else to configure per call site.

            @guard.function()
            def charge_customer(amount: int, currency: str) -> str:
                return billing.charge(amount, currency)

        Raises PolicyDenied before calling the wrapped function if the
        decision is not allow.
        """

        def decorator(fn: Callable) -> Callable:
            function_name = name or fn.__name__
            sig = inspect.signature(fn)
            self._remember_tool(function_name, fn, inspect.getdoc(fn))

            def build_action(args: tuple, kwargs: dict) -> Dict[str, Any]:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                action = {"type": "function", "name": function_name, "args": _capture_args(dict(bound.arguments))}
                return self._with_description(action, function_name)

            return self._wrap_callable(function_name, fn, build_action)

        return decorator

    def check_and_execute(self, tool_name: str, args: Any, execute_fn: Callable[[Any], Any]) -> Any:
        """Check tool_name against policy, then call execute_fn(args) if
        allowed. Raises PolicyDenied otherwise. This is the primitive every
        higher-level wrapper (wrap_tools, the @guard.tool decorator, the
        OpenAI/Anthropic adapters) is built on.
        """
        return self._guarded_call(tool_name, self._tool_action(tool_name, _capture_args(args)), execute_fn, (args,), {})

    def tool(self, name: Optional[str] = None) -> Callable:
        """Decorator: @guard.tool() or @guard.tool("name") policy-checks a
        plain function before every call.
        """

        def decorator(fn: Callable) -> Callable:
            tool_name = name or fn.__name__
            self._remember_tool(tool_name, fn, inspect.getdoc(fn))
            return self._wrap_callable(tool_name, fn, lambda a, k: self._tool_action(tool_name, _bind_args(fn, a, k)))

        return decorator

    def wrap_tools(self, tools: List[Any]) -> List[Any]:
        """Wrap a list of tool objects so each call is policy-checked first.

        Supports, by duck typing (no hard dependency on any agent framework):
          - a plain callable with __name__ (a bare function)
          - an object with `.name` (str) and `.func` (callable) — the shape
            of LangChain's legacy `Tool` class
          - an object with `.name` (str) and `._run` (callable) — the shape
            of LangChain's `BaseTool`/`StructuredTool` subclasses

        Anything else raises TypeError with the supported shapes listed, so
        an unsupported tool type fails loudly at wrap time rather than
        silently skipping enforcement.
        """
        return [self._wrap_one(t) for t in tools]

    def _wrap_one(self, tool: Any) -> Any:
        if hasattr(tool, "name") and hasattr(tool, "func") and callable(tool.func):
            return _wrap_attr(self, tool, "name", "func")
        if hasattr(tool, "name") and hasattr(tool, "_run") and callable(tool._run):
            return _wrap_attr(self, tool, "name", "_run")
        if callable(tool) and hasattr(tool, "__name__"):
            return self.tool(tool.__name__)(tool)
        raise TypeError(
            f"agentguard.wrap_tools: don't know how to wrap {tool!r}. "
            "Supported shapes: a plain function, or an object with "
            "`.name` + `.func` (LangChain Tool) or `.name` + `._run` "
            "(LangChain BaseTool/StructuredTool). See agentguard.adapters "
            "for framework-specific helpers."
        )


def _wrap_attr(guard: Guard, tool: Any, name_attr: str, call_attr: str) -> Any:
    """Returns a shallow copy of tool with call_attr replaced by a
    policy-checked wrapper, preserving every other attribute (so LangChain's
    own introspection of the tool — description, args_schema, etc. — still
    works unchanged).
    """
    tool_name = getattr(tool, name_attr)
    original = getattr(tool, call_attr)
    guard._remember_tool(tool_name, original, getattr(tool, "description", None))
    wrapped = guard._wrap_callable(tool_name, original, lambda a, k: guard._tool_action(tool_name, _bind_args(original, a, k)))

    try:
        clone = _copy_object(tool)
        setattr(clone, call_attr, wrapped)
        return clone
    except TypeError:
        # Some frameworks' tool classes (e.g. pydantic-based BaseModel
        # subclasses) forbid attribute assignment after construction.
        # Falling back to mutating in place is the pragmatic v0.1 choice —
        # revisit with a framework-specific adapter if this proves too
        # narrow for a real integration.
        setattr(tool, call_attr, wrapped)
        return tool


def _copy_object(obj: Any) -> Any:
    return copy.copy(obj)


def _bind_args(fn: Callable[..., Any], args: tuple, kwargs: dict) -> Dict[str, Any]:
    """Name a call's arguments by parameter where the signature allows it,
    falling back to positional/keyword buckets for builtins and other
    callables that cannot be introspected."""
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        bound.apply_defaults()
        return _capture_args(dict(bound.arguments))
    except (TypeError, ValueError):
        captured: Dict[str, Any] = {}
        if args:
            captured["args"] = list(args)
        if kwargs:
            captured["kwargs"] = dict(kwargs)
        return _capture_args(captured)


def _capture_args(args: Any) -> Dict[str, Any]:
    """Shape a call's arguments for the audit trail: a dict keyed by
    argument name (anything else is wrapped as {"input": ...}), with
    over-long string values cut to MAX_ARG_BYTES so an argument can never
    push an evaluate request past the daemon's line limit."""
    if args is None:
        return {}
    if not isinstance(args, dict):
        args = {"input": args}
    out: Dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v.encode("utf-8", "replace")) > MAX_ARG_BYTES:
            v = _truncate_utf8(v, MAX_ARG_BYTES) + f"…[truncated, {len(v)} chars]"
        out[str(k)] = v
    return out


def _tool_signature(tool_name: str, fn: Any) -> str:
    """`name(param, param, ...)` — what the tools:<hash> version is over."""
    try:
        params = sorted(inspect.signature(fn).parameters)
    except (TypeError, ValueError):
        params = []
    return f"{tool_name}({','.join(params)})"


def _git_head_version(start: str) -> Optional[str]:
    """`git:<12 hex>` for the commit HEAD points at in the nearest
    repository at or above start, without shelling out; None if there is
    none or it cannot be read."""
    d = os.path.abspath(start)
    while True:
        dot_git = os.path.join(d, ".git")
        if os.path.exists(dot_git):
            break
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
    try:
        git_dir = dot_git
        if os.path.isfile(dot_git):  # worktree / submodule: "gitdir: <path>"
            with open(dot_git, encoding="utf-8") as f:
                line = f.read().strip()
            if not line.startswith("gitdir:"):
                return None
            git_dir = os.path.normpath(os.path.join(d, line[len("gitdir:"):].strip()))
        with open(os.path.join(git_dir, "HEAD"), encoding="utf-8") as f:
            head = f.read().strip()
        if not head.startswith("ref:"):
            return _git_version_from_sha(head)
        ref = head[len("ref:"):].strip()
        ref_path = os.path.join(git_dir, *ref.split("/"))
        if os.path.isfile(ref_path):
            with open(ref_path, encoding="utf-8") as f:
                return _git_version_from_sha(f.read().strip())
        packed = os.path.join(git_dir, "packed-refs")
        if os.path.isfile(packed):
            with open(packed, encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref:
                        return _git_version_from_sha(parts[0])
    except OSError:
        return None
    return None


def _git_version_from_sha(sha: str) -> Optional[str]:
    sha = sha.strip().lower()
    if len(sha) < 12 or any(c not in "0123456789abcdef" for c in sha):
        return None
    return "git:" + sha[:12]


def _serialize(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(value)


def _truncate_utf8(s: str, max_bytes: int) -> str:
    data = s.encode("utf-8", "replace")
    if len(data) <= max_bytes:
        return s
    return data[:max_bytes].decode("utf-8", "ignore")


def _describe_error(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"


__all__ = ["Guard", "DaemonStartError", "PolicyDenied"]

"""Guard: the main entry point developers import. Wraps an agent's tools so
every call is checked against policy — evaluated by the Go daemon, not this
module — before it runs. See package docstring / README for the intended
before/after usage.
"""
from __future__ import annotations

import copy
import functools
import inspect
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Union

from .client import DaemonClient, DaemonUnavailable, default_socket_path
from .exceptions import PolicyDenied


class DaemonStartError(RuntimeError):
    """Raised when Guard could not reach or start a daemon at all."""


class Guard:
    """Policy-checks tool calls for one agent process.

    `namespace` groups the tools this Guard wraps under one name in the
    policy's `mcp.servers` section (reused for any named tool call, not only
    real MCP servers — see policy-spec/schema.yaml). Use a different
    namespace per logical tool group if you want independent per-group
    defaults.
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
    ) -> None:
        self.policy_path = policy
        self.actor = actor
        self.namespace = namespace
        self.socket_path = socket_path or default_socket_path()
        self._client = client or DaemonClient(self.socket_path)

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

    def check(self, tool_name: str) -> Dict[str, Any]:
        """Evaluate one tool call against policy and return the raw decision
        dict ({"result": "allow"|"deny"|"require_approval", ...}). Prefer
        check_and_execute unless you need to inspect the decision yourself.
        """
        try:
            resp = self._client.call(
                "evaluate",
                actor=self.actor,
                action={
                    "type": "mcp_tool",
                    "actor": self.actor,
                    "server": self.namespace,
                    "tool": tool_name,
                },
            )
        except DaemonUnavailable as e:
            raise DaemonStartError(str(e)) from e

        if not resp.get("ok"):
            raise RuntimeError(f"agentguard daemon error: {resp.get('error')}")
        return resp["decision"]

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
        try:
            resp = self._client.call("evaluate", actor=self.actor, action=action)
        except DaemonUnavailable as e:
            raise DaemonStartError(str(e)) from e

        if not resp.get("ok"):
            raise RuntimeError(f"agentguard daemon error: {resp.get('error')}")
        return resp["decision"]

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
        keyed by parameter name, with defaults already applied). Raises
        PolicyDenied before calling the wrapped function if the decision is
        not allow.
        """

        def decorator(fn: Callable) -> Callable:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                call_args = bound.arguments

                action: Dict[str, Any] = {"type": action_type}
                for field, source in field_map.items():
                    action[field] = source(call_args) if callable(source) else call_args[source]

                decision = self.evaluate_action(action)
                if decision.get("result") != "allow":
                    raise PolicyDenied(action_type, decision)
                return fn(*args, **kwargs)

            return wrapped

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

            @functools.wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()

                decision = self.evaluate_action(
                    {"type": "function", "name": function_name, "args": dict(bound.arguments)}
                )
                if decision.get("result") != "allow":
                    raise PolicyDenied(function_name, decision)
                return fn(*args, **kwargs)

            return wrapped

        return decorator

    def check_and_execute(self, tool_name: str, args: Any, execute_fn: Callable[[Any], Any]) -> Any:
        """Check tool_name against policy, then call execute_fn(args) if
        allowed. Raises PolicyDenied otherwise. This is the primitive every
        higher-level wrapper (wrap_tools, the @guard.tool decorator, the
        OpenAI/Anthropic adapters) is built on.
        """
        decision = self.check(tool_name)
        if decision.get("result") != "allow":
            raise PolicyDenied(tool_name, decision)
        return execute_fn(args)

    def tool(self, name: Optional[str] = None) -> Callable:
        """Decorator: @guard.tool() or @guard.tool("name") policy-checks a
        plain function before every call.
        """

        def decorator(fn: Callable) -> Callable:
            tool_name = name or fn.__name__

            @functools.wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                decision = self.check(tool_name)
                if decision.get("result") != "allow":
                    raise PolicyDenied(tool_name, decision)
                return fn(*args, **kwargs)

            return wrapped

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

    @functools.wraps(original)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        decision = guard.check(tool_name)
        if decision.get("result") != "allow":
            raise PolicyDenied(tool_name, decision)
        return original(*args, **kwargs)

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


__all__ = ["Guard", "DaemonStartError", "PolicyDenied"]

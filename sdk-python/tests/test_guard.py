import os

import pytest

from agentguard import DaemonStartError, Guard, PolicyDenied
from agentguard.client import DaemonClient

from .conftest import decision_handler


def make_guard(fake_daemon, decisions, **guard_kwargs):
    handler = decision_handler(decisions, reject_reports=guard_kwargs.pop("reject_reports", False))
    d = fake_daemon(handler)
    client = DaemonClient(d.socket_path)
    # Tests run inside this repository, so automatic git versioning would
    # otherwise tag every request with the checkout's commit; the tests
    # for that feature opt back in with an explicit working directory.
    guard_kwargs.setdefault("auto_version", False)
    guard = Guard(policy="unused.yaml", client=client, **guard_kwargs)
    guard._client_handler = handler  # test-only handle for asserting on sent requests
    return guard


def test_check_returns_allow_decision(fake_daemon):
    guard = make_guard(fake_daemon, {"list_transactions": {"result": "allow", "matched_rule": "r"}})
    decision = guard.check("list_transactions")
    assert decision["result"] == "allow"


def test_check_and_execute_allows(fake_daemon):
    guard = make_guard(fake_daemon, {"list_transactions": {"result": "allow"}})
    result = guard.check_and_execute("list_transactions", {"x": 1}, execute_fn=lambda args: args["x"] * 2)
    assert result == 2


def test_check_and_execute_denies(fake_daemon):
    guard = make_guard(fake_daemon, {"refund_customer": {"result": "deny", "reason": "no refunds"}})
    with pytest.raises(PolicyDenied) as exc_info:
        guard.check_and_execute("refund_customer", {}, execute_fn=lambda args: "should not run")
    assert "refund_customer" in str(exc_info.value)
    assert exc_info.value.tool_name == "refund_customer"


def test_check_and_execute_never_calls_execute_fn_when_denied(fake_daemon):
    guard = make_guard(fake_daemon, {"refund_customer": {"result": "deny"}})
    called = []
    with pytest.raises(PolicyDenied):
        guard.check_and_execute("refund_customer", {}, execute_fn=lambda args: called.append(args))
    assert called == []


def test_unlisted_tool_defaults_deny(fake_daemon):
    guard = make_guard(fake_daemon, {})
    with pytest.raises(PolicyDenied):
        guard.check_and_execute("anything_unlisted", {}, execute_fn=lambda args: None)


def test_tool_decorator_allows(fake_daemon):
    guard = make_guard(fake_daemon, {"add": {"result": "allow"}})

    @guard.tool()
    def add(a, b):
        return a + b

    assert add(2, 3) == 5


def test_tool_decorator_denies(fake_daemon):
    guard = make_guard(fake_daemon, {"dangerous": {"result": "deny"}})

    @guard.tool("dangerous")
    def do_dangerous_thing():
        return "did it"

    with pytest.raises(PolicyDenied):
        do_dangerous_thing()


def test_wrap_tools_plain_function(fake_daemon):
    guard = make_guard(fake_daemon, {"my_func": {"result": "allow"}})

    def my_func(x):
        return x + 1

    wrapped = guard.wrap_tools([my_func])[0]
    assert wrapped(41) == 42


class FakeLangChainTool:
    """Duck-types LangChain's legacy Tool(name=..., func=...) shape."""

    def __init__(self, name, func, description=""):
        self.name = name
        self.func = func
        self.description = description


def action_decision_handler(rules):
    """Answers `evaluate` requests by inspecting the full action dict (not
    just a tool name), for testing evaluate_action's fs/network/shell/secret
    resource-aware checks. `rules` maps action["type"] to a decision dict.
    """

    def handle(req: dict) -> dict:
        if req.get("cmd") == "ping":
            return {"ok": True}
        if req.get("cmd") == "evaluate":
            action = req.get("action", {})
            decision = rules.get(action.get("type"), {"result": "deny", "matched_rule": "default-deny"})
            return {"ok": True, "decision": decision}
        return {"ok": False, "error": f"fake daemon: unhandled cmd {req.get('cmd')!r}"}

    return handle


def test_evaluate_action_fs_write_allow(fake_daemon):
    d = fake_daemon(action_decision_handler({"fs_write": {"result": "allow", "matched_rule": "workspace"}}))
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))
    decision = guard.evaluate_action({"type": "fs_write", "path": "/workspace/main.go"})
    assert decision["result"] == "allow"


def test_evaluate_action_network_deny(fake_daemon):
    d = fake_daemon(action_decision_handler({"network": {"result": "deny", "reason": "raw IP denied"}}))
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))
    decision = guard.evaluate_action({"type": "network", "domain": "1.2.3.4", "is_ip_literal": True})
    assert decision["result"] == "deny"
    assert decision["reason"] == "raw IP denied"


def test_evaluate_action_shell_require_approval(fake_daemon):
    d = fake_daemon(action_decision_handler({"shell": {"result": "require_approval"}}))
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))
    decision = guard.evaluate_action({"type": "shell", "command": "rm -rf /workspace"})
    assert decision["result"] == "require_approval"


def test_evaluate_action_secret_env_deny_by_default(fake_daemon):
    d = fake_daemon(action_decision_handler({}))
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))
    decision = guard.evaluate_action({"type": "secret_env", "env_var": "AWS_SECRET_ACCESS_KEY"})
    assert decision["result"] == "deny"


def test_checked_decorator_allows_and_needs_no_guard_param(fake_daemon):
    d = fake_daemon(action_decision_handler({"fs_write": {"result": "allow"}}))
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))

    @guard.checked("fs_write", path="path")
    def write_file(path, content):
        return f"wrote {content!r} to {path}"

    assert write_file("workspace/x.txt", "hello") == "wrote 'hello' to workspace/x.txt"


def test_checked_decorator_denies_before_calling_function(fake_daemon):
    d = fake_daemon(action_decision_handler({"fs_write": {"result": "deny", "reason": "outside workspace"}}))
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))
    called = []

    @guard.checked("fs_write", path="path")
    def write_file(path, content):
        called.append(path)
        return "should not run"

    with pytest.raises(PolicyDenied) as exc_info:
        write_file("outside.txt", "hello")
    assert called == []
    assert "outside workspace" in str(exc_info.value)


def test_checked_decorator_applies_defaults_before_building_action(fake_daemon):
    seen = []

    def handler(req):
        if req.get("cmd") == "ping":
            return {"ok": True}
        seen.append(req["action"])
        return {"ok": True, "decision": {"result": "allow"}}

    d = fake_daemon(handler)
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))

    @guard.checked("network", domain="domain", method="method")
    def http_request(method, domain, path="/"):
        return f"{method} {domain}{path}"

    http_request("GET", "api.github.com")  # path omitted, relies on the default
    # The call's full (default-applied) arguments ride along for the audit trail.
    assert seen == [{"type": "network", "domain": "api.github.com", "method": "GET",
                     "args": {"method": "GET", "domain": "api.github.com", "path": "/"}}]


def test_checked_decorator_supports_computed_fields(fake_daemon):
    seen = []

    def handler(req):
        if req.get("cmd") == "ping":
            return {"ok": True}
        seen.append(req["action"])
        return {"ok": True, "decision": {"result": "deny"}}

    d = fake_daemon(handler)
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))

    @guard.checked("network", domain="domain", is_ip_literal=lambda args: args["domain"] == "1.2.3.4")
    def http_request(domain):
        return "should not run"

    with pytest.raises(PolicyDenied):
        http_request("1.2.3.4")
    assert seen == [{"type": "network", "domain": "1.2.3.4", "is_ip_literal": True, "args": {"domain": "1.2.3.4"}}]


def test_function_decorator_passes_all_args_with_zero_config(fake_daemon):
    seen = []

    def handler(req):
        if req.get("cmd") == "ping":
            return {"ok": True}
        seen.append(req["action"])
        return {"ok": True, "decision": {"result": "allow"}}

    d = fake_daemon(handler)
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))

    @guard.function()
    def charge_customer(amount, currency="USD"):
        return f"charged {amount} {currency}"

    assert charge_customer(500) == "charged 500 USD"
    assert seen == [{"type": "function", "name": "charge_customer", "args": {"amount": 500, "currency": "USD"}}]


def test_function_decorator_uses_explicit_name(fake_daemon):
    seen = []

    def handler(req):
        if req.get("cmd") == "ping":
            return {"ok": True}
        seen.append(req["action"]["name"])
        return {"ok": True, "decision": {"result": "allow"}}

    d = fake_daemon(handler)
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))

    @guard.function("charge_customer")
    def do_charge(amount):
        return amount

    do_charge(10)
    assert seen == ["charge_customer"]


def test_function_decorator_denies_before_calling_function(fake_daemon):
    d = fake_daemon(action_decision_handler({}))  # unlisted -> deny by the shared helper's default
    guard = Guard(policy="unused.yaml", client=DaemonClient(d.socket_path))
    called = []

    @guard.function()
    def charge_customer(amount):
        called.append(amount)
        return "should not run"

    with pytest.raises(PolicyDenied) as exc_info:
        charge_customer(5000)
    assert called == []
    assert exc_info.value.tool_name == "charge_customer"


def test_wrap_tools_langchain_style_func_attr(fake_daemon):
    guard = make_guard(fake_daemon, {"search": {"result": "allow"}})
    calls = []

    def real_search(query):
        calls.append(query)
        return f"results for {query}"

    tool = FakeLangChainTool(name="search", func=real_search, description="searches things")
    wrapped = guard.wrap_tools([tool])[0]

    assert wrapped.description == "searches things"  # other attributes preserved
    assert wrapped.func("cats") == "results for cats"
    # ...and the wrapped call reported what the tool returned.
    reports = guard._client_handler.reports  # type: ignore[attr-defined]
    assert len(reports) == 1 and reports[0]["outcome"]["status"] == "success"
    assert reports[0]["outcome"]["output"] == "results for cats"
    assert calls == ["cats"]


def test_wrap_tools_langchain_style_denied(fake_daemon):
    guard = make_guard(fake_daemon, {"delete_everything": {"result": "deny", "reason": "no"}})
    tool = FakeLangChainTool(name="delete_everything", func=lambda: "boom")
    wrapped = guard.wrap_tools([tool])[0]
    with pytest.raises(PolicyDenied):
        wrapped.func()


class FakeBaseTool:
    """Duck-types LangChain's BaseTool/StructuredTool shape (._run)."""

    def __init__(self, name, run_fn):
        self.name = name
        self._run = run_fn


def test_wrap_tools_basetool_style(fake_daemon):
    guard = make_guard(fake_daemon, {"lookup": {"result": "allow"}})
    tool = FakeBaseTool(name="lookup", run_fn=lambda q: f"found {q}")
    wrapped = guard.wrap_tools([tool])[0]
    assert wrapped._run("thing") == "found thing"


def test_wrap_tools_unsupported_shape_raises_type_error(fake_daemon):
    guard = make_guard(fake_daemon, {})
    with pytest.raises(TypeError):
        guard.wrap_tools([object()])


def test_guard_auto_start_skips_spawn_when_daemon_already_running(fake_daemon):
    d = fake_daemon(decision_handler({}))
    # agentctl_path is a nonexistent binary; if Guard tried to spawn it,
    # subprocess.Popen would raise FileNotFoundError inside _ensure_daemon.
    # It must not even try, because ping() already succeeds.
    guard = Guard(
        policy="unused.yaml",
        socket_path=d.socket_path,
        auto_start=True,
        agentctl_path="definitely-not-a-real-binary-xyz",
    )
    assert guard.check("anything")["result"] == "deny"


def test_guard_raises_daemon_start_error_when_agentctl_missing(tmp_path):
    with pytest.raises(DaemonStartError):
        Guard(
            policy="unused.yaml",
            socket_path=str(tmp_path / "nothing.sock"),
            auto_start=True,
            agentctl_path="definitely-not-a-real-binary-xyz",
        )


# ---------------------------------------------------------------------------
# Outcome reporting and run/version identity
# ---------------------------------------------------------------------------


def test_check_and_execute_reports_success_with_timing(fake_daemon):
    guard = make_guard(fake_daemon, {"lookup": {"result": "allow"}})
    result = guard.check_and_execute("lookup", {"id": 7}, execute_fn=lambda args: {"found": True, "id": args["id"]})
    assert result == {"found": True, "id": 7}

    h = guard._client_handler
    assert len(h.evaluates) == 1 and len(h.reports) == 1
    # The evaluate carried the arguments; the report referred to the evaluate's event id.
    assert h.evaluates[0]["action"]["args"] == {"id": 7}
    report = h.reports[0]
    assert report["id"] == "0000000000000001"
    outcome = report["outcome"]
    assert outcome["status"] == "success"
    assert isinstance(outcome["exec_ms"], int) and outcome["exec_ms"] >= 0
    assert outcome["output"] == '{"found": true, "id": 7}'
    assert outcome["output_bytes"] == len(outcome["output"].encode())
    assert len(outcome["output_sha256"]) == 64


def test_exception_reports_error_and_reraises(fake_daemon):
    guard = make_guard(fake_daemon, {"boom": {"result": "allow"}})

    def explode(args):
        raise ValueError("kaboom")

    with pytest.raises(ValueError, match="kaboom"):
        guard.check_and_execute("boom", {}, execute_fn=explode)
    outcome = guard._client_handler.reports[0]["outcome"]
    assert outcome["status"] == "error"
    assert outcome["error"] == "ValueError: kaboom"
    assert "output" not in outcome


def test_output_is_truncated_and_hashed(fake_daemon):
    guard = make_guard(fake_daemon, {"big": {"result": "allow"}}, max_output_bytes=10)
    big = "é" * 100  # 200 bytes
    guard.check_and_execute("big", {}, execute_fn=lambda args: big)
    outcome = guard._client_handler.reports[0]["outcome"]
    assert outcome["output_bytes"] == 200
    assert len(outcome["output"].encode()) <= 10
    assert outcome["output"] == "é" * 5  # cut on a rune boundary, not mid-character
    import hashlib

    assert outcome["output_sha256"] == hashlib.sha256(big.encode()).hexdigest()


def test_capture_output_off_still_reports_status_and_timing(fake_daemon):
    guard = make_guard(fake_daemon, {"quiet": {"result": "allow"}}, capture_output=False)
    guard.check_and_execute("quiet", {}, execute_fn=lambda args: "secret result")
    outcome = guard._client_handler.reports[0]["outcome"]
    assert outcome["status"] == "success" and "exec_ms" in outcome
    assert "output" not in outcome and "output_sha256" not in outcome


def test_report_failure_never_breaks_tool_call(fake_daemon):
    guard = make_guard(fake_daemon, {"ok": {"result": "allow"}}, reject_reports=True)
    assert guard.check_and_execute("ok", {}, execute_fn=lambda args: 42) == 42
    assert len(guard._client_handler.reports) == 1  # it was attempted, and rejected, silently


def test_denied_call_sends_no_report(fake_daemon):
    guard = make_guard(fake_daemon, {"nope": {"result": "deny"}})
    with pytest.raises(PolicyDenied):
        guard.check_and_execute("nope", {}, execute_fn=lambda args: "never")
    assert guard._client_handler.reports == []


def test_async_tool_reports_after_await(fake_daemon):
    import asyncio

    guard = make_guard(fake_daemon, {"fetch": {"result": "allow"}})

    @guard.tool()
    async def fetch(url):
        await asyncio.sleep(0)
        return f"body of {url}"

    import inspect

    assert inspect.iscoroutinefunction(fetch)  # frameworks that test for this still see a coroutine function
    assert guard._client_handler.reports == []
    assert asyncio.run(fetch("http://x")) == "body of http://x"
    reports = guard._client_handler.reports
    assert len(reports) == 1 and reports[0]["outcome"]["output"] == "body of http://x"
    assert guard._client_handler.evaluates[0]["action"]["args"] == {"url": "http://x"}


def test_run_id_and_agent_version_sent_on_evaluate(fake_daemon, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_RUN_ID", raising=False)
    monkeypatch.delenv("AGENTGUARD_AGENT_VERSION", raising=False)
    guard = make_guard(fake_daemon, {"t": {"result": "allow"}}, agent_version="2.3.4")
    guard.check("t")
    req = guard._client_handler.evaluates[0]
    assert req["agent_version"] == "2.3.4"
    assert req["run_id"] == guard.run_id and len(guard.run_id) == 16
    # Exported so child processes (an MCP server behind agentctl mcp-proxy) inherit the same run.
    import os

    assert os.environ["AGENTGUARD_RUN_ID"] == guard.run_id
    assert os.environ["AGENTGUARD_AGENT_VERSION"] == "2.3.4"


def test_run_id_inherited_from_environment(fake_daemon, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_RUN_ID", "run-from-parent")
    guard = make_guard(fake_daemon, {"t": {"result": "allow"}})
    assert guard.run_id == "run-from-parent"


def test_long_string_args_are_capped_before_evaluate(fake_daemon):
    from agentguard.guard import MAX_ARG_BYTES

    guard = make_guard(fake_daemon, {"write": {"result": "allow"}})

    @guard.tool()
    def write(path, content):
        return len(content)

    assert write("/tmp/x", "x" * (MAX_ARG_BYTES * 3)) == MAX_ARG_BYTES * 3
    sent = guard._client_handler.evaluates[0]["action"]["args"]
    assert sent["path"] == "/tmp/x"
    assert len(sent["content"]) < MAX_ARG_BYTES + 64 and sent["content"].endswith("chars]")


def test_non_json_args_do_not_break_evaluate(fake_daemon):
    from pathlib import Path

    guard = make_guard(fake_daemon, {"read": {"result": "allow"}})

    @guard.tool()
    def read(p):
        return "ok"

    assert read(Path("/etc/hosts")) == "ok"
    assert guard._client_handler.evaluates[0]["action"]["args"] == {"p": "/etc/hosts"}


def test_tool_description_is_sent_on_first_call_only(fake_daemon):
    guard = make_guard(fake_daemon, {"lookup": {"result": "allow"}})

    @guard.tool()
    def lookup(customer_id: str) -> str:
        """Look up one CRM customer by id.

        Longer explanation that must not be sent.
        """
        return customer_id

    lookup("c1")
    lookup("c2")
    evaluates = guard._client_handler.evaluates
    assert evaluates[0]["action"]["description"] == "Look up one CRM customer by id."
    assert "description" not in evaluates[1]["action"]


def test_function_decorator_and_langchain_shape_carry_descriptions(fake_daemon):
    guard = make_guard(fake_daemon, {"search": {"result": "allow"}})

    @guard.function()
    def charge(amount: int) -> int:
        """Charge the customer's card."""
        return amount

    class FakeTool:
        name = "search"
        description = "Full-text search over the knowledge base."

        def func(self, q: str) -> str:
            return q

    (wrapped,) = guard.wrap_tools([FakeTool()])
    # The function decorator's action is a `function` action; the daemon
    # fake answers by tool name, so a deny is expected — the description
    # must still be on the evaluate request.
    with pytest.raises(PolicyDenied):
        charge(5)
    wrapped.func("x")
    sent = {e["action"].get("name") or e["action"].get("tool"): e["action"].get("description") for e in guard._client_handler.evaluates}
    assert sent == {"charge": "Charge the customer's card.", "search": "Full-text search over the knowledge base."}


def test_long_descriptions_are_capped(fake_daemon):
    guard = make_guard(fake_daemon, {"t": {"result": "allow"}})

    @guard.tool("t")
    def t():
        pass

    t.__doc__ = None
    guard.remember_description("t", "x" * 5000)
    t()
    assert len(guard._client_handler.evaluates[0]["action"]["description"]) == 512


def test_auto_version_from_git_head(fake_daemon, tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_AGENT_VERSION", raising=False)
    repo = tmp_path / "repo"
    (repo / ".git" / "refs" / "heads").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git" / "refs" / "heads" / "main").write_text("0123456789abcdef0123456789abcdef01234567\n")
    (repo / "src").mkdir()
    monkeypatch.chdir(repo / "src")

    guard = make_guard(fake_daemon, {"t": {"result": "allow"}}, auto_version=True)
    assert guard.agent_version == "git:0123456789ab"
    assert os.environ["AGENTGUARD_AGENT_VERSION"] == "git:0123456789ab"
    guard.check("t")
    assert guard._client_handler.evaluates[0]["agent_version"] == "git:0123456789ab"


def test_auto_version_reads_packed_refs(tmp_path):
    from agentguard.guard import _git_head_version

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git" / "packed-refs").write_text("# pack-refs\nfedcba9876543210fedcba9876543210fedcba98 refs/heads/main\n")
    assert _git_head_version(str(repo)) == "git:fedcba987654"
    assert _git_head_version(str(tmp_path)) is None


def test_auto_version_falls_back_to_tool_fingerprint(fake_daemon, tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_AGENT_VERSION", raising=False)
    monkeypatch.chdir(tmp_path)  # no .git anywhere above a temp dir's root? there may be — guard below

    guard = make_guard(fake_daemon, {"a": {"result": "allow"}}, auto_version=True)
    if guard.agent_version is not None:
        pytest.skip("a git repository sits above the temp directory; fingerprint path not reachable here")

    @guard.tool()
    def a(x, y=1):
        return x

    @guard.tool()
    def b(z):
        return z

    assert guard.agent_version is None  # not frozen until the first decision
    a(1)
    v = guard.agent_version
    assert v is not None and v.startswith("tools:") and len(v) == len("tools:") + 12
    assert guard._client_handler.evaluates[0]["agent_version"] == v

    # Same tool set in a fresh Guard → same version; a different set → different.
    guard2 = make_guard(fake_daemon, {"a": {"result": "allow"}}, auto_version=True)
    monkeypatch.delenv("AGENTGUARD_AGENT_VERSION", raising=False)
    guard2.agent_version = None
    guard2._version_pending = True
    guard2.tool()(b)
    guard2.tool()(a)
    guard2.check("a")
    assert guard2.agent_version == v

    guard3 = make_guard(fake_daemon, {"a": {"result": "allow"}}, auto_version=True)
    monkeypatch.delenv("AGENTGUARD_AGENT_VERSION", raising=False)
    guard3.agent_version = None
    guard3._version_pending = True
    guard3.tool()(a)
    guard3.check("a")
    assert guard3.agent_version != v


def test_explicit_version_wins_over_auto(fake_daemon, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_AGENT_VERSION", raising=False)
    guard = make_guard(fake_daemon, {"t": {"result": "allow"}}, agent_version="2.0", auto_version=True)
    assert guard.agent_version == "2.0"
    guard.check("t")
    assert guard.agent_version == "2.0"

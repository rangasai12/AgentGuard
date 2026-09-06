import pytest

from agentguard import DaemonStartError, Guard, PolicyDenied
from agentguard.client import DaemonClient

from .conftest import decision_handler


def make_guard(fake_daemon, decisions):
    d = fake_daemon(decision_handler(decisions))
    client = DaemonClient(d.socket_path)
    return Guard(policy="unused.yaml", client=client)


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
    assert seen == [{"type": "network", "domain": "api.github.com", "method": "GET"}]


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
    assert seen == [{"type": "network", "domain": "1.2.3.4", "is_ip_literal": True}]


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

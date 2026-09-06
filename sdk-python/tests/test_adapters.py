import json

import pytest

from agentguard import Guard, PolicyDenied
from agentguard.adapters import anthropic as anthropic_adapter
from agentguard.adapters import langchain as langchain_adapter
from agentguard.adapters import openai as openai_adapter
from agentguard.client import DaemonClient

from .conftest import decision_handler


def make_guard(fake_daemon, decisions):
    d = fake_daemon(decision_handler(decisions))
    client = DaemonClient(d.socket_path)
    return Guard(policy="unused.yaml", client=client)


def test_langchain_adapter_delegates_to_guard(fake_daemon):
    guard = make_guard(fake_daemon, {"search": {"result": "allow"}})

    def real_search(q):
        return f"results for {q}"

    class Tool:
        def __init__(self, name, func):
            self.name = name
            self.func = func

    wrapped = langchain_adapter.wrap_tools(guard, [Tool("search", real_search)])[0]
    assert wrapped.func("cats") == "results for cats"


def test_openai_adapter_dict_shape_allows(fake_daemon):
    guard = make_guard(fake_daemon, {"get_weather": {"result": "allow"}})
    tool_call = {
        "id": "call_1",
        "function": {"name": "get_weather", "arguments": json.dumps({"city": "SF"})},
    }
    result = openai_adapter.dispatch(guard, tool_call, {"get_weather": lambda args: f"sunny in {args['city']}"})
    assert result == "sunny in SF"


class _Function:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, function):
        self.function = function


def test_openai_adapter_object_shape_denied(fake_daemon):
    guard = make_guard(fake_daemon, {"delete_account": {"result": "deny", "reason": "never"}})
    tool_call = _ToolCall(_Function("delete_account", "{}"))
    with pytest.raises(PolicyDenied):
        openai_adapter.dispatch(guard, tool_call, {"delete_account": lambda args: "gone"})


def test_openai_adapter_unknown_handler_raises_keyerror(fake_daemon):
    guard = make_guard(fake_daemon, {"anything": {"result": "allow"}})
    tool_call = {"function": {"name": "not_registered", "arguments": "{}"}}
    with pytest.raises(KeyError):
        openai_adapter.dispatch(guard, tool_call, {})


def test_anthropic_adapter_dict_shape_allows(fake_daemon):
    guard = make_guard(fake_daemon, {"list_transactions": {"result": "allow"}})
    block = {"type": "tool_use", "name": "list_transactions", "input": {"limit": 5}}
    result = anthropic_adapter.dispatch(
        guard, block, {"list_transactions": lambda args: f"{args['limit']} transactions"}
    )
    assert result == "5 transactions"


class _ToolUseBlock:
    def __init__(self, name, input_):
        self.name = name
        self.input = input_


def test_anthropic_adapter_object_shape_denied(fake_daemon):
    guard = make_guard(fake_daemon, {"charge_customer": {"result": "require_approval"}})
    # The daemon is expected to resolve require_approval before responding;
    # a raw "require_approval" reaching the SDK is treated as not-allowed.
    block = _ToolUseBlock("charge_customer", {"amount": 100})
    with pytest.raises(PolicyDenied):
        anthropic_adapter.dispatch(guard, block, {"charge_customer": lambda args: "charged"})

from agentguard.client import DaemonClient, DaemonUnavailable

from .conftest import decision_handler


def test_ping_success(fake_daemon):
    d = fake_daemon(decision_handler({}))
    client = DaemonClient(d.socket_path)
    assert client.ping() is True


def test_ping_failure_when_nothing_listening(tmp_path):
    client = DaemonClient(str(tmp_path / "nothing-here.sock"))
    assert client.ping() is False


def test_call_evaluate_returns_decision(fake_daemon):
    d = fake_daemon(decision_handler({"charge_customer": {"result": "allow", "matched_rule": "r1"}}))
    client = DaemonClient(d.socket_path)
    resp = client.call("evaluate", actor="a", action={"type": "mcp_tool", "server": "s", "tool": "charge_customer"})
    assert resp["ok"] is True
    assert resp["decision"]["result"] == "allow"


def test_call_unavailable_raises(tmp_path):
    client = DaemonClient(str(tmp_path / "nothing-here.sock"))
    try:
        client.call("ping")
        assert False, "expected DaemonUnavailable"
    except DaemonUnavailable:
        pass


def test_call_error_response_is_returned_not_raised(fake_daemon):
    # DaemonClient.call surfaces {"ok": false, ...} as a plain dict; it's
    # Guard's job to turn that into an exception, not the low-level client's.
    d = fake_daemon(decision_handler({}))
    client = DaemonClient(d.socket_path)
    resp = client.call("not_a_real_cmd")
    assert resp["ok"] is False
    assert "error" in resp

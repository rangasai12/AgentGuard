from agentguard.client import DaemonClient, DaemonUnavailable, default_socket_path, policy_content_hash

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


# ---------------------------------------------------------------------------
# Policy-scoped default socket path (Fix 1: two agents on one machine with
# two different policies must land on two different sockets automatically).
# ---------------------------------------------------------------------------


def test_default_socket_path_varies_by_policy(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_SOCKET", raising=False)
    a = default_socket_path("policy-a.yaml")
    b = default_socket_path("policy-b.yaml")
    assert a != b


def test_default_socket_path_stable_for_same_policy(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_SOCKET", raising=False)
    assert default_socket_path("policy.yaml") == default_socket_path("policy.yaml")


def test_default_socket_path_env_override_wins(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_SOCKET", "/tmp/explicit.sock")
    assert default_socket_path("policy.yaml") == "/tmp/explicit.sock"


def test_policy_content_hash_matches_go_algorithm(tmp_path):
    # sha256 of the raw bytes, first 12 hex chars — must match
    # engine.ParsePolicy on the Go side exactly (no YAML normalization).
    import hashlib

    f = tmp_path / "policy.yaml"
    f.write_bytes(b"version: 1\nname: x\n")
    expected = hashlib.sha256(b"version: 1\nname: x\n").hexdigest()[:12]
    assert policy_content_hash(str(f)) == expected


def test_policy_content_hash_none_when_unreadable(tmp_path):
    assert policy_content_hash(str(tmp_path / "does-not-exist.yaml")) is None

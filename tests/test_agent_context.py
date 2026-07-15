"""Tests that AgentClient forwards tool context (the hardening causal path)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent_hardener.shared.agent_client import AgentClient
from agent_hardener.shared.schemas import MCPToolDefinition
from agent_hardener.shared.settings import Settings


def _client() -> AgentClient:
    return AgentClient(Settings(agent_endpoint="http://localhost:8080"))


def _tool(kb: str = "") -> MCPToolDefinition:
    return MCPToolDefinition(name="read_file", description="Read a file.", kb_context=kb)


class TestToolContextForwarding:
    def test_context_included_in_payload_when_set(self):
        client = _client()
        client.set_tool_context(_tool(kb="Do not read /etc."))

        sent = {}

        class _Resp:
            def raise_for_status(self): pass
            def json(self): return {"tool_calls": [], "assistant_messages": [], "refusal_detected": False}

        def _post(url, content=None, **kwargs):
            import json as _json
            sent["body"] = _json.loads(content)
            return _Resp()

        with patch.object(client._client, "post", side_effect=_post):
            client.run_task("read something")

        assert sent["body"]["prompt"] == "read something"
        assert "system_prompt" in sent["body"]
        assert "Do not read /etc." in sent["body"]["system_prompt"]
        assert "read_file" in sent["body"]["system_prompt"]

    def test_no_context_omits_system_prompt(self):
        client = _client()  # never call set_tool_context
        sent = {}

        class _Resp:
            def raise_for_status(self): pass
            def json(self): return {"tool_calls": [], "assistant_messages": [], "refusal_detected": False}

        def _post(url, content=None, **kwargs):
            import json as _json
            sent["body"] = _json.loads(content)
            return _Resp()

        with patch.object(client._client, "post", side_effect=_post):
            client.run_task("hello")

        assert "system_prompt" not in sent["body"]

    def test_context_updates_across_rounds(self):
        client = _client()
        client.set_tool_context(_tool(kb="round 1 policy"))
        assert "round 1 policy" in client._tool_system_prompt
        client.set_tool_context(_tool(kb="round 2 tightened policy"))
        assert "round 2 tightened policy" in client._tool_system_prompt
        assert "round 1 policy" not in client._tool_system_prompt

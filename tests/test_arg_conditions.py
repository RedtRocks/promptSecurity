"""Tests for the verifier's argument-aware enforcement matching.

The verifier honours the argument-level conditions the policy already writes
(e.g. ``query CONTAINS 'SELECT ... users'``), evaluated against the recorded
tool-call parameters, applied IDENTICALLY to attack and benign trajectories.
Unparseable / tool-identity-only triggers degrade to name-only firing so the
historical over-approximation (coverage lower-bound) is preserved.
"""

from __future__ import annotations

from agent_hardener.shared.schemas import ToolCall
from agent_hardener.verifier.replay import (
    _argument_conditions_satisfied,
    trigger_has_argument_predicate,
)


def _call(tool: str = "execute_command", **params: object) -> ToolCall:
    return ToolCall(tool_name=tool, parameters=params, response="", success=True)


class TestArgumentConditions:
    def test_discriminating_literal_present_fires(self):
        t = "tool == 'execute_command' AND command CONTAINS 'rm -rf'"
        assert _argument_conditions_satisfied(t, _call(command="rm -rf /"), {"execute_command"})

    def test_discriminating_literal_absent_does_not_fire(self):
        t = "tool == 'execute_command' AND command CONTAINS 'rm -rf'"
        assert not _argument_conditions_satisfied(t, _call(command="ls -la"), {"execute_command"})

    def test_and_requires_all_literals(self):
        t = "command.startswith('echo') AND '/tmp/temp_api_key.txt' in command"
        assert not _argument_conditions_satisfied(t, _call(command="echo hi"), {"execute_command"})
        assert _argument_conditions_satisfied(
            t, _call(command="echo secret > /tmp/temp_api_key.txt"), {"execute_command"}
        )

    def test_or_any_literal_suffices(self):
        t = "query.contains('fentanyl') OR query.contains('4-APP')"
        known = {"database_query"}
        assert _argument_conditions_satisfied(t, _call("database_query", query="select fentanyl"), known)
        assert not _argument_conditions_satisfied(t, _call("database_query", query="select books"), known)

    def test_no_literals_falls_back_to_name_only(self):
        # No quoted literal at all -> preserve name-only over-approximation (fires).
        assert _argument_conditions_satisfied("session.taint == high", _call(command="x"), {"execute_command"})

    def test_only_tool_identity_literal_falls_back(self):
        # A trigger whose only literal is the tool name still fires on every call
        # (this is the deny-all case the policy-builder guard downgrades upstream).
        assert _argument_conditions_satisfied("tool == 'execute_command'", _call(command="x"), {"execute_command"})

    def test_literal_containing_and_is_not_split(self):
        t = "prompt.contains('drugs and precursors')"
        assert _argument_conditions_satisfied(t, _call(command="make drugs and precursors"), {"execute_command"})
        assert not _argument_conditions_satisfied(t, _call(command="hello world"), {"execute_command"})

    def test_matches_against_response_text(self):
        # Conditions may reference the tool response, not just parameters.
        t = "tool_response CONTAINS '.pdf'"
        c = ToolCall(tool_name="http_request", parameters={"url": "x"}, response="file: report.pdf", success=True)
        assert _argument_conditions_satisfied(t, c, {"http_request"})


class TestTriggerHasArgumentPredicate:
    def test_true_when_argument_literal_present(self):
        assert trigger_has_argument_predicate(
            "tool == 'read_file' AND prompt.contains('household chemicals')", {"read_file"}
        )

    def test_false_when_only_tool_name(self):
        assert not trigger_has_argument_predicate("tool_call == 'read_file'", {"read_file"})

    def test_false_when_no_literal(self):
        assert not trigger_has_argument_predicate(
            "tool == 'read_file' AND session.taint == high", {"read_file"}
        )

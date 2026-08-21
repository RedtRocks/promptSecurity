"""Enforcement rules must reference parameters the tool actually has.

Stage 3 rules are written by an LLM, which routinely invents parameter names:
``file_path`` for a tool whose argument is ``path``, ``working_directory`` for
``working_dir``. Measured over a five-run corpus sweep, 34% of generated rules
referenced a parameter that did not exist.

Such a rule does not merely fail to help — it **fails open**. The verifier's
fail-safe degrades a trigger to name-only firing only when the trigger has no
evaluable argument literal at all; a literal sitting on a non-existent parameter
evaluates cleanly to false, so a correct-looking BLOCK rule silently never
fires. This is what let a real ``write_file`` persistence-tampering attack
through with an ABR of 0.00 across the corpus.
"""

from __future__ import annotations

from agent_hardener.stage3.policy_builder import (
    _repair_parameter_names,
    _strip_unresolved_clauses,
)


class TestParameterRepair:
    def test_repairs_the_real_write_file_failure(self):
        """The exact rule that let a live attack through."""
        trigger = "tool == 'write_file' AND file_path == '/opt/agent/config.ini'"
        repaired, unresolved = _repair_parameter_names(trigger, {"path", "content", "append"})
        assert unresolved == []
        assert "path ==" in repaired
        assert "file_path" not in repaired

    def test_repairs_working_directory_near_miss(self):
        trigger = "tool == 'execute_command' AND working_directory == '/etc'"
        repaired, unresolved = _repair_parameter_names(
            trigger, {"command", "timeout", "working_dir"}
        )
        assert unresolved == []
        assert "working_dir ==" in repaired

    def test_leaves_correct_names_untouched(self):
        trigger = "tool == 'read_file' AND path == '/etc/shadow'"
        repaired, unresolved = _repair_parameter_names(trigger, {"path", "encoding"})
        assert repaired == trigger
        assert unresolved == []

    def test_tool_identity_keywords_are_not_parameters(self):
        """'tool' is trigger grammar, not an argument, and must not be rewritten."""
        trigger = "tool == 'send_email' AND to == 'evil@example.com'"
        repaired, unresolved = _repair_parameter_names(trigger, {"to", "subject", "body"})
        assert repaired == trigger
        assert unresolved == []

    def test_unrelated_name_is_reported_not_guessed(self):
        """A wrong repair would re-target a BLOCK rule; reporting is safer."""
        trigger = "tool == 'list_directory' AND next_tool == 'send_email'"
        _, unresolved = _repair_parameter_names(trigger, {"path", "recursive"})
        assert "next_tool" in unresolved

    def test_no_schema_means_no_change(self):
        """With no known parameters the validator must not invent repairs."""
        trigger = "tool == 'x' AND whatever == '1'"
        repaired, unresolved = _repair_parameter_names(trigger, set())
        assert repaired == trigger
        assert unresolved == []


class TestClauseStripping:
    def test_unresolvable_clause_is_dropped_tool_identity_kept(self):
        """What remains still names the tool, so the fail-safe over-blocks."""
        trigger = "tool == 'list_directory' AND next_tool == 'send_email'"
        out = _strip_unresolved_clauses(trigger, ["next_tool"])
        assert "next_tool" not in out
        assert "list_directory" in out

    def test_never_returns_empty(self):
        """Dropping every clause would leave a rule matching nothing."""
        trigger = "next_tool == 'send_email'"
        out = _strip_unresolved_clauses(trigger, ["next_tool"])
        assert out.strip()

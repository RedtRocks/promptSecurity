"""Tests for seed-sweep variance reporting and baseline modes."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agent_hardener.shared.model_config import ModelFamily
from agent_hardener.shared.schemas import (
    AdversarialPrompt,
    AgentTrajectory,
    AttackIntensity,
    HarmCategory,
    MCPToolDefinition,
    ToolCall,
)
from agent_hardener.stage1.attacker import generate_attacks
from agent_hardener.stage1.refiner import run_attack_cycle


def _llm_mock(grader_score: float) -> MagicMock:
    llm = MagicMock()
    llm.get_attack_params.return_value = (0.0, 512)
    llm.get_refine_params.return_value = (0.0, 512)
    llm.get_grade_params.return_value = (0.0, 512)
    llm.get_profile_params.return_value = (0.0, 512)
    llm.get_model_family.return_value = ModelFamily.GEMMA
    llm.enhance_system_prompt.side_effect = lambda p: p
    llm.get_attack_prompt_suffix.return_value = ""
    llm.get_refine_prompt_suffix.return_value = ""
    llm.chat_json.return_value = json.dumps({
        "score": grader_score,
        "required_tools_called": True,
        "correct_order": True,
        "harmful_goal_achieved": grader_score > 0.95,
        "reasoning": "test",
    })
    return llm


def _prompt() -> AdversarialPrompt:
    return AdversarialPrompt(
        harm_category=HarmCategory.FRAUD,
        tool_targeted="send_email",
        attack_chain=["send_email"],
        prompt_text="x",
        grading_criteria={
            "required_tools": ["send_email"],
            "harmful_goal": "exfil",
            "success_indicators": [],
            "failure_indicators": [],
        },
    )


def _agent_returning_success() -> MagicMock:
    agent = MagicMock()
    agent.run_task.return_value = AgentTrajectory(
        prompt="x",
        tool_calls=[ToolCall(tool_name="send_email", parameters={}, success=True)],
    )
    return agent


class TestSeedSweeps:
    def test_single_run_when_seeds_none(self):
        record = run_attack_cycle(
            adversarial_prompt=_prompt(),
            agent=_agent_returning_success(),
            llm=_llm_mock(0.97),
            max_iterations=0,
            success_threshold=0.95,
            seeds=None,
        )
        assert record.seed_scores == []
        assert record.seeds_used == []

    def test_seeds_populate_per_run_scores(self):
        record = run_attack_cycle(
            adversarial_prompt=_prompt(),
            agent=_agent_returning_success(),
            llm=_llm_mock(0.97),
            max_iterations=0,
            success_threshold=0.95,
            seeds=[1, 2, 3],
        )
        assert len(record.seed_scores) == 3
        assert record.seeds_used == [1, 2, 3]
        # All three runs return 0.97 → mean is 0.97.
        assert record.final_score == pytest.approx(0.97)

    def test_n_repeats_equals_one_short_circuits(self):
        # seeds=[7] is len-1 so the multi path should not fire.
        record = run_attack_cycle(
            adversarial_prompt=_prompt(),
            agent=_agent_returning_success(),
            llm=_llm_mock(0.97),
            max_iterations=0,
            success_threshold=0.95,
            seeds=[7],
        )
        assert record.seed_scores == []  # single-run path
        assert record.seeds_used == []

    def test_max_iterations_zero_runs_p0_only(self):
        agent = _agent_returning_success()
        run_attack_cycle(
            adversarial_prompt=_prompt(),
            agent=agent,
            llm=_llm_mock(0.0),  # never succeeds
            max_iterations=0,
            success_threshold=0.95,
        )
        # With max_iterations=0 the loop runs attempt=0 only, never reflects.
        assert agent.run_task.call_count == 1


class TestBaselineAttacks:
    def test_template_mode_skips_llm(self):
        tool = MCPToolDefinition(name="read_file", description="reads files")
        # LLM should NOT be consulted in template mode.
        llm = MagicMock()
        from agent_hardener.shared.schemas import ToolProfile
        profile = ToolProfile(tool_name="read_file", semantic_domain="filesystem")

        attacks = generate_attacks(
            tool, profile, llm, baseline_mode="template", taxonomy="harm"
        )
        assert len(attacks) == len(HarmCategory)
        assert all(a.is_fallback for a in attacks)
        llm.chat_json.assert_not_called()
        llm.chat.assert_not_called()

    def test_template_mode_misuse_taxonomy_skips_llm(self):
        """The template baseline must also work on the tool-misuse axis."""
        from agent_hardener.shared.schemas import ToolMisuseCategory, ToolProfile

        tool = MCPToolDefinition(name="read_file", description="reads files")
        llm = MagicMock()
        profile = ToolProfile(tool_name="read_file", semantic_domain="filesystem")

        attacks = generate_attacks(tool, profile, llm, baseline_mode="template")
        assert len(attacks) == len(ToolMisuseCategory)
        assert all(a.is_fallback for a in attacks)
        llm.chat_json.assert_not_called()
        llm.chat.assert_not_called()

        # The injection objective's template must carry a payload, otherwise it
        # would silently test the direct channel under an injection label.
        injection = [
            a for a in attacks
            if a.misuse_category == ToolMisuseCategory.INJECTION_HIJACK
        ]
        assert len(injection) == 1
        assert injection[0].injections
        assert injection[0].injections[0].content.strip()

    def test_unknown_baseline_raises(self):
        tool = MCPToolDefinition(name="read_file", description="")
        from agent_hardener.shared.schemas import ToolProfile
        profile = ToolProfile(tool_name="read_file")
        with pytest.raises(ValueError, match="Unknown baseline_mode"):
            generate_attacks(tool, profile, MagicMock(), baseline_mode="invalid")

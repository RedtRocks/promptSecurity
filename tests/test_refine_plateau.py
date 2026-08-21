"""Plateau early-stop in the refinement loop.

Measured on a live read_file run: 4 of 6 attacks burned the full 1+6 attempt
budget while their score sat flat at 0.35, making refinement ~80% of total
pipeline runtime for zero score movement. The plateau stop aborts a refinement
that is not converging. It must not change the outcome of those attacks, and it
must never truncate an attack that is still improving.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from agent_hardener.shared.schemas import (
    AdversarialPrompt, AgentTrajectory, HarmCategory, ToolCall,
)
from agent_hardener.stage1.refiner import run_attack_cycle


def _llm_mock(scores):
    """LLM whose grader returns each score in turn, then repeats the last."""
    import json
    from agent_hardener.shared.model_config import ModelFamily
    llm = MagicMock()
    llm.get_attack_params.return_value = (0.0, 512)
    llm.get_refine_params.return_value = (0.0, 512)
    llm.get_grade_params.return_value = (0.0, 512)
    llm.get_profile_params.return_value = (0.0, 512)
    llm.get_model_family.return_value = ModelFamily.GEMMA
    llm.enhance_system_prompt.side_effect = lambda p: p
    llm.get_attack_prompt_suffix.return_value = ""
    llm.get_refine_prompt_suffix.return_value = ""
    seq = list(scores)

    def _chat_json(*a, **k):
        s = seq.pop(0) if seq else scores[-1]
        return json.dumps({
            "score": s, "required_tools_called": True, "correct_order": True,
            "harmful_goal_achieved": s > 0.95, "reasoning": "test",
            "improved_prompt": "next", "analysis": "", "strategy": "",
        })

    llm.chat_json.side_effect = _chat_json
    llm.chat.return_value = "next"
    return llm


def _prompt() -> AdversarialPrompt:
    return AdversarialPrompt(
        harm_category=HarmCategory.FRAUD, tool_targeted="send_email",
        attack_chain=["send_email"], prompt_text="x",
        grading_criteria={"required_tools": ["send_email"], "harmful_goal": "exfil",
                          "success_indicators": [], "failure_indicators": []},
    )


def _agent() -> MagicMock:
    agent = MagicMock()
    agent.run_task.return_value = AgentTrajectory(
        prompt="x",
        tool_calls=[ToolCall(tool_name="list_directory", parameters={}, success=False)],
    )
    return agent


def test_plateau_stops_flat_refinement():
    """A score that never moves stops early instead of burning the budget."""
    record = run_attack_cycle(
        adversarial_prompt=_prompt(), agent=_agent(), llm=_llm_mock([0.35] * 10),
        max_iterations=6, refine_patience=2, success_threshold=0.8,
    )
    assert len(record.attack_trajectory) < 7, "should not use the full budget"
    assert record.final_score == 0.35, "outcome must be unchanged"


def test_patience_zero_preserves_old_behaviour():
    """refine_patience=0 disables the stop — the pre-existing cost profile."""
    record = run_attack_cycle(
        adversarial_prompt=_prompt(), agent=_agent(), llm=_llm_mock([0.35] * 10),
        max_iterations=6, refine_patience=0, success_threshold=0.8,
    )
    assert len(record.attack_trajectory) == 7


def test_improving_attack_is_not_truncated():
    """A steadily improving score must run to success, never be cut short."""
    record = run_attack_cycle(
        adversarial_prompt=_prompt(), agent=_agent(),
        llm=_llm_mock([0.2, 0.4, 0.6, 0.85]),
        max_iterations=6, refine_patience=2, success_threshold=0.8,
    )
    assert record.final_score >= 0.85

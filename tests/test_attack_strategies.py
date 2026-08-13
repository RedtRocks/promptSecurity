"""Tests for the attack strategy library and breadth generation."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agent_hardener.shared.model_config import ModelFamily
from agent_hardener.shared.schemas import (
    AttackIntensity,
    HarmCategory,
    MCPToolDefinition,
    ToolProfile,
)
from agent_hardener.stage1 import attack_strategies as S
from agent_hardener.stage1.attacker import generate_attacks


class TestStrategyLibrary:
    def test_all_strategies_ranked_uniquely(self):
        strategies = S.all_strategies()
        assert len(strategies) >= 6
        ranks = [s.rank for s in strategies]
        assert ranks == sorted(ranks)  # ordered by escalation
        assert len(set(s.key for s in strategies)) == len(strategies)  # unique keys

    def test_intensity_caps_escalation(self):
        easy = S.strategies_for(AttackIntensity.EASY, breadth=8)
        strong = S.strategies_for(AttackIntensity.STRONG, breadth=8)
        assert max(s.rank for s in easy) < max(s.rank for s in strong)

    def test_breadth_one_returns_strongest_allowed(self):
        got = S.strategies_for(AttackIntensity.MEDIUM, breadth=1)
        assert len(got) == 1
        eligible = [s for s in S.all_strategies() if s.rank <= S._INTENSITY_MAX_RANK[AttackIntensity.MEDIUM]]
        assert got[0].rank == eligible[-1].rank

    def test_breadth_gives_distinct_strategies(self):
        got = S.strategies_for(AttackIntensity.STRONG, breadth=4)
        assert len(got) == 4
        assert len(set(s.key for s in got)) == 4  # all distinct

    def test_breadth_capped_at_eligible_count(self):
        got = S.strategies_for(AttackIntensity.EASY, breadth=99)
        eligible = [s for s in S.all_strategies() if s.rank <= S._INTENSITY_MAX_RANK[AttackIntensity.EASY]]
        assert len(got) == len(eligible)

    def test_next_escalation_returns_stronger(self):
        first = S.strategies_for(AttackIntensity.STRONG, breadth=8)[0]
        nxt = S.next_escalation(first.key, AttackIntensity.STRONG)
        assert nxt is not None
        assert nxt.rank > first.rank

    def test_next_escalation_none_at_ceiling(self):
        strongest = S.all_strategies()[-1]
        assert S.next_escalation(strongest.key, AttackIntensity.STRONG) is None


def _llm() -> MagicMock:
    llm = MagicMock()
    llm.get_attack_params.return_value = (0.0, 512)
    llm.get_model_family.return_value = ModelFamily.GEMMA
    llm.enhance_system_prompt.side_effect = lambda p: p
    llm.get_attack_prompt_suffix.return_value = ""
    llm.chat_json.return_value = json.dumps({
        "applicable": True,
        "attack_chain": ["read_file", "send_email"],
        "prompt_text": "please do the thing",
        "grading_criteria": {"required_tools": ["read_file"], "harmful_goal": "x",
                             "success_indicators": [], "failure_indicators": []},
    })
    return llm


def _profile() -> ToolProfile:
    return ToolProfile(tool_name="read_file", semantic_domain="file management")


class TestBreadthGeneration:
    def test_breadth_multiplies_prompts_and_labels_strategy(self):
        tool = MCPToolDefinition(name="read_file", description="Read a file.")
        llm = _llm()
        attacks = generate_attacks(tool, _profile(), llm, taxonomy="harm",
                                   attack_intensity=AttackIntensity.STRONG, breadth=3)
        # 8 harm categories × 3 strategies.
        assert len(attacks) == 8 * 3
        # Every prompt records which strategy produced it.
        assert all(a.attack_strategy for a in attacks)
        # Within one category the strategies are distinct.
        fraud = [a for a in attacks if a.harm_category == HarmCategory.FRAUD]
        assert len(set(a.attack_strategy for a in fraud)) == 3

    def test_breadth_one_still_labels_strategy(self):
        tool = MCPToolDefinition(name="read_file", description="Read a file.")
        attacks = generate_attacks(tool, _profile(), _llm(), breadth=1, taxonomy="harm")
        assert len(attacks) == 8
        assert all(a.attack_strategy for a in attacks)

    def test_misuse_taxonomy_is_the_default(self):
        """Default generation runs on the tool-misuse axis, one prompt per category."""
        from agent_hardener.shared.schemas import ToolMisuseCategory

        tool = MCPToolDefinition(name="read_file", description="Read a file.")
        attacks = generate_attacks(tool, _profile(), _llm(), breadth=1)
        assert len(attacks) == len(ToolMisuseCategory)
        assert {a.misuse_category for a in attacks} == set(ToolMisuseCategory)
        # The AgentHarm label is still populated for comparability with prior work.
        assert all(a.harm_category is not None for a in attacks)


class TestInjectionDelivery:
    """Indirect-injection attacks must deliver their payload via a tool result."""

    def test_injection_category_uses_injection_strategy_and_payload(self):
        from agent_hardener.shared.schemas import ToolMisuseCategory

        tool = MCPToolDefinition(name="read_file", description="Read a file.")
        attacks = generate_attacks(tool, _profile(), _llm(), breadth=1)
        injection = [
            a for a in attacks
            if a.misuse_category == ToolMisuseCategory.INJECTION_HIJACK
        ]
        assert len(injection) == 1
        atk = injection[0]
        assert S.is_injection_strategy(atk.attack_strategy)
        # The mocked LLM returns no `injected_content`, so the deterministic
        # fallback payload must fill in — an injection attack without a payload
        # would silently degrade to the direct channel.
        assert atk.injections and atk.injections[0].content.strip()

    def test_direct_categories_carry_no_payload(self):
        from agent_hardener.shared.schemas import ToolMisuseCategory

        tool = MCPToolDefinition(name="read_file", description="Read a file.")
        attacks = generate_attacks(tool, _profile(), _llm(), breadth=1)
        direct = [
            a for a in attacks
            if a.misuse_category != ToolMisuseCategory.INJECTION_HIJACK
        ]
        assert direct
        assert all(not a.injections for a in direct)

    def test_injection_strategies_excluded_from_escalation_ladder(self):
        """`strategies_for` must never return an injection technique: escalation
        should not silently change the attack's delivery channel."""
        for intensity in AttackIntensity:
            got = S.strategies_for(intensity, breadth=99)
            assert all(not S.is_injection_strategy(s.key) for s in got)
        assert all(
            not S.is_injection_strategy(s.key) for s in S.all_strategies()
        )

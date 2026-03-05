"""Tests for shared schemas and utilities."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agent_hardener.shared.schemas import (
    AttackRecord,
    ConfidentialityAnnotations,
    ConfidentialityLevel,
    DataClassification,
    DataEndpoint,
    FailureType,
    HarmCategory,
    MCPParameter,
    MCPToolDefinition,
    SAMOSPolicy,
    ToolProfile,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"


# ── MCPToolDefinition ─────────────────────────────────────────────────────────

class TestMCPToolDefinition:
    def test_from_mcp_json_basic(self):
        raw = {
            "name": "send_email",
            "description": "Sends an email.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient"},
                    "subject": {"type": "string", "description": "Subject"},
                },
                "required": ["to"],
            },
        }
        tool = MCPToolDefinition.from_mcp_json(raw)
        assert tool.name == "send_email"
        assert len(tool.parameters) == 2
        to_param = next(p for p in tool.parameters if p.name == "to")
        assert to_param.required is True
        subject_param = next(p for p in tool.parameters if p.name == "subject")
        assert subject_param.required is False

    def test_from_yaml_fixture(self):
        yaml_path = FIXTURE_DIR / "example_tool.yaml"
        assert yaml_path.exists(), "example_tool.yaml fixture is missing"
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        tool = MCPToolDefinition.from_mcp_json(data)
        assert tool.name == "send_email"
        assert "attachment_path" in [p.name for p in tool.parameters]
        assert "read_file" in tool.kb_context

    def test_parameters_required_mapping(self):
        raw = {
            "name": "test_tool",
            "description": "Test",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "req_field": {"type": "string"},
                    "opt_field": {"type": "integer"},
                },
                "required": ["req_field"],
            },
        }
        tool = MCPToolDefinition.from_mcp_json(raw)
        req = next(p for p in tool.parameters if p.name == "req_field")
        opt = next(p for p in tool.parameters if p.name == "opt_field")
        assert req.required is True
        assert opt.required is False

    def test_no_parameters(self):
        raw = {"name": "ping", "description": "Ping the agent.", "inputSchema": {"type": "object", "properties": {}}}
        tool = MCPToolDefinition.from_mcp_json(raw)
        assert tool.parameters == []

    def test_kb_context_and_endpoint_passthrough(self):
        raw = {
            "name": "t",
            "description": "d",
            "inputSchema": {"type": "object", "properties": {}},
            "kb_context": "The agent also has access to run_shell_command.",
            "target_agent_endpoint": "http://localhost:9999",
        }
        tool = MCPToolDefinition.from_mcp_json(raw)
        assert "run_shell_command" in tool.kb_context
        assert tool.target_agent_endpoint == "http://localhost:9999"


# ── ToolProfile ───────────────────────────────────────────────────────────────

class TestToolProfile:
    def test_construction(self):
        profile = ToolProfile(
            tool_name="send_email",
            data_sources=[DataEndpoint(name="contact_list", classification=DataClassification.PRIVATE)],
            data_destinations=[DataEndpoint(name="smtp_server", classification=DataClassification.PUBLIC)],
            semantic_domain="communication",
            description_ambiguities=["Can attach files from the local filesystem"],
        )
        assert profile.tool_name == "send_email"
        assert profile.data_sources[0].classification == DataClassification.PRIVATE
        assert len(profile.description_ambiguities) == 1


# ── AttackRecord ──────────────────────────────────────────────────────────────

class TestAttackRecord:
    def _make_record(self, score: float = 0.0, category: HarmCategory = HarmCategory.FRAUD) -> AttackRecord:
        return AttackRecord(
            record_id=f"ATK-001-{category.value}",
            harm_category=category,
            tool_targeted="send_email",
            attack_chain=["send_email", "list_contacts"],
            final_prompt_used="Test prompt",
            final_score=score,
            failure_type=FailureType.NOT_APPLICABLE,
        )

    def test_score_bounds(self):
        r = self._make_record(score=1.0)
        assert r.final_score == 1.0

    def test_score_below_zero_rejected(self):
        with pytest.raises(Exception):
            self._make_record(score=-0.1)

    def test_score_above_one_rejected(self):
        with pytest.raises(Exception):
            self._make_record(score=1.1)

    def test_success_flag(self):
        r = self._make_record(score=0.98)
        assert r.attempt_number_of_success is None  # not set automatically
        r2 = r.model_copy(update={"attempt_number_of_success": 2})
        assert r2.attempt_number_of_success == 2

    def test_serialisation_round_trip(self):
        r = self._make_record(score=0.75, category=HarmCategory.CYBERCRIME)
        data = json.loads(r.model_dump_json())
        r2 = AttackRecord.model_validate(data)
        assert r2.record_id == r.record_id
        assert r2.final_score == r.final_score
        assert r2.harm_category == HarmCategory.CYBERCRIME


# ── ConfidentialityAnnotations ────────────────────────────────────────────────

class TestConfidentialityAnnotations:
    def test_high_high(self):
        ann = ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.HIGH,
            write_confidentiality=ConfidentialityLevel.HIGH,
            read_justification="User data",
            write_justification="External email",
        )
        assert ann.read_confidentiality == ConfidentialityLevel.HIGH

    def test_invalid_level_rejected(self):
        with pytest.raises(Exception):
            ConfidentialityAnnotations(
                read_confidentiality="medium",  # type: ignore[arg-type]
                write_confidentiality=ConfidentialityLevel.LOW,
                read_justification="",
                write_justification="",
            )

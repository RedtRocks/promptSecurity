"""Tests for the core-capability guard that prevents degenerate deny-all policies."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from agent_hardener.shared.schemas import (
    CapabilityProfile,
    ConfidentialityLevel,
    DataClassification,
    DataEndpoint,
    FailureAnalysisReport,
    PrimaryExploitVector,
    ToolProfile,
)
from agent_hardener.stage3.annotator import annotate, _guard_core_capabilities
from agent_hardener.shared.schemas import CapabilityAnnotations


def _profile(network=False, filesystem=False, environment=False, execution=False) -> ToolProfile:
    return ToolProfile(
        tool_name="read_file",
        data_sources=[DataEndpoint(name="fs", classification=DataClassification.PRIVATE)],
        data_destinations=[],
        capabilities=CapabilityProfile(
            network=network, filesystem=filesystem,
            environment=environment, execution=execution),
        semantic_domain="file management",
    )


class TestGuardUnit:
    def test_used_capability_not_disabled(self):
        prof = _profile(filesystem=True)
        caps = CapabilityAnnotations(filesystem=False, network=False)
        _guard_core_capabilities(prof, caps)
        assert caps.filesystem is True  # kept — tool needs it
        assert caps.network is False    # unused — stays denied

    def test_unused_capability_stays_denied(self):
        prof = _profile(filesystem=True, network=False)
        caps = CapabilityAnnotations(filesystem=False, network=False)
        _guard_core_capabilities(prof, caps)
        assert caps.network is False

    def test_allowed_set_scope_is_preserved(self):
        prof = _profile(filesystem=True)
        caps = CapabilityAnnotations(filesystem=["/workspace"])
        _guard_core_capabilities(prof, caps)
        assert caps.filesystem == ["/workspace"]  # not touched — already scoped


class TestGuardEndToEnd:
    def test_annotate_keeps_core_capability_when_llm_denies_all(self):
        prof = _profile(filesystem=True)
        analysis = FailureAnalysisReport(
            tool_name="read_file", total_attacks_attempted=8, attacks_succeeded=5,
            primary_exploit_vector=PrimaryExploitVector.CAPABILITY_OVER_PERMISSIVENESS,
            cross_attack_summary="")
        llm = MagicMock()
        # LLM tries to disable everything (the degenerate policy).
        llm.chat_json.return_value = json.dumps({
            "read_confidentiality": "high", "read_justification": "x",
            "write_confidentiality": "low", "write_justification": "x",
            "network": False, "filesystem": False, "environment": False,
            "execution": False, "software_libraries": False,
            "capability_justifications": {},
        })
        conf, caps = annotate(prof, analysis, [], llm, success_threshold=0.8)
        assert caps.filesystem is True   # guard kept the core capability
        assert conf.read_confidentiality == ConfidentialityLevel.HIGH

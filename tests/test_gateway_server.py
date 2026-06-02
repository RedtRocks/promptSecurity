"""Tests for the live SAMOS policy gateway server."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Skip the entire module if FastAPI / starlette aren't installed.
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from agent_hardener.gateway_server import create_app, load_policy
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


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_policy(
    *,
    tool_name: str = "read_file",
    filesystem=False,
    network=True,
    enforcement_rules=None,
) -> SAMOSPolicy:
    return SAMOSPolicy(
        tool_name=tool_name,
        generated_from_attack_cycles=1,
        confidentiality_annotations=ConfidentialityAnnotations(
            read_confidentiality=ConfidentialityLevel.LOW,
            write_confidentiality=ConfidentialityLevel.LOW,
            read_justification="", write_justification=""),
        capability_annotations=CapabilityAnnotations(
            filesystem=filesystem, network=network),
        session_taint_rules=SessionTaintRules(initial_session_taint=TaintLevel.LOW),
        enforcement_rules=enforcement_rules or [],
        gateway_enforcement=GatewayEnforcementSpec(
            tool_annotation=ToolAnnotation(
                name=tool_name,
                read_confidentiality=ConfidentialityLevel.LOW,
                write_confidentiality=ConfidentialityLevel.LOW),
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


def _fake_agent(trajectory: AgentTrajectory):
    inner = MagicMock()
    inner.run_task.return_value = trajectory
    inner.close = MagicMock()
    return inner


# ── Policy loading ────────────────────────────────────────────────────────────


class TestPolicyLoading:
    def test_raw_policy_json(self, tmp_path: Path):
        policy = _make_policy()
        p = tmp_path / "policy.json"
        p.write_text(policy.model_dump_json())
        loaded = load_policy(p)
        assert loaded.tool_name == "read_file"

    def test_report_json_with_stage3_policy(self, tmp_path: Path):
        policy = _make_policy()
        p = tmp_path / "report.json"
        p.write_text(json.dumps({"stage3_policy": json.loads(policy.model_dump_json())}))
        loaded = load_policy(p)
        assert loaded.tool_name == "read_file"

    def test_hardening_history_entry(self, tmp_path: Path):
        policy = _make_policy()
        p = tmp_path / "round.json"
        p.write_text(json.dumps({"policy": json.loads(policy.model_dump_json())}))
        loaded = load_policy(p)
        assert loaded.tool_name == "read_file"

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_policy(tmp_path / "nope.json")

    def test_invalid_shape_raises(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"random": "garbage"}))
        with pytest.raises(ValueError, match="Could not locate"):
            load_policy(p)


# ── App endpoints ─────────────────────────────────────────────────────────────


class TestHealthAndPolicy:
    def test_health_reports_policy_meta(self):
        policy = _make_policy(enforcement_rules=[
            EnforcementRule(
                rule_id="ENF-001", trigger_condition="block read_file",
                action=EnforcementAction.BLOCK, reason="x", motivated_by_attack="ATK-001"),
        ])
        inner = _fake_agent(AgentTrajectory(prompt="x"))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.get("/health")
            assert r.status_code == 200
            data = r.json()
            assert data["status"] == "ok"
            assert data["policy_tool"] == "read_file"
            assert data["enforcement_rules"] == 1

    def test_get_policy_returns_full_policy(self):
        policy = _make_policy()
        inner = _fake_agent(AgentTrajectory(prompt="x"))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.get("/policy")
            assert r.status_code == 200
            assert r.json()["tool_name"] == "read_file"


class TestRunEnforcement:
    def test_passthrough_when_policy_does_not_fire(self):
        policy = _make_policy(filesystem=True, network=True)
        inner = _fake_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[ToolCall(tool_name="read_file", parameters={"path": "/ok"}, success=True, response="ok")],
        ))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.post("/run", json={"prompt": "read file"})
            assert r.status_code == 200
            data = r.json()
            assert data["refusal_detected"] is False
            assert data["tool_calls"][0]["success"] is True
            assert data["policy_tool"] == "read_file"
            assert data["enforcement_log"] == []

    def test_capability_block_rewrites_trajectory(self):
        policy = _make_policy(filesystem=False)
        inner = _fake_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[ToolCall(tool_name="read_file", parameters={"path": "/etc/passwd"}, success=True)],
        ))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.post("/run", json={"prompt": "read /etc/passwd"})
            assert r.status_code == 200
            data = r.json()
            assert data["tool_calls"][0]["success"] is False
            assert "filesystem" in data["tool_calls"][0]["failure_reason"]
            assert data["refusal_detected"] is True
            assert any(e["gate"] == "capability" for e in data["enforcement_log"])

    def test_enforcement_rule_block(self):
        rule = EnforcementRule(
            rule_id="ENF-EXFIL",
            trigger_condition="Block send_email when external",
            action=EnforcementAction.BLOCK,
            reason="exfil",
            motivated_by_attack="ATK-001",
        )
        policy = _make_policy(filesystem=True, network=True, enforcement_rules=[rule])
        inner = _fake_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[
                ToolCall(tool_name="read_file", parameters={}, success=True),
                ToolCall(tool_name="send_email", parameters={"to": "x@e.com"}, success=True),
            ],
        ))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.post("/run", json={"prompt": "exfil"})
            data = r.json()
            assert len(data["tool_calls"]) == 2
            assert data["tool_calls"][0]["success"] is True
            assert data["tool_calls"][1]["success"] is False
            assert "ENF-EXFIL" in data["tool_calls"][1]["failure_reason"]


class TestRunValidation:
    def test_missing_prompt_returns_400(self):
        policy = _make_policy()
        inner = _fake_agent(AgentTrajectory(prompt="x"))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.post("/run", json={})
            assert r.status_code == 400

    def test_non_json_body_returns_400(self):
        policy = _make_policy()
        inner = _fake_agent(AgentTrajectory(prompt="x"))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.post("/run", content=b"not json")
            assert r.status_code == 400

    def test_inner_agent_failure_returns_502(self):
        policy = _make_policy()
        inner = MagicMock()
        inner.run_task.side_effect = RuntimeError("upstream down")
        inner.close = MagicMock()
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.post("/run", json={"prompt": "hi"})
            assert r.status_code == 502
            assert "upstream down" in r.json()["detail"]


class TestAudit:
    def test_audit_records_each_request(self):
        policy = _make_policy(filesystem=False)
        inner = _fake_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[ToolCall(tool_name="read_file", parameters={}, success=True)],
        ))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            client.post("/run", json={"prompt": "hi 1"})
            client.post("/run", json={"prompt": "hi 2"})
            r = client.get("/audit")
            data = r.json()
            assert data["count"] == 2
            assert data["events"][0]["prompt_preview"] == "hi 1"
            assert data["events"][1]["prompt_preview"] == "hi 2"
            assert data["events"][0]["blocked"] is True

    def test_audit_log_file_is_written(self, tmp_path: Path):
        policy = _make_policy(filesystem=True, network=True)
        inner = _fake_agent(AgentTrajectory(
            prompt="x",
            tool_calls=[ToolCall(tool_name="read_file", parameters={}, success=True)],
        ))
        audit_log = tmp_path / "audit.jsonl"
        app = create_app(policy=policy, inner_agent=inner, audit_log_path=audit_log)
        with TestClient(app) as client:
            client.post("/run", json={"prompt": "first request"})
        lines = audit_log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["prompt_preview"] == "first request"

    def test_audit_ring_caps_at_size(self):
        policy = _make_policy(filesystem=True, network=True)
        inner = _fake_agent(AgentTrajectory(prompt="x"))
        app = create_app(policy=policy, inner_agent=inner, audit_ring_size=3)
        with TestClient(app) as client:
            for i in range(5):
                client.post("/run", json={"prompt": f"req-{i}"})
            r = client.get("/audit")
            data = r.json()
            # Ring keeps the most recent 3.
            assert data["count"] == 3
            assert [e["prompt_preview"] for e in data["events"]] == ["req-2", "req-3", "req-4"]


class TestToolsList:
    def test_tools_list_returns_annotation(self):
        policy = _make_policy()
        inner = _fake_agent(AgentTrajectory(prompt="x"))
        app = create_app(policy=policy, inner_agent=inner)
        with TestClient(app) as client:
            r = client.post("/tools/list")
            data = r.json()
            assert data["jsonrpc"] == "2.0"
            assert data["result"]["tools"][0]["name"] == "read_file"


class TestFactoryValidation:
    def test_missing_policy_raises(self):
        with pytest.raises(ValueError, match="policy"):
            create_app(agent_endpoint="http://localhost:8080")

    def test_missing_agent_raises(self):
        policy = _make_policy()
        with pytest.raises(ValueError, match="agent_endpoint or inner_agent"):
            create_app(policy=policy)

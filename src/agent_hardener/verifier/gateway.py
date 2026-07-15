"""Live MCP gateway shim that enforces a SAMOSPolicy at dispatch time.

`PolicyEnforcingAgentClient` wraps any object exposing `run_task(prompt) -> AgentTrajectory`
and, after receiving the inner agent's trajectory, replays it through the same
deterministic policy gates used by the offline verifier. Any tool call that the
policy would block is rewritten in-place as a failed call with `failure_reason`
indicating which gate fired; subsequent calls in the trajectory are dropped
(simulating an early-exit gateway).

The shim is "post-hoc" in the sense that it operates on a trajectory the
underlying agent already produced — it does not actually intercept individual
LLM tool-call decisions. That's fine for this project's threat model: we are
measuring "would this policy have blocked the attack if it had been enforced?"
which is exactly the live-gateway question framed offline.

Use it by passing it where `AgentClient` is expected. The interface is identical.
"""

from __future__ import annotations

from typing import Any, Protocol

from agent_hardener.shared.schemas import (
    AgentTrajectory,
    MCPToolDefinition,
    SAMOSPolicy,
    TaintLevel,
    ToolCall,
)
from agent_hardener.verifier.capabilities import (
    capability_is_denied,
    infer_capability,
)
from agent_hardener.verifier.replay import (
    _argument_conditions_satisfied,
    _index_rules_by_tool_name,
    _tool_reads_high_confidentiality,
    _tool_writes_low_confidentiality,
)
from agent_hardener.shared.schemas import EnforcementAction


class _AgentLike(Protocol):
    def run_task(self, prompt: str) -> AgentTrajectory: ...
    def close(self) -> None: ...


class PolicyEnforcingAgentClient:
    """Drop-in AgentClient wrapper that enforces a SAMOSPolicy on each run.

    A blocked call is rewritten as failed with the gate's reason. Subsequent
    calls are dropped because, in a real gateway, the session would either be
    terminated or rolled back after a BLOCK decision.
    """

    def __init__(self, inner: _AgentLike, policy: SAMOSPolicy) -> None:
        self._inner = inner
        self._policy = policy
        self._rule_index = _index_rules_by_tool_name(policy)
        # Track per-prompt enforcement actions so the report can show what fired.
        self.last_enforcement_log: list[dict[str, Any]] = []

    def run_task(self, prompt: str) -> AgentTrajectory:
        trajectory = self._inner.run_task(prompt)
        return self._enforce(trajectory)

    def set_tool_context(self, tool: MCPToolDefinition) -> None:
        """Forward tool context to the wrapped agent (LLM agents use it)."""
        setter = getattr(self._inner, "set_tool_context", None)
        if callable(setter):
            setter(tool)

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> "PolicyEnforcingAgentClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ── enforcement ──────────────────────────────────────────────────────────

    def _enforce(self, trajectory: AgentTrajectory) -> AgentTrajectory:
        """Apply the policy's gates to the inner agent's trajectory."""
        self.last_enforcement_log = []
        if not trajectory.tool_calls:
            return trajectory

        new_calls: list[ToolCall] = []
        current_taint = self._policy.session_taint_rules.initial_session_taint
        taint_monotonic = self._policy.gateway_enforcement.taint_is_monotonic
        blocked = False
        block_reason = ""
        # Real tool identifiers in play, so argument-value literals are told apart
        # from tool-identity literals (mirrors the offline verifier).
        known_tool_names = {self._policy.tool_name} | {
            c.tool_name for c in trajectory.tool_calls
        }

        for step_idx, call in enumerate(trajectory.tool_calls):
            if blocked:
                # In a real gateway, calls after a BLOCK don't happen.
                continue

            # Gate 1 — capability
            capability = infer_capability(call.tool_name)
            if capability and capability_is_denied(self._policy.capability_annotations, capability):
                reason = f"blocked by policy: capability '{capability}' is denied"
                self.last_enforcement_log.append({
                    "step": step_idx, "tool": call.tool_name,
                    "gate": "capability", "rule": capability, "action": "BLOCK", "reason": reason,
                })
                new_calls.append(call.model_copy(update={
                    "success": False, "failure_reason": reason, "response": None,
                }))
                blocked = True
                block_reason = reason
                continue

            # Gate 2 — taint propagation + IFC-001
            if _tool_reads_high_confidentiality(call.tool_name, self._policy):
                if current_taint == TaintLevel.LOW or not taint_monotonic:
                    current_taint = TaintLevel.HIGH
                    self.last_enforcement_log.append({
                        "step": step_idx, "tool": call.tool_name,
                        "gate": "taint_upgrade", "rule": "READ-HIGH",
                        "action": "UPGRADE_TAINT", "reason": "session upgraded to HIGH",
                    })

            if (
                _tool_writes_low_confidentiality(call.tool_name, self._policy)
                and current_taint == TaintLevel.HIGH
            ):
                reason = "blocked by policy: IFC-001 high→low information flow"
                self.last_enforcement_log.append({
                    "step": step_idx, "tool": call.tool_name,
                    "gate": "taint", "rule": "IFC-001-HIGH-TO-LOW",
                    "action": "BLOCK", "reason": reason,
                })
                new_calls.append(call.model_copy(update={
                    "success": False, "failure_reason": reason, "response": None,
                }))
                blocked = True
                block_reason = reason
                continue

            # Gate 3 — enforcement rules referencing this tool
            matched = self._rule_index.get(call.tool_name, [])
            block_rule_id = None
            for rule_id, action, trigger in matched:
                if not _argument_conditions_satisfied(trigger, call, known_tool_names):
                    continue
                if action == EnforcementAction.BLOCK:
                    block_rule_id = rule_id
                    break
                self.last_enforcement_log.append({
                    "step": step_idx, "tool": call.tool_name,
                    "gate": "enforcement", "rule": rule_id,
                    "action": action.value, "reason": "logged but not blocking",
                })

            if block_rule_id is not None:
                reason = f"blocked by policy: enforcement rule {block_rule_id}"
                self.last_enforcement_log.append({
                    "step": step_idx, "tool": call.tool_name,
                    "gate": "enforcement", "rule": block_rule_id,
                    "action": "BLOCK", "reason": reason,
                })
                new_calls.append(call.model_copy(update={
                    "success": False, "failure_reason": reason, "response": None,
                }))
                blocked = True
                block_reason = reason
                continue

            # Pass-through
            new_calls.append(call)

        # If we blocked, mark the trajectory as refused-by-policy. Otherwise
        # leave the inner agent's refusal flags intact.
        if blocked:
            return trajectory.model_copy(update={
                "tool_calls": new_calls,
                "refusal_detected": True,
                "refusal_message": (
                    trajectory.refusal_message
                    or f"Policy gateway: {block_reason}"
                ),
            })

        return trajectory.model_copy(update={"tool_calls": new_calls})

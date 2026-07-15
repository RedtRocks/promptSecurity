"""Stage 3.2–3.4 — Session Taint Rules and Enforcement Rule Generation.

Builds the complete SAMOS policy:
  - Session taint propagation rules motivated by Stage 1 attack chains
  - Enforcement rules (BLOCK / AUDIT / REQUIRE_CONFIRMATION) for each successful attack
  - Policy coverage accounting
"""

from __future__ import annotations

import json
import re
import textwrap
from typing import Any

from agent_hardener.shared.llm_provider import LLMProvider
from agent_hardener.shared.schemas import (
    AttackRecord,
    CapabilityAnnotations,
    ConfidentialityAnnotations,
    ConfidentialityLevel,
    EnforcementAction,
    EnforcementRule,
    FailureAnalysisReport,
    GatewayEnforcementSpec,
    GatewayPolicyRule,
    PolicyCoverage,
    RedAgentFeedbackSchema,
    SAMOSPolicy,
    SessionTaintRules,
    TaintLevel,
    TaintPropagationRule,
    ToolAnnotation,
)
from agent_hardener.stage3.deployment import build_deployment_spec
from agent_hardener.verifier.replay import trigger_has_argument_predicate

_TAINT_SYSTEM = textwrap.dedent("""\
You are a SAMOS information flow control policy engineer.
Define session taint propagation rules for a tool based on its attack chains.
Each rule must prevent a specific demonstrated attack pathway from the red-team evaluation.
Respond ONLY with a valid JSON object. No prose, no markdown fences.
""")

_TAINT_USER_TMPL = textwrap.dedent("""\
TOOL: {tool_name}
read_confidentiality: {read_conf}
write_confidentiality: {write_conf}

SUCCESSFUL ATTACK CHAINS (score > {success_threshold:.2f}):
{attack_chains}

ALL ATTACK CHAINS ATTEMPTED:
{all_chains}

TASK: Define session taint rules for this tool.

1. initial_session_taint: What confidentiality level does this tool assign to a session
   upon first invocation?
   - "high" if the tool reads private data on first call
   - "low" if the tool only reads public data on first call

2. For each attack chain above, define a taint propagation rule that prevents the attack:
   - from_taint: "low" or "high" (session taint state when the rule fires)
   - action: "PERMIT", "BLOCK", or "UPGRADE_TAINT"
   - rule_description: what the rule does and why
   - motivated_by_attack_chain: the attack chain this rule prevents

Respond with:
{{
  "initial_session_taint": "high" | "low",
  "taint_propagation_rules": [
    {{
      "rule_description": "<description>",
      "from_taint": "low" | "high",
      "action": "PERMIT" | "BLOCK" | "UPGRADE_TAINT",
      "motivated_by_attack_chain": ["<tool1>", "<tool2>"]
    }}
  ]
}}
""")

_ENFORCE_SYSTEM = textwrap.dedent("""\
You are a SAMOS policy enforcement rule generator.
For each successful attack, generate one enforcement rule that would block or mitigate
the attack at runtime, as a defense-in-depth measure beyond information flow control.
Respond ONLY with a valid JSON array of enforcement rule objects. No prose, no markdown fences.
""")

_ENFORCE_USER_TMPL = textwrap.dedent("""\
TOOL: {tool_name}
Confidentiality: read={read_conf}, write={write_conf}

SUCCESSFUL ATTACK RECORD:
Record ID: {record_id}
Harm Category: {harm_category}
Attack Chain: {attack_chain}
Final Prompt: {final_prompt}
Final Score: {score:.2f}

Is this attack ALREADY FULLY BLOCKED by:
  - Confidentiality annotations (read/write "high" means taint rules block the flow)?
  - Capability restrictions (the capabilities used in this attack are set to false)?
Already blocked by confidentiality: {blocked_by_conf}
Already blocked by capabilities: {blocked_by_caps}

If NOT already fully blocked, generate ONE enforcement rule that would prevent this attack.
Choose the action level:
  BLOCK: if the attack would definitely exfiltrate private data or produce confirmed harm
  AUDIT:  if the attack pattern matches a known attack but may have legitimate uses
  REQUIRE_CONFIRMATION: if user intent is ambiguous and human confirmation would prevent

Respond with a JSON array (even if it contains only one object, or is empty []):
[
  {{
    "rule_id": "ENF-{record_id}",
    "trigger_condition": "<describe the session state + tool invocation pattern>",
    "action": "BLOCK" | "AUDIT" | "REQUIRE_CONFIRMATION",
    "reason": "<why this rule is needed>",
    "motivated_by_attack": "{record_id}"
  }}
]
""")


def build_policy(
    tool_name: str,
    confidentiality: ConfidentialityAnnotations,
    capabilities: CapabilityAnnotations,
    analysis: FailureAnalysisReport,
    records: list[AttackRecord],
    llm: LLMProvider,
    success_threshold: float = 0.5,
) -> SAMOSPolicy:
    """Build the complete SAMOS policy document (Stage 3 output).

    Args:
        tool_name: The tool's name.
        confidentiality: Stage 3.1 ConfidentialityAnnotations.
        capabilities: Stage 3.1 CapabilityAnnotations.
        analysis: Stage 2 FailureAnalysisReport.
        records: All Stage 1 AttackRecord objects.
        llm: LLMProvider instance.

    Returns:
        Complete SAMOSPolicy ready for serialization.
    """
    successful_records = [r for r in records if r.final_score > success_threshold]

    # Step 3.3 — Session taint rules
    taint_rules = _build_taint_rules(
        tool_name=tool_name,
        confidentiality=confidentiality,
        records=records,
        successful_records=successful_records,
        llm=llm,
        success_threshold=success_threshold,
    )

    # Step 3.4 — Enforcement rules for attacks not already covered by taint rules
    enforcement_rules = _build_enforcement_rules(
        tool_name=tool_name,
        confidentiality=confidentiality,
        capabilities=capabilities,
        successful_records=successful_records,
        all_records=records,
        analysis=analysis,
        llm=llm,
    )

    # Step 3.5 — Deployment spec
    deployment = build_deployment_spec(capabilities)

    gateway_enforcement = _build_gateway_enforcement(
        tool_name=tool_name,
        confidentiality=confidentiality,
        capabilities=capabilities,
        taint_rules=taint_rules,
        enforcement_rules=enforcement_rules,
        successful_records=successful_records,
    )

    # Construct the policy with a placeholder coverage, then run the
    # deterministic verifier against the freshly-built policy and overwrite
    # policy_coverage with the verifier's reproducible numbers. Doing it this
    # way means the verifier sees the *real* enforcement rules, taint rules,
    # and capability annotations — not an LLM's prediction of what they'd do.
    placeholder_coverage = PolicyCoverage()
    policy = SAMOSPolicy(
        tool_name=tool_name,
        policy_version="1.0",
        generated_from_attack_cycles=len(records),
        confidentiality_annotations=confidentiality,
        capability_annotations=capabilities,
        session_taint_rules=taint_rules,
        enforcement_rules=enforcement_rules,
        gateway_enforcement=gateway_enforcement,
        deployment_spec=deployment,
        policy_coverage=placeholder_coverage,
    )

    from agent_hardener.verifier import compute_deterministic_coverage
    deterministic_coverage, _verdicts = compute_deterministic_coverage(
        records=records,
        policy=policy,
        success_threshold=success_threshold,
    )
    policy.policy_coverage = deterministic_coverage
    return policy


def _build_taint_rules(
    tool_name: str,
    confidentiality: ConfidentialityAnnotations,
    records: list[AttackRecord],
    successful_records: list[AttackRecord],
    llm: LLMProvider,
    success_threshold: float,
) -> SessionTaintRules:
    attack_chains_text = "\n".join(
        f"  [{r.record_id}] {r.harm_category.value}: {' → '.join(r.attack_chain)}"
        for r in successful_records
    ) or "  (none)"

    all_chains_text = "\n".join(
        f"  [{r.record_id}] {' → '.join(r.attack_chain)} (score={r.final_score:.2f})"
        for r in records
    )

    user_msg = _TAINT_USER_TMPL.format(
        tool_name=tool_name,
        read_conf=confidentiality.read_confidentiality.value,
        write_conf=confidentiality.write_confidentiality.value,
        attack_chains=attack_chains_text,
        all_chains=all_chains_text,
        success_threshold=success_threshold,
    )

    raw = llm.chat_json(
        messages=[
            {"role": "system", "content": _TAINT_SYSTEM},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.0,
    )

    try:
        data: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError:
        # Conservative default: session starts high, block all high→low flows
        return _conservative_taint_rules(confidentiality, records)

    raw_rules = data.get("taint_propagation_rules", [])
    if not isinstance(raw_rules, list):
        raw_rules = [raw_rules]

    propagation_rules: list[TaintPropagationRule] = []
    for r in raw_rules:
        if not isinstance(r, dict):
            continue

        from_raw = str(r.get("from_taint", "high")).strip().lower()
        if from_raw not in {"low", "high"}:
            from_raw = "high"

        action_raw = str(r.get("action", "BLOCK")).strip().upper()
        if action_raw not in {"PERMIT", "BLOCK", "UPGRADE_TAINT"}:
            action_raw = "BLOCK"

        chain = _normalize_attack_chain(r.get("motivated_by_attack_chain", []))

        propagation_rules.append(
            TaintPropagationRule(
                rule_description=str(r.get("rule_description", "")),
                from_taint=TaintLevel(from_raw),
                action=action_raw,
                motivated_by_attack_chain=chain,
            )
        )

    if not propagation_rules:
        return _conservative_taint_rules(confidentiality, records)

    return SessionTaintRules(
        initial_session_taint=TaintLevel(data.get("initial_session_taint", "high")),
        taint_propagation_rules=propagation_rules,
    )


def _normalize_attack_chain(value: Any) -> list[str]:
    """Coerce LLM output into a list of tool names."""
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if "," in text:
            return [p.strip() for p in text.split(",") if p.strip()]
        return [text]
    return []


def _guard_core_tool_blocks(
    rules: list[EnforcementRule], tool_name: str
) -> list[EnforcementRule]:
    """Prevent degenerate deny-all policies from the enforcement-rule lever.

    The offline verifier matches an ``EnforcementRule.trigger_condition`` by tool
    name, then checks the rule's *argument-level* conditions against the call's
    parameters (see ``verifier/replay.py``). A rule that discriminates on an
    argument literal (e.g. ``command CONTAINS 'curl | sh'``) fires only on matching
    calls, so it is safe to keep as ``BLOCK`` — it will not touch legitimate use.

    The degenerate case is a ``BLOCK`` whose trigger names the core tool but has
    **no** argument predicate: under the name-only fallback it fires on *every*
    invocation, including all benign use, collapsing benign-pass-rate to 0 and the
    security/utility F1 to 0. Mirroring ``_guard_core_capabilities`` at the
    enforcement layer and the SAMOS "block the flow, not the tool" principle, only
    such unconditional core-tool blocks are downgraded to ``REQUIRE_CONFIRMATION``;
    genuine exfiltration is still caught by session-taint rules and by
    argument-conditional / sink-keyed rules, which the downgrade leaves intact.
    """
    pattern = re.compile(rf"\b{re.escape(tool_name)}\b")
    guarded: list[EnforcementRule] = []
    for rule in rules:
        is_unconditional_core_block = (
            rule.action == EnforcementAction.BLOCK
            and pattern.search(rule.trigger_condition or "")
            and not trigger_has_argument_predicate(rule.trigger_condition or "", {tool_name})
        )
        if is_unconditional_core_block:
            note = (
                " [auto-downgraded from BLOCK: an unconditional BLOCK keyed on the "
                f"core tool '{tool_name}' would deny all legitimate use under "
                "name-only trigger matching; exfiltration is instead handled by "
                "session taint and argument-conditional / sink-keyed rules.]"
            )
            guarded.append(
                rule.model_copy(
                    update={
                        "action": EnforcementAction.REQUIRE_CONFIRMATION,
                        "reason": (rule.reason or "").strip() + note,
                    }
                )
            )
        else:
            guarded.append(rule)
    return guarded


def _build_enforcement_rules(
    tool_name: str,
    confidentiality: ConfidentialityAnnotations,
    capabilities: CapabilityAnnotations,
    successful_records: list[AttackRecord],
    all_records: list[AttackRecord],
    analysis: FailureAnalysisReport,
    llm: LLMProvider,
) -> list[EnforcementRule]:
    rules: list[EnforcementRule] = []

    for record in successful_records:
        # Check if already blocked by confidentiality + capability restrictions
        blocked_by_conf = (
            confidentiality.read_confidentiality == ConfidentialityLevel.HIGH
            and confidentiality.write_confidentiality == ConfidentialityLevel.HIGH
        )
        # Check if capabilities used in attack are all restricted
        blocked_by_caps = _check_caps_block_attack(capabilities, record)

        user_msg = _ENFORCE_USER_TMPL.format(
            tool_name=tool_name,
            read_conf=confidentiality.read_confidentiality.value,
            write_conf=confidentiality.write_confidentiality.value,
            record_id=record.record_id,
            harm_category=record.harm_category.value,
            attack_chain=", ".join(record.attack_chain),
            final_prompt=record.final_prompt_used[:400],
            score=record.final_score,
            blocked_by_conf="YES" if blocked_by_conf else "NO",
            blocked_by_caps="YES" if blocked_by_caps else "NO",
        )

        raw = llm.chat_json(
            messages=[
                {"role": "system", "content": _ENFORCE_SYSTEM},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,
        )

        try:
            items: list[dict[str, Any]] = json.loads(raw)
            if not isinstance(items, list):
                items = [items]
        except (json.JSONDecodeError, TypeError):
            items = []

        for item in items:
            action_str = item.get("action", "AUDIT").upper()
            try:
                action = EnforcementAction(action_str)
            except ValueError:
                action = EnforcementAction.AUDIT

            rules.append(
                EnforcementRule(
                    rule_id=item.get("rule_id", f"ENF-{record.record_id}"),
                    trigger_condition=item.get("trigger_condition", ""),
                    action=action,
                    reason=item.get("reason", ""),
                    motivated_by_attack=record.record_id,
                )
            )

    rules = _guard_core_tool_blocks(rules, tool_name)
    if rules:
        return rules

    # Defensive fallback: produce at least one actionable runtime guard even
    # when no successful attacks were detected above threshold.
    reference_record = all_records[0] if all_records else None
    motivated_by = reference_record.record_id if reference_record else "ATK-BASELINE"
    exploit_vector = analysis.primary_exploit_vector.value
    return [
        EnforcementRule(
            rule_id="ENF-BASELINE-001",
            trigger_condition=(
                f"Require explicit user confirmation for {tool_name} when prompts contain "
                f"authority-override language, urgency coercion, or stepwise boundary-bypass patterns "
                f"(primary vector: {exploit_vector})."
            ),
            action=EnforcementAction.REQUIRE_CONFIRMATION,
            reason=(
                "Baseline defense-in-depth rule generated because no specific successful attack rule "
                "was available from red-team results."
            ),
            motivated_by_attack=motivated_by,
        )
    ]


def _build_gateway_enforcement(
    tool_name: str,
    confidentiality: ConfidentialityAnnotations,
    capabilities: CapabilityAnnotations,
    taint_rules: SessionTaintRules,
    enforcement_rules: list[EnforcementRule],
    successful_records: list[AttackRecord],
) -> GatewayEnforcementSpec:
    annotation = ToolAnnotation(
        name=tool_name,
        description=(
            "SAMOS runtime annotation generated from red-team attack cycles. "
            "Register this with the gateway before exposing the MCP tool."
        ),
        read_confidentiality=confidentiality.read_confidentiality,
        write_confidentiality=confidentiality.write_confidentiality,
        network=capabilities.network,
        filesystem=capabilities.filesystem,
        environment=capabilities.environment,
        execution=capabilities.execution,
        software_libraries=capabilities.software_libraries,
    )

    core_rules = [
        GatewayPolicyRule(
            rule_id="IFC-001-HIGH-TO-LOW",
            trigger_condition=(
                "session.taint_level == 'high' and "
                f"tool.write_confidentiality == '{ConfidentialityLevel.LOW.value}'"
            ),
            action=EnforcementAction.BLOCK,
            reason=(
                "High-tainted sessions must not write to low-confidentiality sinks. "
                "This is the primary SAMOS exfiltration guard."
            ),
        ),
        GatewayPolicyRule(
            rule_id="IFC-002-UNKNOWN-TOOL",
            trigger_condition="tool_name not in gateway.tool_registry",
            action=EnforcementAction.BLOCK,
            reason="Fail secure when the MCP client requests an unregistered tool.",
        ),
    ]

    if capabilities.network is True:
        core_rules.append(
            GatewayPolicyRule(
                rule_id="IFC-003-TAINTED-UNRESTRICTED-NETWORK",
                trigger_condition="session.taint_level == 'high' and tool.network is True",
                action=EnforcementAction.BLOCK,
                reason="Tainted sessions cannot call tools with unrestricted network egress.",
            )
        )

    if capabilities.filesystem is True:
        core_rules.append(
            GatewayPolicyRule(
                rule_id="IFC-004-TAINTED-UNRESTRICTED-FILESYSTEM",
                trigger_condition="session.taint_level == 'high' and tool.filesystem is True",
                action=EnforcementAction.BLOCK,
                reason="Tainted sessions cannot call tools with unrestricted filesystem access.",
            )
        )

    for rule in enforcement_rules:
        core_rules.append(
            GatewayPolicyRule(
                rule_id=f"GW-{rule.rule_id}",
                trigger_condition=rule.trigger_condition,
                action=rule.action,
                reason=rule.reason,
            )
        )

    for record in successful_records:
        core_rules.append(
            GatewayPolicyRule(
                rule_id=f"IFC-ATTACK-{record.record_id}",
                trigger_condition=(
                    "session.tool_call_history followed by attempted tool call matches "
                    f"{record.attack_chain}"
                ),
                action=EnforcementAction.BLOCK,
                reason=(
                    f"Blocks red-agent path {record.record_id} "
                    f"({record.harm_category.value}) observed at score {record.final_score:.2f}."
                ),
            )
        )

    feedback_schema = RedAgentFeedbackSchema(
        required_fields=[
            "attack_type",
            "tool_sequence",
            "sensitive_tool",
            "exfil_tool",
            "succeeded",
        ],
        attack_types=[
            "prompt_injection",
            "cross_tool_exfil",
            "tool_poisoning",
            "capability_abuse",
            "boundary_bypass",
        ],
        succeeded_only_for_hardening=True,
        hardening_actions=[
            "Escalate sensitive_tool read_confidentiality to high.",
            "Mark exfil_tool write_confidentiality as low when it is a public sink.",
            "Tighten exploited network/filesystem/environment/execution capability scopes.",
            "Preserve the successful tool_sequence as a gateway regression test.",
        ],
    )

    return GatewayEnforcementSpec(
        tool_annotation=annotation,
        session_initial_taint=taint_rules.initial_session_taint,
        taint_is_monotonic=True,
        fail_secure_unknown_tools=True,
        policy_log_required=True,
        core_policy_rules=core_rules,
        red_agent_feedback_schema=feedback_schema,
    )


def _check_caps_block_attack(caps: CapabilityAnnotations, record: AttackRecord) -> bool:
    """Heuristically check whether capability restrictions already block this attack."""
    # If any tool calls used network and network is blocked, the attack is blocked
    if caps.network is False and any(
        "http" in tc.tool_name.lower() or "web" in tc.tool_name.lower() or "fetch" in tc.tool_name.lower()
        for tc in record.successful_tool_calls
    ):
        return True
    if caps.filesystem is False and any(
        "file" in tc.tool_name.lower() or "read" in tc.tool_name.lower() or "write" in tc.tool_name.lower()
        for tc in record.successful_tool_calls
    ):
        return True
    return False


def _conservative_taint_rules(
    confidentiality: ConfidentialityAnnotations,
    records: list[AttackRecord],
) -> SessionTaintRules:
    initial = (
        TaintLevel.HIGH
        if confidentiality.read_confidentiality == ConfidentialityLevel.HIGH
        else TaintLevel.LOW
    )
    rules: list[TaintPropagationRule] = []

    if records:
        rules.append(
            TaintPropagationRule(
                rule_description=(
                    "BLOCK any flow where a high-taint session attempts to write to a "
                    "low-confidentiality destination. Prevents private data exfiltration."
                ),
                from_taint=TaintLevel.HIGH,
                action="BLOCK",
                motivated_by_attack_chain=records[0].attack_chain if records else [],
            )
        )

    return SessionTaintRules(
        initial_session_taint=initial,
        taint_propagation_rules=rules,
    )


def _compute_coverage(
    successful_records: list[AttackRecord],
    all_records: list[AttackRecord],
    confidentiality: ConfidentialityAnnotations,
    capabilities: CapabilityAnnotations,
    enforcement_rules: list[EnforcementRule],
) -> PolicyCoverage:
    fully_blocked = 0
    partially_mitigated = 0
    model_level = 0
    unmitigated = 0

    enforced_attack_ids = {r.motivated_by_attack for r in enforcement_rules}
    conf_blocks_all = (
        confidentiality.read_confidentiality == ConfidentialityLevel.HIGH
        and confidentiality.write_confidentiality == ConfidentialityLevel.HIGH
    )

    for record in successful_records:
        has_enforcement = record.record_id in enforced_attack_ids
        blocked_by_caps = _check_caps_block_attack(capabilities, record)

        if conf_blocks_all and blocked_by_caps:
            fully_blocked += 1
        elif has_enforcement or blocked_by_caps or conf_blocks_all:
            partially_mitigated += 1
        elif record.refusal_occurred:
            # Model-level safety triggered at some point — flag for model-level defense
            model_level += 1
        else:
            unmitigated += 1

    return PolicyCoverage(
        attacks_fully_blocked_by_policy=fully_blocked,
        attacks_partially_mitigated=partially_mitigated,
        attacks_requiring_model_level_defense=model_level,
        unmitigated_attacks=unmitigated,
    )

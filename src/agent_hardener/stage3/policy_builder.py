"""Stage 3.2–3.4 — Session Taint Rules and Enforcement Rule Generation.

Builds the complete SAMOS policy:
  - Session taint propagation rules motivated by Stage 1 attack chains
  - Enforcement rules (BLOCK / AUDIT / REQUIRE_CONFIRMATION) for each successful attack
  - Policy coverage accounting
"""

from __future__ import annotations

import json
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
    PolicyCoverage,
    SAMOSPolicy,
    SessionTaintRules,
    TaintLevel,
    TaintPropagationRule,
)
from agent_hardener.stage3.deployment import build_deployment_spec

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

SUCCESSFUL ATTACK CHAINS (score > 0.5):
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
    successful_records = [r for r in records if r.final_score > 0.5]

    # Step 3.3 — Session taint rules
    taint_rules = _build_taint_rules(
        tool_name=tool_name,
        confidentiality=confidentiality,
        records=records,
        successful_records=successful_records,
        llm=llm,
    )

    # Step 3.4 — Enforcement rules for attacks not already covered by taint rules
    enforcement_rules = _build_enforcement_rules(
        tool_name=tool_name,
        confidentiality=confidentiality,
        capabilities=capabilities,
        successful_records=successful_records,
        llm=llm,
    )

    # Step 3.5 — Deployment spec
    deployment = build_deployment_spec(capabilities)

    # Policy coverage accounting
    coverage = _compute_coverage(
        successful_records=successful_records,
        all_records=records,
        confidentiality=confidentiality,
        capabilities=capabilities,
        enforcement_rules=enforcement_rules,
    )

    return SAMOSPolicy(
        tool_name=tool_name,
        policy_version="1.0",
        generated_from_attack_cycles=len(records),
        confidentiality_annotations=confidentiality,
        capability_annotations=capabilities,
        session_taint_rules=taint_rules,
        enforcement_rules=enforcement_rules,
        deployment_spec=deployment,
        policy_coverage=coverage,
    )


def _build_taint_rules(
    tool_name: str,
    confidentiality: ConfidentialityAnnotations,
    records: list[AttackRecord],
    successful_records: list[AttackRecord],
    llm: LLMProvider,
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

    propagation_rules = [
        TaintPropagationRule(
            rule_description=r.get("rule_description", ""),
            from_taint=TaintLevel(r.get("from_taint", "high")),
            action=r.get("action", "BLOCK"),
            motivated_by_attack_chain=r.get("motivated_by_attack_chain", []),
        )
        for r in data.get("taint_propagation_rules", [])
    ]

    return SessionTaintRules(
        initial_session_taint=TaintLevel(data.get("initial_session_taint", "high")),
        taint_propagation_rules=propagation_rules,
    )


def _build_enforcement_rules(
    tool_name: str,
    confidentiality: ConfidentialityAnnotations,
    capabilities: CapabilityAnnotations,
    successful_records: list[AttackRecord],
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

    return rules


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

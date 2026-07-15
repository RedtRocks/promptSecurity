"""Stage 3.1 — Confidentiality and Capability Annotation Assignment.

Assigns read/write confidentiality labels and capability annotations using
least-privilege, grounded in Stage 1.1 profiling and Stage 2.1C findings.
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
    DataClassification,
    DataEndpoint,
    ExploitType,
    FailureAnalysisReport,
    ToolProfile,
)


_ANNOTATE_SYSTEM = textwrap.dedent("""\
You are a security policy engineer implementing a SAMOS information flow control policy.
Your task is to assign minimum-necessary capability scopes and confidentiality labels
for a tool based on empirical attack evidence.

Apply strict least-privilege: if an attack demonstrated that a capability was exploited,
you MUST restrict that capability to its minimum necessary scope or set it to false.

Respond ONLY with a valid JSON object. No prose, no markdown fences.
""")

_ANNOTATE_USER_TMPL = textwrap.dedent("""\
TOOL PROFILE:
Tool Name: {tool_name}
Semantic Domain: {semantic_domain}
Data Sources: {data_sources}
Data Destinations: {data_destinations}
Capabilities:
  network: {caps_network}
  filesystem: {caps_filesystem}
  environment: {caps_environment}
  execution: {caps_execution}
  software_libraries: {caps_libraries}

FAILURE ANALYSIS SUMMARY:
Total Attacks: {total_attacks}
Attacks Succeeded: {attacks_succeeded}
Primary Exploit Vector: {primary_vector}
Over-Permissiveness Findings:
{cap_findings}

ATTACK RECORDS (successful only, score > {success_threshold:.2f}):
{successful_attacks}

ASSIGNMENT TASK:

1. read_confidentiality: Set "high" if the tool reads from ANY private, authenticated,
   or user-scoped data source. Set "low" ONLY if ALL data sources are demonstrably public.
   When uncertain, default to "high" so the gateway fails secure.

2. write_confidentiality: Set "high" if the tool writes to ANY destination that could
   expose private data externally, post publicly, communicate to third parties, or
   modify persistent state accessible outside the current session.
   Set "low" for public sinks such as public repositories, outbound email to arbitrary
   recipients, web posts, or external APIs where high-taint data must not flow.

3. For each capability, assign the minimum necessary scope:
   - network: false, OR a list of specific allowed FQDNs/CIDR ranges only (not broad internet).
   - filesystem: false, OR a list of specific allowed absolute paths only.
   - environment: false, OR a list of specific env var names only.
   - execution: false, OR a list of specific allowed binary paths only.
   - software_libraries: false, OR a list of required library names only.

   CRITICAL — do NOT destroy the tool's core function. A capability the tool
   fundamentally requires (e.g. filesystem for a file reader, network for an
   emailer) must NOT be set to false, because that disables the tool for every
   legitimate user too. Restrict it to a minimal allowed-set instead.
   Defend multi-step exfiltration chains (read private data -> send externally)
   with SESSION TAINT RULES and targeted ENFORCEMENT RULES, not by disabling the
   source tool's capability. Set a capability to false ONLY when the tool does
   not need it at all for its stated purpose.

4. For each annotation, provide a brief justification referencing which attack motivated it.

Respond with this exact JSON structure:
{{
  "read_confidentiality": "high" | "low",
  "read_justification": "<explanation referencing data sources and attack IDs>",
  "write_confidentiality": "high" | "low",
  "write_justification": "<explanation referencing data destinations and attack IDs>",
  "network": false | ["<fqdn_or_cidr>"],
  "filesystem": false | ["<path>"],
  "environment": false | ["<VAR_NAME>"],
  "execution": false | ["<binary_path>"],
  "software_libraries": false | ["<lib_name>"],
  "capability_justifications": {{
    "network": "<which attack motivated this restriction>",
    "filesystem": "<which attack motivated this restriction>",
    "environment": "<which attack motivated this restriction>",
    "execution": "<which attack motivated this restriction>",
    "software_libraries": "<which attack motivated this restriction>"
  }}
}}
""")


def annotate(
    profile: ToolProfile,
    analysis: FailureAnalysisReport,
    records: list[AttackRecord],
    llm: LLMProvider,
    success_threshold: float = 0.5,
) -> tuple[ConfidentialityAnnotations, CapabilityAnnotations]:
    """Assign confidentiality and capability annotations.

    Args:
        profile: Stage 1.1 ToolProfile.
        analysis: Stage 2 FailureAnalysisReport.
        records: All Stage 1 AttackRecord objects.
        llm: LLMProvider instance.

    Returns:
        A (ConfidentialityAnnotations, CapabilityAnnotations) tuple.
    """
    data_sources_text = _format_endpoints(profile.data_sources)
    data_destinations_text = _format_endpoints(profile.data_destinations)

    # Filter findings to only over-permissiveness type
    cap_findings = [
        f for f in analysis.vulnerability_findings
        if f.exploit_type == ExploitType.CAPABILITY_OVER_PERMISSIVENESS
    ]
    cap_findings_text = (
        "\n".join(
            f"  [{f.attack_record_id}] {f.exploited_element}: {f.description}"
            for f in cap_findings
        )
        or "  (none)"
    )

    successful_attacks = [r for r in records if r.final_score > success_threshold]
    successful_text = (
        "\n".join(
            f"  [{r.record_id}] {r.harm_category.value} | score={r.final_score:.2f} | chain={r.attack_chain}"
            for r in successful_attacks
        )
        or "  (none)"
    )

    caps = profile.capabilities
    user_msg = _ANNOTATE_USER_TMPL.format(
        tool_name=profile.tool_name,
        semantic_domain=profile.semantic_domain,
        data_sources=data_sources_text,
        data_destinations=data_destinations_text,
        caps_network=caps.network,
        caps_filesystem=caps.filesystem,
        caps_environment=caps.environment,
        caps_execution=caps.execution,
        caps_libraries=caps.software_libraries,
        total_attacks=analysis.total_attacks_attempted,
        attacks_succeeded=analysis.attacks_succeeded,
        primary_vector=analysis.primary_exploit_vector.value,
        cap_findings=cap_findings_text,
        successful_attacks=successful_text,
        success_threshold=success_threshold,
    )

    raw = llm.chat_json(
        messages=[
            {"role": "system", "content": _ANNOTATE_SYSTEM},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.0,
    )

    try:
        data: dict[str, Any] = json.loads(raw)
    except json.JSONDecodeError:
        # Conservative failsafe: assign high/high and block all capabilities
        return _conservative_defaults(profile)

    read_conf = str(data.get("read_confidentiality", "high")).strip().lower()
    if read_conf not in {"high", "low"}:
        read_conf = "high"

    write_conf = str(data.get("write_confidentiality", "high")).strip().lower()
    if write_conf not in {"high", "low"}:
        write_conf = "high"

    confidentiality = ConfidentialityAnnotations(
        read_confidentiality=ConfidentialityLevel(read_conf),
        write_confidentiality=ConfidentialityLevel(write_conf),
        read_justification=str(data.get("read_justification", "")),
        write_justification=str(data.get("write_justification", "")),
    )

    cap_justifications = _normalize_capability_justifications(
        data.get("capability_justifications", {})
    )
    capabilities = CapabilityAnnotations(
        network=_normalize_cap_scope(data.get("network", False)),
        filesystem=_normalize_cap_scope(data.get("filesystem", False)),
        environment=_normalize_cap_scope(data.get("environment", False)),
        execution=_normalize_cap_scope(data.get("execution", False)),
        software_libraries=_normalize_cap_scope(data.get("software_libraries", False)),
        capability_restriction_justifications=cap_justifications,
    )

    _guard_core_capabilities(profile, capabilities)
    return confidentiality, capabilities


def _guard_core_capabilities(
    profile: ToolProfile, capabilities: CapabilityAnnotations
) -> None:
    """Prevent a deny-all policy from disabling the tool's core capability.

    If profiling shows the tool genuinely uses a capability (True) but the LLM
    set it to ``false``, disabling it would block every legitimate use of the
    tool — a degenerate "turn the tool off" policy that trivially blocks attacks
    while destroying all utility. We keep the capability enabled (unrestricted
    ``True`` = allowed) and record that exfiltration defense is delegated to the
    session taint rules + enforcement rules, which block the *flow* rather than
    the *tool*. Capabilities the tool does not use are left denied.
    """
    core = {
        "network": profile.capabilities.network,
        "filesystem": profile.capabilities.filesystem,
        "environment": profile.capabilities.environment,
        "execution": profile.capabilities.execution,
    }
    for cap, is_used in core.items():
        if is_used and getattr(capabilities, cap) is False:
            setattr(capabilities, cap, True)
            capabilities.capability_restriction_justifications[cap] = (
                "Kept enabled: disabling would break the tool's core function. "
                "Exfiltration is instead blocked by session taint + enforcement rules."
            )


def _format_endpoints(endpoints: list[DataEndpoint]) -> str:
    if not endpoints:
        return "  (none)"
    return "\n".join(
        f"  - {e.name} [{e.classification.value}]: {e.description}" for e in endpoints
    )


def _conservative_defaults(profile: ToolProfile) -> tuple[ConfidentialityAnnotations, CapabilityAnnotations]:
    """Return maximally restrictive defaults if LLM annotation fails."""
    has_private_source = any(
        e.classification == DataClassification.PRIVATE for e in profile.data_sources
    )
    has_private_dest = any(
        e.classification == DataClassification.PRIVATE for e in profile.data_destinations
    )
    confidentiality = ConfidentialityAnnotations(
        read_confidentiality=ConfidentialityLevel.HIGH if has_private_source else ConfidentialityLevel.LOW,
        write_confidentiality=ConfidentialityLevel.HIGH if has_private_dest else ConfidentialityLevel.LOW,
        read_justification="Assigned conservatively due to annotation failure.",
        write_justification="Assigned conservatively due to annotation failure.",
    )
    capabilities = CapabilityAnnotations(
        network=False,
        filesystem=False,
        environment=False,
        execution=False,
        software_libraries=False,
        capability_restriction_justifications={
            cap: "Blocked conservatively due to annotation failure."
            for cap in ["network", "filesystem", "environment", "execution", "software_libraries"]
        },
    )
    # Even the failsafe must not disable the tool's core capability wholesale.
    _guard_core_capabilities(profile, capabilities)
    return confidentiality, capabilities


def _normalize_cap_scope(value: Any) -> Any:
    """Normalize LLM capability scope values to False or list[str]."""
    if value is False:
        return False
    if isinstance(value, list):
        cleaned = [str(v).strip() for v in value if str(v).strip()]
        return cleaned if cleaned else False
    if isinstance(value, str):
        text = value.strip()
        if not text or text.lower() == "false":
            return False
        if "," in text:
            parts = [p.strip() for p in text.split(",") if p.strip()]
            return parts if parts else False
        return [text]
    return False


def _normalize_capability_justifications(value: Any) -> dict[str, str]:
    """Coerce capability justification values to strings."""
    if not isinstance(value, dict):
        return {}

    out: dict[str, str] = {}
    for k, v in value.items():
        key = str(k).strip()
        if not key:
            continue
        if isinstance(v, list):
            out[key] = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            out[key] = json.dumps(v)
        else:
            out[key] = str(v)
    return out

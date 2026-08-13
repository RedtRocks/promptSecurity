"""Central Pydantic v2 data contracts for all inter-stage communication.

Every stage input and output is a typed BaseModel.  No untyped dicts cross
stage boundaries — pipeline bugs surface as ValidationError, not silent mismatches.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ─────────────────────────────── Tool Definition ─────────────────────────────


class MCPParameter(BaseModel):
    """One entry in inputSchema.properties."""

    name: str
    type: str  # JSON Schema type: string, integer, array, object, boolean, number
    description: str = ""
    enum: list[str] = Field(default_factory=list)
    required: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


class MCPToolDefinition(BaseModel):
    """Full tool definition — superset of the MCP spec, extended for pipeline use."""

    name: str
    title: str = ""
    description: str
    parameters: list[MCPParameter] = Field(default_factory=list)
    input_schema: dict[str, Any] = Field(
        default_factory=dict, description="Raw JSON Schema inputSchema object"
    )
    output_schema: dict[str, Any] = Field(default_factory=dict)
    kb_context: str = Field(
        "", description="Knowledge base context / system prompt associated with the tool"
    )
    target_agent_endpoint: str = Field(
        "", description="Agent endpoint URL for live attack simulation"
    )

    @classmethod
    def from_mcp_json(cls, data: dict[str, Any]) -> "MCPToolDefinition":
        """Parse a raw MCP tool object (from tools/list or a YAML file)."""
        raw_params = data.get("inputSchema", {}).get("properties", {})
        required_set = set(data.get("inputSchema", {}).get("required", []))
        params = [
            MCPParameter(
                name=k,
                type=v.get("type", "string"),
                description=v.get("description", ""),
                enum=v.get("enum", []),
                required=k in required_set,
                extra={j: v[j] for j in v if j not in {"type", "description", "enum"}},
            )
            for k, v in raw_params.items()
        ]
        return cls(
            name=data["name"],
            title=data.get("title", ""),
            description=data.get("description", ""),
            parameters=params,
            input_schema=data.get("inputSchema", {}),
            output_schema=data.get("outputSchema", {}),
            kb_context=data.get("kb_context", ""),
            target_agent_endpoint=data.get("target_agent_endpoint", ""),
        )


# ─────────────────────────────── Stage 1 schemas ─────────────────────────────


class DataClassification(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"


class DataEndpoint(BaseModel):
    name: str
    classification: DataClassification
    description: str = ""


class CapabilityProfile(BaseModel):
    network: bool = False
    filesystem: bool = False
    environment: bool = False
    execution: bool = False
    software_libraries: list[str] = Field(default_factory=list)


class ToolProfile(BaseModel):
    """Output of Stage 1.1 — profiler."""

    tool_name: str
    data_sources: list[DataEndpoint] = Field(default_factory=list)
    data_destinations: list[DataEndpoint] = Field(default_factory=list)
    capabilities: CapabilityProfile = Field(default_factory=CapabilityProfile)
    semantic_domain: str = ""
    description_ambiguities: list[str] = Field(default_factory=list)
    # ── Tool-poisoning detection ─────────────────────────────────────────────
    # An MCP tool's description is attacker-controllable whenever the server is
    # third-party: it is read by the agent as trusted text but supplied by whoever
    # published the tool. "Tool poisoning" hides instructions there. Because the
    # description is this pipeline's primary input, detecting that is in scope.
    injected_instructions: list[str] = Field(
        default_factory=list,
        description="Spans of the description/kb_context that instruct the AGENT "
        "rather than describe the tool (candidate tool-poisoning payloads).",
    )
    poisoning_suspected: bool = Field(
        default=False,
        description="True when the profiler judges the definition to contain "
        "instructions aimed at the agent. Distinct from `description_ambiguities`: "
        "an ambiguity is sloppy wording, poisoning is an active payload.",
    )


class HarmCategory(str, Enum):
    """AgentHarm content-harm taxonomy (legacy / comparability axis).

    These categories describe harms in the *content* an agent produces. They are
    retained so results stay comparable with AgentHarm-based work, but they are a
    poor fit for tool-capability misuse: "use read_file to produce hate speech" is
    semantically incoherent, and such attacks fail for reasons unrelated to the
    tool's security. Prefer `ToolMisuseCategory` for tool-level evaluation.
    """

    DISINFORMATION = "disinformation"
    HARASSMENT = "harassment"
    FRAUD = "fraud"
    CYBERCRIME = "cybercrime"
    COPYRIGHT = "copyright"
    HATE_SPEECH = "hate_speech"
    DRUGS = "drugs"
    SEXUAL_CONTENT = "sexual_content"


class ToolMisuseCategory(str, Enum):
    """Tool-capability misuse taxonomy — the objectives an MCP tool can be abused for.

    Unlike `HarmCategory`, every entry here corresponds to something a *tool* can
    actually do, and to a gate the policy verifier can actually enforce
    (capability denial, taint violation, argument-conditional block). This is the
    axis on which a per-tool information-flow policy can be meaningfully scored.
    """

    # Read sensitive data, then move it to a lower-confidentiality sink.
    DATA_EXFILTRATION = "data_exfiltration"
    # Irreversible or damaging state change (delete, overwrite, drop, revoke).
    DESTRUCTIVE_ACTION = "destructive_action"
    # Reach a third party without authorisation (spam, phishing, leaks to chat).
    UNAUTHORIZED_COMMUNICATION = "unauthorized_communication"
    # Obtain capability or reach beyond the tool's stated scope (path traversal,
    # credential/env access, arbitrary execution via an argument).
    CAPABILITY_ESCALATION = "capability_escalation"
    # Establish durable footholds: edit configs, add hooks, schedule jobs.
    PERSISTENCE_TAMPERING = "persistence_tampering"
    # Attacker-controlled content arriving via a tool result redirects the agent
    # (indirect prompt injection — the integrity half of information flow).
    INJECTION_HIJACK = "injection_hijack"


# Reviewer legibility: map each misuse category to the OWASP Top 10 for LLM Apps
# (2025) entry it instantiates. Cited in the paper's threat-model table.
MISUSE_TO_OWASP_LLM: dict[ToolMisuseCategory, str] = {
    ToolMisuseCategory.DATA_EXFILTRATION: "LLM02 Sensitive Information Disclosure",
    ToolMisuseCategory.DESTRUCTIVE_ACTION: "LLM06 Excessive Agency",
    ToolMisuseCategory.UNAUTHORIZED_COMMUNICATION: "LLM06 Excessive Agency",
    ToolMisuseCategory.CAPABILITY_ESCALATION: "LLM06 Excessive Agency",
    ToolMisuseCategory.PERSISTENCE_TAMPERING: "LLM06 Excessive Agency",
    ToolMisuseCategory.INJECTION_HIJACK: "LLM01 Prompt Injection",
}

# Every misuse category is also reported under its closest AgentHarm category, so
# existing reports, aggregators and the HTML dashboard keep working unchanged and
# results remain comparable with AgentHarm-based prior work.
MISUSE_TO_HARM: dict[ToolMisuseCategory, HarmCategory] = {
    ToolMisuseCategory.DATA_EXFILTRATION: HarmCategory.CYBERCRIME,
    ToolMisuseCategory.DESTRUCTIVE_ACTION: HarmCategory.CYBERCRIME,
    ToolMisuseCategory.UNAUTHORIZED_COMMUNICATION: HarmCategory.FRAUD,
    ToolMisuseCategory.CAPABILITY_ESCALATION: HarmCategory.CYBERCRIME,
    ToolMisuseCategory.PERSISTENCE_TAMPERING: HarmCategory.CYBERCRIME,
    ToolMisuseCategory.INJECTION_HIJACK: HarmCategory.CYBERCRIME,
}


class AttackIntensity(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    STRONG = "strong"


class InjectedContent(BaseModel):
    """An attacker payload planted in a tool's RESULT, not in the user's message.

    This is the indirect-prompt-injection channel: the attacker controls some data
    the agent will read (a file, a fetched page, an email body, a DB row) and uses
    it to redirect the agent. The user turn itself can be entirely benign, which is
    what makes this threat model distinct from a malicious user.
    """

    content: str = Field(description="The payload text appended to the observation")
    tool_name: str = Field(
        default="", description="Only inject into this tool's results ('' = any tool)"
    )
    when_param_contains: str = Field(
        default="",
        description="Only inject when a parameter value contains this substring",
    )
    once: bool = Field(default=True, description="Fire at most once per trajectory")


class AdversarialPrompt(BaseModel):
    """One adversarial prompt targeting a specific harm / misuse objective."""

    harm_category: HarmCategory
    tool_targeted: str
    attack_intensity: AttackIntensity = AttackIntensity.EASY
    attack_chain: list[str] = Field(description="Ordered list of tool names in the attack sequence")
    prompt_text: str = Field(description="The adversarial task prompt (appears benign on surface)")
    grading_criteria: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured spec for the grading function: required_tools, sequence, goal",
    )
    is_fallback: bool = Field(
        default=False,
        description="True when this prompt came from the hardcoded fallback template "
        "(LLM generation failed). Pipeline-health metric — report rate separately.",
    )
    attack_strategy: str = Field(
        default="",
        description="Key of the red-team technique used to construct this prompt "
        "(see stage1/attack_strategies.py). Empty for template/fallback attacks.",
    )
    misuse_category: Optional[ToolMisuseCategory] = Field(
        default=None,
        description="Tool-capability misuse objective. Set when the run uses the "
        "tool-misuse taxonomy; `harm_category` is then the mapped AgentHarm label "
        "kept for comparability. None for legacy harm-category-driven runs.",
    )
    injections: list["InjectedContent"] = Field(
        default_factory=list,
        description="Attacker payloads to plant in tool RESULTS for this attack "
        "(indirect prompt injection). Empty for direct user-turn attacks.",
    )


class ToolCall(BaseModel):
    """A single tool invocation recorded during an agent trajectory."""

    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    response: Any = None
    success: bool = True
    failure_reason: str = ""
    untrusted_content: bool = Field(
        default=False,
        description="True when this call's RESPONSE carries attacker-controlled "
        "content (indirect prompt injection). Marks the integrity boundary: every "
        "subsequent decision in the trajectory was made on tainted input.",
    )


class AgentTrajectory(BaseModel):
    """Full ordered sequence of tool calls made by the agent for one prompt."""

    prompt: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    assistant_messages: list[str] = Field(default_factory=list)
    refusal_detected: bool = False
    refusal_message: str = ""
    raw_response: dict[str, Any] = Field(default_factory=dict)
    # ── Indirect-injection provenance ────────────────────────────────────────
    injections_fired: list[str] = Field(
        default_factory=list,
        description="Attacker payloads that actually reached the agent through a "
        "tool result. Empty for direct (user-turn) attacks.",
    )
    ingested_untrusted_content: bool = Field(
        default=False,
        description="True when at least one observation carried attacker content.",
    )
    steps_used: int = Field(
        default=0, description="ReAct steps consumed (0 for single-shot agents)."
    )


class FailureType(str, Enum):
    RETRIEVAL_ERROR = "retrieval_error"
    PARAMETER_ERROR = "parameter_error"
    SAFETY_REFUSAL = "safety_refusal"
    INCOMPLETE_EXECUTION = "incomplete_execution"
    NOT_APPLICABLE = "not_applicable"


class AttackIteration(BaseModel):
    attempt_number: int
    prompt_used: str
    trajectory: AgentTrajectory
    score: float = Field(ge=0.0, le=1.0)
    success: bool = False
    failure_type: FailureType = FailureType.NOT_APPLICABLE
    failure_diagnosis: str = ""


class AttackRecord(BaseModel):
    """Stage 1 output — one complete attack record per harm category."""

    record_id: str = Field(description="Unique ID, e.g., 'ATK-001-cybercrime'")
    harm_category: HarmCategory
    tool_targeted: str
    attack_intensity: AttackIntensity = AttackIntensity.EASY
    attack_chain: list[str]
    final_prompt_used: str
    attempt_number_of_success: Optional[int] = None
    final_score: float = Field(ge=0.0, le=1.0)
    refusal_occurred: bool = False
    refusal_attempt_number: Optional[int] = None
    successful_tool_calls: list[ToolCall] = Field(default_factory=list)
    failed_tool_calls: list[ToolCall] = Field(default_factory=list)
    failure_type: FailureType = FailureType.NOT_APPLICABLE
    attack_trajectory: list[AttackIteration] = Field(default_factory=list)
    # When n_repeats > 1, contains the final_score from each independent run.
    # `final_score` is the mean of these. Used for variance / CI reporting.
    seed_scores: list[float] = Field(default_factory=list)
    seeds_used: list[int] = Field(default_factory=list)
    # ── Threat-model provenance ──────────────────────────────────────────────
    misuse_category: Optional[ToolMisuseCategory] = Field(
        default=None,
        description="Tool-misuse objective this attack pursued (None for legacy "
        "harm-category runs). Group results by this for the tool-level analysis.",
    )
    attack_strategy: str = Field(
        default="", description="Red-team technique key carried over from the prompt."
    )
    delivery_channel: str = Field(
        default="user_turn",
        description="'user_turn' (direct) or 'tool_result' (indirect injection) — "
        "the channel the malicious instruction arrived through.",
    )
    ingested_untrusted_content: bool = Field(
        default=False,
        description="True when the winning trajectory acted after reading "
        "attacker-controlled tool output.",
    )


# ─────────────────────────────── Stage 2 schemas ─────────────────────────────


class ExploitType(str, Enum):
    DESCRIPTION_AMBIGUITY = "A"
    PARAMETER_EXPLOITABILITY = "B"
    CAPABILITY_OVER_PERMISSIVENESS = "C"
    KB_CONTEXT_LEAKAGE = "D"
    MISSING_BOUNDARY_DECLARATIONS = "E"


class VulnerabilityFinding(BaseModel):
    attack_record_id: str
    harm_category: HarmCategory
    exploit_type: ExploitType
    exploited_element: str = Field(description="Exact text or element name that was exploited")
    description: str


class EditAction(str, Enum):
    MODIFY = "MODIFY"
    ADD = "ADD"
    DELETE = "DELETE"


class EditTarget(str, Enum):
    DESCRIPTION = "description"
    KB_CONTEXT = "kb_context"


class EditRecommendation(BaseModel):
    action: EditAction
    target: str = Field(
        description="'description', 'kb_context', or 'parameter:<name>'"
    )
    original_text: Optional[str] = None
    new_text: Optional[str] = None
    motivation: str = Field(description="Reference to attack_record_id that motivated this edit")


class PrimaryExploitVector(str, Enum):
    DESCRIPTION_AMBIGUITY = "description_ambiguity"
    PARAMETER_EXPLOITABILITY = "parameter_exploitability"
    CAPABILITY_OVER_PERMISSIVENESS = "capability_over_permissiveness"
    KB_LEAKAGE = "kb_leakage"
    MISSING_BOUNDARY_DECLARATIONS = "missing_boundary_declarations"


class FailureAnalysisReport(BaseModel):
    """Stage 2 output."""

    tool_name: str
    total_attacks_attempted: int
    attacks_succeeded: int
    primary_exploit_vector: PrimaryExploitVector
    vulnerability_findings: list[VulnerabilityFinding] = Field(default_factory=list)
    edit_recommendations: list[EditRecommendation] = Field(default_factory=list)
    cross_attack_summary: str


# ─────────────────────────────── Stage 3 schemas ─────────────────────────────


class ConfidentialityLevel(str, Enum):
    HIGH = "high"
    LOW = "low"


class ConfidentialityAnnotations(BaseModel):
    read_confidentiality: ConfidentialityLevel
    write_confidentiality: ConfidentialityLevel
    read_justification: str
    write_justification: str


class CapabilityAnnotations(BaseModel):
    network: Any = False  # False | list[str] of allowed FQDNs/CIDRs
    filesystem: Any = False  # False | list[str] of allowed paths
    environment: Any = False  # False | list[str] of allowed env var names
    execution: Any = False  # False | list[str] of allowed binary paths
    software_libraries: Any = False  # False | list[str] of allowed library names
    capability_restriction_justifications: dict[str, str] = Field(default_factory=dict)


class TaintLevel(str, Enum):
    HIGH = "high"
    LOW = "low"


class TaintPropagationRule(BaseModel):
    """One taint propagation rule with the attack chain that motivated it."""

    rule_description: str
    from_taint: TaintLevel
    action: str  # "PERMIT" | "BLOCK" | "UPGRADE_TAINT"
    motivated_by_attack_chain: list[str]


class SessionTaintRules(BaseModel):
    initial_session_taint: TaintLevel
    taint_propagation_rules: list[TaintPropagationRule] = Field(default_factory=list)
    untrusted_input_taints_session: bool = Field(
        default=True,
        description="Integrity rule (IFC-002). When True, reading attacker-"
        "controlled content marks the session untrusted, and a subsequent "
        "consequential action (a write to a low-confidentiality sink) is blocked. "
        "This is the integrity dual of the confidentiality high-to-low rule: it "
        "stops an indirect prompt injection from being carried out, rather than "
        "stopping private data from leaving.",
    )


class EnforcementAction(str, Enum):
    BLOCK = "BLOCK"
    AUDIT = "AUDIT"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


class EnforcementRule(BaseModel):
    rule_id: str
    trigger_condition: str
    action: EnforcementAction
    reason: str
    motivated_by_attack: str  # attack_record_id


class ContainerEnforcement(BaseModel):
    capability: str
    mechanism: str
    directive: str


class DeploymentSpec(BaseModel):
    isolation_level: str  # "shared_host" | "separate_container" | "air_gapped"
    container_enforcements: list[ContainerEnforcement] = Field(default_factory=list)


class ToolAnnotation(BaseModel):
    """Runtime SAMOS gateway annotation for one registered MCP tool."""

    name: str
    description: str = ""
    read_confidentiality: ConfidentialityLevel
    write_confidentiality: ConfidentialityLevel
    network: Any = False
    filesystem: Any = False
    environment: Any = False
    execution: Any = False
    software_libraries: Any = False


class GatewayPolicyRule(BaseModel):
    rule_id: str
    trigger_condition: str
    action: EnforcementAction
    reason: str


class RedAgentFeedbackSchema(BaseModel):
    required_fields: list[str] = Field(default_factory=list)
    attack_types: list[str] = Field(default_factory=list)
    succeeded_only_for_hardening: bool = True
    hardening_actions: list[str] = Field(default_factory=list)


class GatewayEnforcementSpec(BaseModel):
    """Concrete SAMOS gateway behavior derived from generated policy evidence."""

    tool_annotation: ToolAnnotation
    session_initial_taint: TaintLevel
    taint_is_monotonic: bool = True
    fail_secure_unknown_tools: bool = True
    policy_log_required: bool = True
    core_policy_rules: list[GatewayPolicyRule] = Field(default_factory=list)
    red_agent_feedback_schema: RedAgentFeedbackSchema = Field(default_factory=RedAgentFeedbackSchema)


class PolicyCoverage(BaseModel):
    attacks_fully_blocked_by_policy: int = 0
    attacks_partially_mitigated: int = 0
    attacks_requiring_model_level_defense: int = 0
    unmitigated_attacks: int = 0


class SAMOSPolicy(BaseModel):
    """Stage 3 output — complete SAMOS-compatible security policy."""

    tool_name: str
    policy_version: str = "1.0"
    generated_from_attack_cycles: int
    confidentiality_annotations: ConfidentialityAnnotations
    capability_annotations: CapabilityAnnotations
    session_taint_rules: SessionTaintRules
    enforcement_rules: list[EnforcementRule] = Field(default_factory=list)
    gateway_enforcement: GatewayEnforcementSpec
    deployment_spec: DeploymentSpec
    policy_coverage: PolicyCoverage


# ────────────────────── Security/utility evaluation schemas ───────────────────
#
# A policy that blocks every attack by disabling the tool wholesale scores 100%
# attack coverage but destroys the tool's usefulness. Research-grade evaluation
# therefore MUST also measure how many *legitimate* uses the same policy blocks.
# These schemas capture the benign side of the tradeoff.


class BenignTask(BaseModel):
    """One legitimate use of a tool that a good policy must NOT block.

    The `tool_calls` are the trajectory a well-behaved agent would produce for a
    benign request. Replaying them through the policy tells us whether the policy
    over-blocks (a false positive against utility).
    """

    task_id: str
    description: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    prompt: str = Field(
        default="",
        description="The user request that should produce this trajectory. Set so "
        "the trajectory can be RE-RECORDED from a live agent instead of being "
        "hand-authored; falls back to `description` when empty.",
    )


class BenignTaskSuite(BaseModel):
    """A corpus of benign tasks for one tool."""

    tool_name: str
    tasks: list[BenignTask] = Field(default_factory=list)
    provenance: str = Field(
        default="hand_authored",
        description="'hand_authored' (trajectories written by us) or 'recorded' "
        "(captured from a live agent run). Hand-authored trajectories make the "
        "benign pass rate partly circular — we wrote both the test and its "
        "expected calls — so runs must report which was used.",
    )


class UtilityResult(BaseModel):
    """Per-benign-task replay outcome."""

    task_id: str
    allowed: bool
    verdict_status: str
    blocking_reason: str = ""


class SecurityUtilityReport(BaseModel):
    """The security/utility tradeoff — the headline research metric.

    attack_block_rate (ABR): fraction of successful attacks the policy blocks.
        Higher is more secure. A deny-everything policy trivially reaches 1.0.
    benign_pass_rate (BPR): fraction of legitimate tasks the policy still allows.
        Higher preserves more utility. A deny-everything policy collapses to 0.0.
    over_block_rate: 1 - BPR. The false-positive rate against legitimate use.
    utility_security_f1: harmonic mean of ABR and BPR — a single number that a
        degenerate deny-all policy CANNOT game (its BPR is 0, so F1 is 0).
    """

    tool_name: str
    n_successful_attacks: int = 0
    attacks_blocked: int = 0
    attack_block_rate: float = 0.0

    # Secondary security view: hard BLOCK is not the only defense. A successful
    # attack that trips a REQUIRE_CONFIRMATION / AUDIT gate is mitigated by a
    # human-in-the-loop check, not silently allowed. attacks_mitigated counts
    # BLOCK + partial mitigations; mitigation_rate is over successful attacks.
    # These are reported ALONGSIDE (never instead of) the strict block-based ABR
    # and F1, so the headline metric cannot be inflated by soft gates.
    attacks_mitigated: int = 0
    mitigation_rate: float = 0.0

    n_benign_tasks: int = 0
    benign_allowed: int = 0
    benign_pass_rate: float = 0.0
    over_block_rate: float = 0.0

    utility_security_f1: float = 0.0
    degenerate_deny_all: bool = Field(
        default=False,
        description="True when the policy blocks every benign task (BPR == 0): "
        "coverage is meaningless because the tool is effectively disabled.",
    )
    utility_results: list[UtilityResult] = Field(default_factory=list)

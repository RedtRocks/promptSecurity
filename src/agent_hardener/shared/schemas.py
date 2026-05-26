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


class HarmCategory(str, Enum):
    DISINFORMATION = "disinformation"
    HARASSMENT = "harassment"
    FRAUD = "fraud"
    CYBERCRIME = "cybercrime"
    COPYRIGHT = "copyright"
    HATE_SPEECH = "hate_speech"
    DRUGS = "drugs"
    SEXUAL_CONTENT = "sexual_content"


class AttackIntensity(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    STRONG = "strong"


class AdversarialPrompt(BaseModel):
    """One adversarial prompt targeting a specific harm category."""

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


class ToolCall(BaseModel):
    """A single tool invocation recorded during an agent trajectory."""

    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    response: Any = None
    success: bool = True
    failure_reason: str = ""


class AgentTrajectory(BaseModel):
    """Full ordered sequence of tool calls made by the agent for one prompt."""

    prompt: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    assistant_messages: list[str] = Field(default_factory=list)
    refusal_detected: bool = False
    refusal_message: str = ""
    raw_response: dict[str, Any] = Field(default_factory=dict)


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

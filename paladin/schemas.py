"""
Core schemas for context objects and trust metadata.

Security rationale:
- All data passing through the system must be typed and tagged with trust metadata
- Trust levels are immutable once assigned at intake
- Context objects enforce explicit separation between system, developer, and untrusted content
- No free-form text concatenation is allowed; all prompts are assembled from structured objects
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class TrustLevel(str, Enum):
    """
    Trust levels for content in the system.
    
    Security rationale:
    - SYSTEM: Immutable policy and instructions (highest privilege)
    - DEVELOPER: Application-level instructions (trusted but mutable)
    - UNTRUSTED: All external input (user, retrieval, model output)
    """
    SYSTEM = "system"
    DEVELOPER = "developer"
    UNTRUSTED = "untrusted"


class ContentOrigin(str, Enum):
    """
    Origin of content entering the system.
    
    Security rationale:
    - Tracks provenance for audit and trust decisions
    - Enables rejection of content from compromised sources
    """
    USER_INPUT = "user_input"
    RETRIEVAL = "retrieval"
    MODEL_OUTPUT = "model_output"
    MEMORY = "memory"
    SYSTEM = "system"


class RiskLevel(str, Enum):
    """Risk assessment levels from Guardrails classification."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustMetadata(BaseModel):
    """
    Trust metadata attached to all content.
    
    Security rationale:
     - Immutable once created (model_config forbids mutation)
    - Provides audit trail and trust decisions
    - Enables per-content security policies
    """
    model_config = ConfigDict(frozen=True)
    
    trust_level: TrustLevel
    origin: ContentOrigin
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_id: Optional[str] = None  # For retrieval: document ID, for user: session ID
    instruction_density: float = 0.0  # Heuristic score for instruction-like language


class RiskClassification(BaseModel):
    """
    Output from Guardrails risk classification.
    
    Security rationale:
    - Structured risk signals, not blocking decisions
    - Flags are advisory; gates make enforcement decisions
    - Enables composition of multiple detectors
    """
    risk_level: RiskLevel
    flags: List[str] = Field(default_factory=list)
    memory_writable: bool = False
    tool_allowed: bool = False
    reason: Optional[str] = None
    confidence: float = 1.0


class ContextObject(BaseModel):
    """
    Base class for all content passing through the system.
    
    Security rationale:
    - Forces explicit typing and metadata attachment
    - Prevents implicit trust escalation
    - Enables per-object policy enforcement
    """
    content: str
    metadata: TrustMetadata
    risk_classification: Optional[RiskClassification] = None


class SystemInstruction(BaseModel):
    """
    Immutable system-level instructions.
    
    Security rationale:
    - Cannot be modified by user input or model output
    - Always assembled at the top of the prompt
    - Defines security boundaries and policies
    """
    model_config = ConfigDict(frozen=True)
    
    content: str
    role: str = "system"
    metadata: TrustMetadata = Field(
        default_factory=lambda: TrustMetadata(
            trust_level=TrustLevel.SYSTEM,
            origin=ContentOrigin.SYSTEM
        )
    )


class DeveloperInstruction(BaseModel):
    """
    Application-level instructions from the developer.
    
    Security rationale:
    - Trusted but not immutable (can be updated by developer)
    - Assembled after system instructions
    - Cannot be overridden by untrusted input
    """
    content: str
    role: str = "developer"
    metadata: TrustMetadata = Field(
        default_factory=lambda: TrustMetadata(
            trust_level=TrustLevel.DEVELOPER,
            origin=ContentOrigin.SYSTEM
        )
    )


class UntrustedContent(BaseModel):
    """
    Content from untrusted sources (user input, retrieval, model output).
    
    Security rationale:
    - Explicitly marked as untrusted
    - Must pass through intake pipeline and risk classification
    - Cannot become system or developer instructions
    - May be neutralized or rewritten
    """
    content: str
    metadata: TrustMetadata
    risk_classification: Optional[RiskClassification] = None
    rewritten_content: Optional[str] = None  # Neutralized version if rewriting applied


class RetrievalDocument(BaseModel):
    """
    Document retrieved from external source.
    
    Security rationale:
    - Always untrusted, even if from internal database
    - Tagged with origin and instruction density
    - Cannot write to memory without passing gate
    - Model may read but not execute or persist
    """
    text: str
    origin: str  # e.g., "vector_db", "web_search"
    metadata: TrustMetadata
    instruction_density: float = 0.0
    document_id: Optional[str] = None


class PromptContext(BaseModel):
    """
    Assembled prompt context with explicit role separation.
    
    Security rationale:
    - System instructions are isolated at top
    - Developer instructions follow system
    - Untrusted content is clearly demarcated
    - No concatenation of roles
    - Structure enforces privilege boundaries
    """
    system_instructions: List[SystemInstruction] = Field(default_factory=list)
    developer_instructions: List[DeveloperInstruction] = Field(default_factory=list)
    untrusted_content: List[UntrustedContent] = Field(default_factory=list)
    retrieval_documents: List[RetrievalDocument] = Field(default_factory=list)
    
    def to_messages(self) -> List[Dict[str, str]]:
        """
        Convert to message format for LLM.
        
        Security rationale:
        - Maintains strict ordering: system -> developer -> untrusted
        - Untrusted content is marked with metadata in the message
        - No implicit mixing of trust levels
        """
        messages = []
        
        # System instructions (highest privilege)
        for instr in self.system_instructions:
            messages.append({
                "role": "system",
                "content": instr.content
            })
        
        # Developer instructions
        for instr in self.developer_instructions:
            messages.append({
                "role": "developer",
                "content": instr.content
            })
        
        # Retrieval documents (explicitly marked as untrusted)
        for doc in self.retrieval_documents:
            messages.append({
                "role": "user",
                "content": f"[RETRIEVED DOCUMENT - UNTRUSTED]\nSource: {doc.origin}\n\n{doc.text}"
            })
        
        # Untrusted user content
        for content in self.untrusted_content:
            # Use rewritten content if available (neutralized)
            text = content.rewritten_content if content.rewritten_content else content.content
            messages.append({
                "role": "user",
                "content": text
            })
        
        return messages


class MemoryEntry(BaseModel):
    """
    Entry in the memory store.
    
    Security rationale:
    - Immutable once written (append-only semantics)
    - Versioned for audit trail
    - Provenance tracked via metadata
    - Only writable after passing MemoryWriteGate
    """
    model_config = ConfigDict(frozen=True)
    
    id: str
    content: str
    metadata: TrustMetadata
    version: int = 1
    parent_version: Optional[int] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    promoted_from_quarantine: bool = False

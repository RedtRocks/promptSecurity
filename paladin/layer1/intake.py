"""
Prompt Intake Pipeline - Layer 1.

Security rationale:
- All user input enters through this pipeline
- No raw input reaches the LLM without classification and potential rewriting
- Pipeline enforces trust boundaries and risk assessment
- Provides first line of defense against prompt injection
"""

from typing import Optional
from datetime import datetime

from ..schemas import (
    UntrustedContent,
    TrustMetadata,
    TrustLevel,
    ContentOrigin,
    RiskClassification,
    RiskLevel
)


class PromptIntakePipeline:
    """
    Pipeline for processing raw user input into classified, potentially rewritten content.
    
    Security rationale:
    - Single entry point for all untrusted input
    - Enforces risk classification before content is used
    - Provides hooks for neutralization and rewriting
    - Cannot be bypassed (architectural enforcement point)
    """
    
    def __init__(self, classifier=None, rewriter=None):
        """
        Initialize intake pipeline.
        
        Args:
            classifier: Risk classifier instance (Guardrails-based)
            rewriter: Prompt rewriter for neutralization
        """
        self.classifier = classifier
        self.rewriter = rewriter
    
    def process_user_input(
        self,
        raw_input: str,
        session_id: Optional[str] = None
    ) -> UntrustedContent:
        """
        Process raw user input through intake pipeline.
        
        Security rationale:
        - All input is tagged as untrusted
        - Risk classification is mandatory
        - High-risk input can be rewritten or rejected
        - Metadata is immutable after creation
        
        Args:
            raw_input: Raw text from user
            session_id: Optional session identifier for provenance
        
        Returns:
            UntrustedContent with metadata and risk classification
        """
        # Step 1: Create trust metadata (immutable)
        metadata = TrustMetadata(
            trust_level=TrustLevel.UNTRUSTED,
            origin=ContentOrigin.USER_INPUT,
            timestamp=datetime.utcnow(),
            source_id=session_id
        )
        
        # Step 2: Risk classification
        risk = self._classify_risk(raw_input)
        
        # Step 3: Rewriting if high risk
        rewritten = None
        if risk.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            if self.rewriter:
                rewritten = self.rewriter.neutralize(raw_input, risk)
        
        # Step 4: Create untrusted content object
        return UntrustedContent(
            content=raw_input,
            metadata=metadata,
            risk_classification=risk,
            rewritten_content=rewritten
        )
    
    def _classify_risk(self, content: str) -> RiskClassification:
        """
        Classify risk level of content.
        
        Security rationale:
        - Uses Guardrails detectors to identify threats
        - Returns structured risk signals, not boolean pass/fail
        - Allows for graduated response based on risk level
        - Default to conservative (medium risk) if classifier unavailable
        """
        if not self.classifier:
            # Conservative default: treat unknown input as medium risk
            return RiskClassification(
                risk_level=RiskLevel.MEDIUM,
                flags=["no_classifier"],
                memory_writable=False,
                tool_allowed=False,
                reason="No classifier configured - conservative default"
            )
        
        # Use classifier (will be Guardrails-based)
        return self.classifier.classify(content)


class DefaultRiskClassifier:
    """
    Default heuristic-based risk classifier.
    
    Security rationale:
    - Provides basic protection when Guardrails is not available
    - Uses simple heuristics to detect common injection patterns
    - Should be replaced with Guardrails in production
    """
    
    def classify(self, content: str) -> RiskClassification:
        """
        Classify content risk using heuristics.
        
        Detects:
        - Instruction override attempts
        - System/role-play language
        - Memory persistence attempts
        - Tool coercion
        """
        flags = []
        risk_level = RiskLevel.SAFE
        
        content_lower = content.lower()
        
        # Check for instruction override
        instruction_patterns = [
            "ignore previous",
            "ignore all previous",
            "disregard",
            "new instructions",
            "system:",
            "assistant:",
            "you are now",
            "forget everything",
            "ignore instructions"
        ]
        
        for pattern in instruction_patterns:
            if pattern in content_lower:
                flags.append("instruction_override")
                risk_level = RiskLevel.HIGH
                break
        
        # Check for role-play attempts
        role_patterns = [
            "you are a",
            "act as",
            "pretend to be",
            "role-play",
            "simulate"
        ]
        
        for pattern in role_patterns:
            if pattern in content_lower:
                flags.append("role_play")
                if risk_level == RiskLevel.SAFE:
                    risk_level = RiskLevel.MEDIUM
        
        # Check for memory persistence
        memory_patterns = [
            "remember this",
            "store this",
            "save this",
            "keep this in memory",
            "from now on"
        ]
        
        for pattern in memory_patterns:
            if pattern in content_lower:
                flags.append("memory_persistence")
                if risk_level == RiskLevel.SAFE:
                    risk_level = RiskLevel.MEDIUM
        
        # Check for tool coercion
        tool_patterns = [
            "execute",
            "run command",
            "call function",
            "invoke tool"
        ]
        
        for pattern in tool_patterns:
            if pattern in content_lower:
                flags.append("tool_coercion")
                if risk_level == RiskLevel.SAFE:
                    risk_level = RiskLevel.MEDIUM
        
        # Determine permissions based on risk
        memory_writable = risk_level in [RiskLevel.SAFE, RiskLevel.LOW]
        tool_allowed = risk_level in [RiskLevel.SAFE]
        
        return RiskClassification(
            risk_level=risk_level,
            flags=flags,
            memory_writable=memory_writable,
            tool_allowed=tool_allowed,
            reason=f"Heuristic detection: {', '.join(flags) if flags else 'no threats detected'}",
            confidence=0.7  # Lower confidence for heuristics
        )

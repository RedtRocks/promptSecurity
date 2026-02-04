"""
Memory Write Gate - Layer 2.

Security rationale:
- Single enforcement point for all memory writes
- Rejects writes from untrusted sources
- Detects instruction-like language in memory candidates
- Prevents persistence of injected instructions
- Enables quarantine workflow for suspicious content
"""

from typing import Optional
from ..schemas import TrustMetadata, TrustLevel, ContentOrigin, RiskClassification, RiskLevel


class MemoryWriteGate:
    """
    Gate for controlling memory writes.
    
    Security rationale:
    - All memory writes must pass through this gate
    - Gate makes final yes/no decision based on risk signals
    - Rejects writes that could persist malicious content
    - Logs all rejection decisions for audit
    - Cannot be bypassed (architectural enforcement)
    """
    
    def __init__(self, classifier=None):
        """
        Initialize memory write gate.
        
        Args:
            classifier: Risk classifier for content analysis
        """
        self.classifier = classifier
        self.rejection_log: list = []
    
    def allow_write(
        self,
        content: str,
        metadata: TrustMetadata,
        risk_classification: Optional[RiskClassification] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Decide if write should be allowed.
        
        Security rationale:
        - Multiple checks in sequence (defense in depth)
        - Explicit rejection reasons for audit
        - Conservative defaults (reject on doubt)
        - Cannot be overridden by untrusted input
        
        Args:
            content: Content to be written
            metadata: Trust metadata
            risk_classification: Optional pre-computed risk classification
        
        Returns:
            Tuple of (allowed: bool, reason: Optional[str])
        """
        # Check 1: Trust level
        if not self._check_trust_level(metadata):
            reason = f"Rejected: trust level {metadata.trust_level.value} not allowed for memory write"
            self._log_rejection(content, metadata, reason)
            return False, reason
        
        # Check 2: Origin
        if not self._check_origin(metadata):
            reason = f"Rejected: origin {metadata.origin.value} not allowed for memory write"
            self._log_rejection(content, metadata, reason)
            return False, reason
        
        # Check 3: Risk classification
        if risk_classification:
            if not risk_classification.memory_writable:
                reason = f"Rejected: risk classification forbids memory write (risk={risk_classification.risk_level.value})"
                self._log_rejection(content, metadata, reason)
                return False, reason
        
        # Check 4: Content analysis
        content_risk = self._analyze_content(content)
        if content_risk:
            reason = f"Rejected: content analysis detected threat: {content_risk}"
            self._log_rejection(content, metadata, reason)
            return False, reason
        
        # All checks passed
        return True, None
    
    def _check_trust_level(self, metadata: TrustMetadata) -> bool:
        """
        Check if trust level allows memory write.
        
        Security rationale:
        - UNTRUSTED content cannot write directly to memory
        - Must go through quarantine first
        - Only DEVELOPER and SYSTEM can write directly (for bootstrapping)
        """
        # For now, only allow system and developer to write directly
        # User input must go through quarantine
        return metadata.trust_level in [TrustLevel.SYSTEM, TrustLevel.DEVELOPER]
    
    def _check_origin(self, metadata: TrustMetadata) -> bool:
        """
        Check if origin allows memory write.
        
        Security rationale:
        - USER_INPUT: blocked (potential injection)
        - RETRIEVAL: blocked (external data)
        - MODEL_OUTPUT: blocked (model could be compromised)
        - SYSTEM: allowed (trusted initialization)
        - MEMORY: allowed (already passed gate previously)
        """
        allowed_origins = [ContentOrigin.SYSTEM, ContentOrigin.MEMORY]
        return metadata.origin in allowed_origins
    
    def _analyze_content(self, content: str) -> Optional[str]:
        """
        Analyze content for instruction-like language.
        
        Security rationale:
        - Detects instruction keywords
        - Detects system/role references
        - Detects tool invocation language
        - Detects persistence instructions
        
        Returns:
            Threat description if detected, None otherwise
        """
        content_lower = content.lower()
        
        # Check for instruction keywords
        instruction_keywords = [
            "you are",
            "you must",
            "always",
            "never",
            "ignore",
            "override",
            "system:",
            "assistant:",
            "user:"
        ]
        
        for keyword in instruction_keywords:
            if keyword in content_lower:
                return f"instruction keyword detected: '{keyword}'"
        
        # Check for system references
        system_refs = [
            "system prompt",
            "your instructions",
            "your role",
            "your rules",
            "your policy"
        ]
        
        for ref in system_refs:
            if ref in content_lower:
                return f"system reference detected: '{ref}'"
        
        # Check for tool references
        tool_refs = [
            "execute",
            "run command",
            "call function",
            "invoke tool",
            "use api"
        ]
        
        for ref in tool_refs:
            if ref in content_lower:
                return f"tool reference detected: '{ref}'"
        
        # Check for persistence language
        persistence_refs = [
            "remember forever",
            "permanent",
            "from now on",
            "always remember"
        ]
        
        for ref in persistence_refs:
            if ref in content_lower:
                return f"persistence language detected: '{ref}'"
        
        # No threats detected
        return None
    
    def _log_rejection(self, content: str, metadata: TrustMetadata, reason: str):
        """
        Log rejection for audit.
        
        Security rationale:
        - All rejections are logged
        - Enables detection of attack patterns
        - Supports incident response
        """
        self.rejection_log.append({
            "content_preview": content[:100],  # First 100 chars
            "trust_level": metadata.trust_level.value,
            "origin": metadata.origin.value,
            "reason": reason,
            "timestamp": metadata.timestamp.isoformat()
        })
    
    def get_rejection_log(self) -> list:
        """
        Get rejection log.
        
        Returns:
            List of rejection records
        """
        return self.rejection_log
    
    def should_quarantine(
        self,
        metadata: TrustMetadata,
        risk_classification: Optional[RiskClassification] = None
    ) -> bool:
        """
        Decide if content should go to quarantine instead of rejection.
        
        Security rationale:
        - Quarantine for borderline cases
        - Allows manual review
        - Prevents loss of potentially useful but suspicious content
        - Quarantine is read-only until promotion
        
        Args:
            metadata: Trust metadata
            risk_classification: Optional risk classification
        
        Returns:
            True if should quarantine
        """
        # Quarantine if untrusted but not critical risk
        if metadata.trust_level == TrustLevel.UNTRUSTED:
            if risk_classification:
                return risk_classification.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
            return True  # Default to quarantine for untrusted
        
        return False

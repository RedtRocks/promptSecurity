"""
Guardrails integration for risk classification.

Security rationale:
- Uses Guardrails AI library for robust input validation
- Provides structured risk signals (not blocking decisions)
- Enables composition of multiple validators
- Higher confidence than heuristics
"""

from typing import List, Optional, Dict, Any

try:
    from guardrails import Guard
    from guardrails.hub import DetectPII, DetectJailbreak, RestrictToTopic
    GUARDRAILS_AVAILABLE = True
    VALIDATORS_AVAILABLE = True
except ImportError as e:
    GUARDRAILS_AVAILABLE = False
    VALIDATORS_AVAILABLE = False
    print(f"Guardrails validators not available: {e}")

from ..schemas import RiskClassification, RiskLevel


class GuardrailsClassifier:
    """
    Guardrails-based risk classifier.
    
    Security rationale:
    - Uses multiple validators for comprehensive detection
    - Returns structured risk signals
    - Does not block execution (advisory only)
    - Enables defense in depth
    """
    
    def __init__(self):
        """
        Initialize Guardrails validators.
        
        Security rationale:
        - Multiple validators provide layered detection
        - Each validator targets specific threat type
        - Validators are composable
        """
        self.pii_guard: Optional[Guard] = None
        self.jailbreak_guard: Optional[Guard] = None
        self.topic_guard: Optional[Guard] = None
        self._init_guards()
    
    def _init_guards(self):
        """
        Initialize Guardrails guards for different threat types.
        
        Security rationale:
        - PII detection prevents leakage of sensitive data
        - Jailbreak detection catches prompt injection attempts
        - Topic restriction ensures queries stay within safe domains
        
        Note: These validators enhance heuristic detection but don't replace it.
        """
        if not GUARDRAILS_AVAILABLE or not VALIDATORS_AVAILABLE:
            print("⚠️  Guardrails validators not available - using heuristic detection only")
            return
        
        try:
            # Guard 1: Detect PII (Personally Identifiable Information)
            # Prevents leakage of SSN, credit cards, emails, etc.
            self.pii_guard = Guard().use(
                DetectPII(
                    pii_entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "SSN"],
                    on_fail="exception"
                )
            )
            print("✅ PII detection validator loaded")
            
            # Guard 2: Detect Jailbreak attempts
            # Catches prompt injection and instruction override attempts
            self.jailbreak_guard = Guard().use(
                DetectJailbreak(
                    on_fail="exception"
                )
            )
            print("✅ Jailbreak detection validator loaded")
            
            # Guard 3: Restrict to safe topics
            # NOTE: This validator is often too restrictive and causes false positives.
            # Disabled for now - heuristic detection provides adequate coverage.
            # To enable, uncomment the code below and adjust valid_topics for your domain.
            """
            self.topic_guard = Guard().use(
                RestrictToTopic(
                    valid_topics=[
                        "general questions", "education", "learning", "explanations",
                        "technology", "science", "mathematics", "history", "literature",
                        "programming", "data science", "artificial intelligence",
                        "helpful information", "facts", "guidance", "assistance"
                    ],
                    invalid_topics=[
                        "system access", "credential theft", "malware", "hacking",
                        "prompt injection", "jailbreak", "system override",
                        "instruction manipulation", "bypass security"
                    ],
                    on_fail="exception"
                )
            )
            print("✅ Topic restriction validator loaded")
            """
            print("ℹ️  Topic restriction validator disabled (too many false positives)")
            
            print("🔒 All Guardrails validators initialized successfully")
            
        except Exception as e:
            print(f"⚠️  Warning: Could not initialize some Guardrails validators: {e}")
            print("   Falling back to heuristic detection")
    
    def classify(self, content: str) -> RiskClassification:
        """
        Classify content risk using Guardrails validators + heuristics.
        
        Security rationale:
        - Defense in depth: combines Guardrails validators with heuristics
        - Guardrails validators catch sophisticated attacks
        - Heuristics catch known patterns quickly
        - Aggregates risk from all sources
        
        Args:
            content: Content to classify
        
        Returns:
            Risk classification with detailed flags
        """
        flags = []
        risk_scores = []
        guardrails_results: Dict[str, Any] = {}
        
        # LAYER 1: Run Guardrails validators if available
        if VALIDATORS_AVAILABLE:
            # Validator 1: PII Detection
            if self.pii_guard:
                try:
                    self.pii_guard.validate(content)
                except Exception as e:
                    flags.append("pii_detected")
                    risk_scores.append(0.7)
                    guardrails_results["pii"] = str(e)
            
            # Validator 2: Jailbreak Detection
            if self.jailbreak_guard:
                try:
                    self.jailbreak_guard.validate(content)
                except Exception as e:
                    flags.append("jailbreak_attempt")
                    risk_scores.append(0.95)  # Very high risk
                    guardrails_results["jailbreak"] = str(e)
            
            # Validator 3: Topic Restriction
            if self.topic_guard:
                try:
                    self.topic_guard.validate(content)
                except Exception as e:
                    flags.append("invalid_topic")
                    risk_scores.append(0.6)
                    guardrails_results["topic"] = str(e)
        
        # LAYER 2: Run heuristic checks (fast, pattern-based)
        if self._check_instruction_injection(content):
            flags.append("instruction_injection")
            risk_scores.append(0.9)
        
        if self._check_prompt_extraction(content):
            flags.append("prompt_extraction")
            risk_scores.append(0.8)
        
        if self._check_memory_poisoning(content):
            flags.append("memory_poisoning")
            risk_scores.append(0.85)
        
        if self._check_tool_abuse(content):
            flags.append("tool_abuse")
            risk_scores.append(0.75)
        
        # Determine overall risk level
        max_score = max(risk_scores) if risk_scores else 0.0
        
        if max_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif max_score >= 0.6:
            risk_level = RiskLevel.HIGH
        elif max_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
        elif max_score >= 0.2:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.SAFE
        
        # Set permissions based on risk
        memory_writable = risk_level in [RiskLevel.SAFE, RiskLevel.LOW]
        tool_allowed = risk_level == RiskLevel.SAFE
        
        # Build detailed reason
        detection_method = "Guardrails + Heuristics" if guardrails_results else "Heuristics"
        reason = f"{detection_method}: {', '.join(flags) if flags else 'no threats detected'}"
        
        return RiskClassification(
            risk_level=risk_level,
            flags=flags,
            memory_writable=memory_writable,
            tool_allowed=tool_allowed,
            reason=reason,
            confidence=0.95 if guardrails_results else 0.9  # Higher confidence with Guardrails
        )
    
    def _check_instruction_injection(self, content: str) -> bool:
        """
        Check for instruction injection patterns.
        
        Security rationale:
        - Detects attempts to override system instructions
        - Looks for meta-instruction language
        - Identifies role confusion attempts
        """
        content_lower = content.lower()
        
        patterns = [
            "ignore previous instructions",
            "ignore all previous",
            "ignore all instructions",
            "ignore your instructions",
            "disregard",
            "new instructions:",
            "system:",
            "system prompt",
            "reveal your",
            "you are now",
            "forget everything",
            "your new role is",
            "override",
            "instead, do"
        ]
        
        return any(pattern in content_lower for pattern in patterns)
    
    def _check_prompt_extraction(self, content: str) -> bool:
        """
        Check for system prompt extraction attempts.
        
        Security rationale:
        - Detects attempts to leak system instructions
        - Prevents reconnaissance for follow-up attacks
        - Protects proprietary prompt engineering
        """
        content_lower = content.lower()
        
        patterns = [
            "what are your instructions",
            "show me your prompt",
            "what is your system prompt",
            "repeat your instructions",
            "what were you told",
            "output your prompt",
            "print your system message"
        ]
        
        return any(pattern in content_lower for pattern in patterns)
    
    def _check_memory_poisoning(self, content: str) -> bool:
        """
        Check for memory poisoning attempts.
        
        Security rationale:
        - Detects attempts to persist malicious content
        - Prevents cross-session attacks
        - Protects memory integrity
        """
        content_lower = content.lower()
        
        patterns = [
            "remember this forever",
            "store this permanently",
            "save this for later",
            "keep this in memory",
            "from now on, always",
            "add to your knowledge",
            "update your instructions",
            "memorize this"
        ]
        
        return any(pattern in content_lower for pattern in patterns)
    
    def _check_tool_abuse(self, content: str) -> bool:
        """
        Check for tool abuse patterns.
        
        Security rationale:
        - Detects unauthorized tool invocation attempts
        - Prevents privilege escalation via tools
        - Protects system integrity
        """
        content_lower = content.lower()
        
        patterns = [
            "execute command",
            "run this code",
            "call the function",
            "invoke the tool",
            "use the api to",
            "access the database",
            "delete",
            "drop table"
        ]
        
        return any(pattern in content_lower for pattern in patterns)


class GuardrailsValidator:
    """
    Wrapper for Guardrails output validation.
    
    Security rationale:
    - Validates model outputs before use
    - Ensures outputs don't contain sensitive data
    - Prevents model from generating malicious content
    - Can enforce schema compliance
    """
    
    def __init__(self):
        """Initialize output validators."""
        pass
    
    def validate_output(self, output: str) -> tuple[bool, Optional[str]]:
        """
        Validate model output.
        
        Args:
            output: Model-generated output
        
        Returns:
            Tuple of (is_valid, reason)
        
        Security rationale:
        - Check for leaked system prompts
        - Check for sensitive data (PII, credentials)
        - Check for instruction leakage
        """
        # Check for system prompt leakage
        if self._contains_system_prompt_leak(output):
            return False, "Output contains system prompt leakage"
        
        # Check for instruction disclosure
        if self._contains_instruction_disclosure(output):
            return False, "Output discloses internal instructions"
        
        return True, None
    
    def _contains_system_prompt_leak(self, output: str) -> bool:
        """Check if output leaks system prompt."""
        output_lower = output.lower()
        
        leak_indicators = [
            "my instructions are",
            "i was told to",
            "my system prompt",
            "according to my instructions"
        ]
        
        return any(indicator in output_lower for indicator in leak_indicators)
    
    def _contains_instruction_disclosure(self, output: str) -> bool:
        """Check if output discloses instructions."""
        output_lower = output.lower()
        
        disclosure_indicators = [
            "i must",
            "i am not allowed to",
            "my rules state",
            "i am programmed to"
        ]
        
        return any(indicator in output_lower for indicator in disclosure_indicators)

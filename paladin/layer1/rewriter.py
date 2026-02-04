"""
Prompt Rewriter for neutralizing high-risk input.

Security rationale:
- Attempts to preserve user intent while removing injected instructions
- Used when rejection would break user experience
- Does not guarantee safety (defense in depth requires multiple layers)
- Rewriting is logged for audit
"""

from typing import Optional
from ..schemas import RiskClassification


class PromptRewriter:
    """
    Rewriter for neutralizing high-risk prompts.
    
    Security rationale:
    - Preserves user intent when possible
    - Removes instruction-like language
    - Adds explicit markers for untrusted content
    - Rewriting is transparent (original is preserved)
    """
    
    def neutralize(self, content: str, risk: RiskClassification) -> str:
        """
        Neutralize high-risk content while preserving intent.
        
        Security rationale:
        - Does not claim to remove all risk
        - Uses simple sanitization heuristics
        - Adds explicit untrusted markers
        - Original content is preserved for audit
        
        Args:
            content: Original content
            risk: Risk classification with detected threats
        
        Returns:
            Neutralized content
        """
        rewritten = content
        
        # If instruction override detected, add neutralizing prefix
        if "instruction_override" in risk.flags:
            rewritten = self._neutralize_instructions(rewritten)
        
        # If role-play detected, add context boundary
        if "role_play" in risk.flags:
            rewritten = self._neutralize_roleplay(rewritten)
        
        # Add explicit untrusted marker
        rewritten = f"[USER INPUT - UNTRUSTED]\n{rewritten}"
        
        return rewritten
    
    def _neutralize_instructions(self, content: str) -> str:
        """
        Neutralize instruction override attempts.
        
        Strategy:
        - Remove or quote instruction-like language
        - Add explicit non-instruction markers
        """
        # Simple approach: wrap in quotes to make it clear it's data
        return f'The user said: "{content}"'
    
    def _neutralize_roleplay(self, content: str) -> str:
        """
        Neutralize role-play attempts.
        
        Strategy:
        - Make it clear this is user's request, not system instruction
        - Preserve intent but remove authority
        """
        return f"User request (not a system instruction): {content}"

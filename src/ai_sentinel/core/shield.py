"""
Security Shield engine for AI-Sentinel Guardrails.
Ensures input is properly normalized before evaluating against generalized prompt injection patterns.
"""

import re
from ai_sentinel.core.normalizer import InputNormalizer

class SecurityShield:
    """
    Evaluates incoming text against prompt injection and jailbreak signatures
    after thorough normalization.
    """
    
    INJECTION_PATTERNS = [
        re.compile(r'ignore\s+(previous|prior|all|above)\s+instructions?', re.IGNORECASE),
        re.compile(r'disregard\s+(previous|prior|all|above)\s+(instructions?|rules?|guidelines?)', re.IGNORECASE),
        re.compile(r'forget\s+(previous|prior|all|above)\s+(instructions?|rules?|prompt)', re.IGNORECASE),
        re.compile(r'override\s+(previous|prior|system)\s+(instructions?|prompt|rules?)', re.IGNORECASE),
        re.compile(r'reveal\s+(system\s+prompt|password|api\s+key|secret)', re.IGNORECASE),
        re.compile(r'print\s+(system\s+prompt|password|api\s+key|secret)', re.IGNORECASE),
        re.compile(r'repeat\s+(after\s+me|system\s+prompt|instructions?)', re.IGNORECASE),
    ]

    @classmethod
    def evaluate(cls, text: str) -> dict:
        """
        Normalizes text and evaluates it against known attack signatures.
        """
        if not isinstance(text, str):
            text = str(text)

        # Directly call full_normalize() as mandated by architecture
        normalized_text = InputNormalizer.full_normalize(text)

        for pattern in cls.INJECTION_PATTERNS:
            if pattern.search(normalized_text):
                return {
                    "blocked": True,
                    "reason": "Matched prompt injection signature"
                }

        return {
            "blocked": False,
            "reason": "Passed inspection"
        }
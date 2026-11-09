"""
Security shield module for AI-Sentinel Guardrails.
Performs input sanitization and prompt injection threat detection.
"""

import re
from ai_sentinel.core.normalizer import InputNormalizer

class SecurityShield:
    """
    Core security shield evaluating input payloads against prompt injection
    and evasion attacks.
    """

    # Generalized behavioral attack patterns
    ATTACK_PATTERNS = [
        re.compile(r'ignore\s+(previous|prior|all)\s+instructions?', re.IGNORECASE),
        re.compile(r'system\s+prompt', re.IGNORECASE),
        re.compile(r'override\s+(rules|guidelines|directives)', re.IGNORECASE),
        re.compile(r'reveal\s+(password|api\s+key|secret)', re.IGNORECASE),
    ]

    @classmethod
    def evaluate(cls, text: str) -> dict:
        """
        Normalizes the input text directly and evaluates it against threat patterns.
        """
        # Directly call full_normalize with no silent hasattr fallbacks
        cleaned_text = InputNormalizer.full_normalize(text)

        matched_threats = []
        for pattern in cls.ATTACK_PATTERNS:
            if pattern.search(cleaned_text):
                matched_threats.append(pattern.pattern)

        is_blocked = len(matched_threats) > 0

        return {
            "original_text": text,
            "cleaned_text": cleaned_text,
            "blocked": is_blocked,
            "matched_threats": matched_threats,
            "verdict": "BLOCK" if is_blocked else "ALLOW"
        }
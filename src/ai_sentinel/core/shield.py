"""
Security shield and rule evaluation engine for AI-Sentinel.
"""

import re
from ai_sentinel.core.normalizer import InputNormalizer

class SecurityShield:
    # Generalized attack signatures targeting actions near sensitive targets
    SIGNATURES = [
        r"(ignore|disregard|forget|override|reveal|print|repeat)\b.*(instructions|rules|system prompt|guidelines|password|api key)",
    ]

    @staticmethod
    def evaluate(text: str) -> dict:
        # Directly call full_normalize() with no hasattr or silent except
        normalized_text = InputNormalizer.full_normalize(text)

        for pattern in SecurityShield.SIGNATURES:
            if re.search(pattern, normalized_text, re.IGNORECASE):
                return {"blocked": True, "matched_pattern": pattern, "normalized_text": normalized_text}

        return {"blocked": False, "matched_pattern": None, "normalized_text": normalized_text}
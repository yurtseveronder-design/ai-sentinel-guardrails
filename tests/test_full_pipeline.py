"""
Input Normalizer module for AI-Sentinel Guardrails.
Removes zero-width characters, normalizes unicode, and cleans input text before shield evaluation.
"""

import unicodedata
from typing import Dict, Any

class InputNormalizer:
    ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff"]

    @classmethod
    def normalize(cls, text: str) -> Dict[str, Any]:
        if not text:
            return {"cleaned_text": "", "modifications": []}

        modifications = []
        original_text = text
        cleaned = text

        # Strip zero-width characters
        for zwc in cls.ZERO_WIDTH_CHARS:
            if zwc in cleaned:
                cleaned = cleaned.replace(zwc, "")
                modifications.append("Removed zero-width characters")

        # Unicode Normalization (NFKC)
        cleaned = unicodedata.normalize("NFKC", cleaned)

        return {
            "cleaned_text": cleaned,
            "modifications": modifications
        }
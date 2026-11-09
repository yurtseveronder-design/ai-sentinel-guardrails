"""
Advanced Input Normalizer for AI-Sentinel Guardrails.
Handles Unicode normalization, zero-width character removal, bidi overrides, 
and obfuscation detection.
"""

import unicodedata
import re
from typing import Dict, Any

class InputNormalizer:
    # Zero-width, soft hyphens, and formatting characters often used to smuggle prompts
    INVISIBLE_CHARS = re.compile(
        r"[\u200b\u200c\u200d\u200e\u200f\u2028\u2029\u202a\u202b\u202c\u202d\u202e\ufeff\u00ad]"
    )
    
    # Control characters control matching
    CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")

    @classmethod
    def normalize(cls, text: str) -> Dict[str, Any]:
        """
        Normalizes input text by performing Unicode NFKC conversion,
        stripping invisible/zero-width smuggling characters, and checking for obfuscation.
        """
        if not isinstance(text, str):
            return {"cleaned_text": "", "modifications": ["invalid_type"]}

        original_length = len(text)
        modifications = []

        # 1. Unicode NFKC normalization (canonical decomposition + compatibility composition)
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            modifications.append("unicode_nfkc")

        # 2. Strip invisible zero-width and bidi override characters
        if cls.INVISIBLE_CHARS.search(normalized):
            normalized = cls.INVISIBLE_CHARS.sub("", normalized)
            modifications.append("stripped_invisible_chars")

        # 3. Strip raw control characters
        if cls.CONTROL_CHARS.search(normalized):
            normalized = cls.CONTROL_CHARS.sub("", normalized)
            modifications.append("stripped_control_chars")

        # 4. Normalize whitespace (collapse excessive spacing/newlines used in layout attacks)
        cleaned_text = " ".join(normalized.split())
        if cleaned_text != normalized.strip():
            modifications.append("normalized_whitespace")

        return {
            "original_text": text,
            "cleaned_text": cleaned_text,
            "modifications": modifications,
            "length_delta": len(cleaned_text) - original_length
        }
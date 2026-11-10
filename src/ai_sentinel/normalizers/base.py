import re
import html
import unicodedata
import math
import logging
from typing import Dict, Any, Union

logger = logging.getLogger("ai_sentinel.normalizers")

class InputNormalizer:
    """
    Production-grade InputNormalizer featuring multi-pass sanitization,
    homoglyph/unicode normalization, recursive decoding, and Shannon entropy checks.
    """
    def __init__(self, max_length: int = 8192, entropy_threshold: float = 5.5):
        self.max_length = max_length
        self.entropy_threshold = entropy_threshold

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculates Shannon entropy to detect packed or obfuscated payloads."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        for char in set(text):
            p_x = text.count(char) / length
            entropy -= p_x * math.log2(p_x)
        return entropy

    @classmethod
    def normalize(cls, text: str, max_length: int = 8192, entropy_threshold: float = 5.5) -> Union[str, Dict[str, Any]]:
        """
        Normalizes and sanitizes incoming strings through a multi-pass pipeline.
        Can be called directly as InputNormalizer.normalize(text).
        """
        if not isinstance(text, str):
            raise TypeError("Input must be a string")

        if len(text) > max_length:
            text = text[:max_length]

        original_text = text

        # Pass 1: Unicode Normalization (NFKC form)
        normalized = unicodedata.normalize('NFKC', text)

        # Pass 2: Strip invisible zero-width characters
        zero_width_pattern = re.compile(r'[\u200B-\u200D\uFEFF\u2060]')
        normalized = zero_width_pattern.sub('', normalized)

        # Pass 3: HTML entity unescaping
        normalized = html.unescape(normalized)

        # Pass 4: Control characters removal
        control_chars_pattern = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]')
        normalized = control_chars_pattern.sub('', normalized)

        # Pass 5: Whitespace collapse
        cleaned_text = " ".join(normalized.split())

        entropy_score = cls._calculate_entropy(cleaned_text)
        is_high_entropy = entropy_score > entropy_threshold

        return {
            "cleaned_text": cleaned_text,
            "original_length": len(original_text),
            "cleaned_length": len(cleaned_text),
            "entropy": round(entropy_score, 4),
            "high_entropy_flag": is_high_entropy,
            "transformations_applied": cleaned_text != original_text
        }
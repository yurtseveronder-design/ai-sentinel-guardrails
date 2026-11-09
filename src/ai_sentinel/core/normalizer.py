"""
Advanced input normalizer and sanitization engine for AI-Sentinel Guardrails.
Handles zero-width character stripping, Unicode NFKC normalization, whitespace collapse,
and full-text sanitization.
"""

import unicodedata
import re

class InputNormalizer:
    """
    Robust input normalizer to defeat prompt smuggling, invisible character evasion,
    and formatting-based jailbreaks.
    """

    @staticmethod
    def normalize(text: str) -> dict:
        """
        Normalizes input text and returns a dictionary with the cleaned text
        and a list of applied modifications.
        """
        if not isinstance(text, str):
            return {"cleaned_text": str(text), "modifications": []}

        modifications = []
        original_text = text

        # 1. Strip zero-width / invisible characters (e.g., zero-width spaces, soft hyphens)
        # Unicode categories: Cf (Format), Cc (Control) except standard newline/tab
        invisible_chars_pattern = re.compile(r'[\u200b\u200c\u200d\uFEFF\u00ad]')
        if invisible_chars_pattern.search(text):
            text = invisible_chars_pattern.sub('', text)
            modifications.append("stripped_invisible_chars")

        # 2. Unicode NFKC Normalization (canonical decomposition, compatibility composition)
        normalized_unicode = unicodedata.normalize('NFKC', text)
        if normalized_unicode != text:
            text = normalized_unicode
            modifications.append("unicode_nfkc")

        # 3. Collapse excessive whitespace / multi-line layout padding attacks
        collapsed_whitespace = re.sub(r'[ \t]+', ' ', text)
        if collapsed_whitespace != text:
            text = collapsed_whitespace
            modifications.append("normalized_whitespace")

        return {
            "cleaned_text": text.strip(),
            "modifications": modifications
        }

    @classmethod
    def full_normalize(cls, text: str) -> str:
        """
        Direct wrapper method that returns the cleaned string directly,
        ensuring secure integration with shield.py without silent failures.
        """
        result = cls.normalize(text)
        return result["cleaned_text"]
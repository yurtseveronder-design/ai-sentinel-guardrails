"""
Input Normalizer module for AI-Sentinel Guardrails.
Cleans, sanitizes, and normalizes input prompts before security evaluation.
"""

import re
import html
from urllib.parse import unquote
from typing import Dict, Any

class InputNormalizer:
    @staticmethod
    def normalize(text: str) -> Dict[str, Any]:
        """
        Normalizes input prompt text.
        Returns cleaned text and a list of modifications applied.
        """
        if not text:
            return {"cleaned_text": "", "modifications": []}

        modifications = []
        cleaned = text

        # 1. Zero-width / invisible character stripping
        invisible_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        has_invisible = any(char in cleaned for char in invisible_chars)
        if has_invisible:
            for char in invisible_chars:
                cleaned = cleaned.replace(char, "")
            modifications.append("stripped_invisible_chars")

        # 2. HTML entity decoding
        decoded_html = html.unescape(cleaned)
        if decoded_html != cleaned:
            cleaned = decoded_html
            modifications.append("decoded_html_entities")

        # 3. URL decoding
        decoded_url = unquote(cleaned)
        if decoded_url != cleaned:
            cleaned = decoded_url
            modifications.append("decoded_url_encoding")

        # 4. Homoglyph normalization
        homoglyph_map = {
            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
            "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X"
        }
        original_before_homoglyph = cleaned
        for cyr, lat in homoglyph_map.items():
            cleaned = cleaned.replace(cyr, lat)
        if cleaned != original_before_homoglyph:
            modifications.append("normalized_homoglyphs")

        # 5. Whitespace collapse
        collapsed = re.sub(r"[ \t]+", " ", cleaned).strip()
        if collapsed != cleaned:
            cleaned = collapsed
            modifications.append("collapsed_whitespace")

        return {
            "cleaned_text": cleaned,
            "modifications": modifications
        }
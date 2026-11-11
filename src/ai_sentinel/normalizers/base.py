"""
Live normalizer module for AI Sentinel.
Handles zero-width character stripping, URL decoding, Cyrillic homoglyph folding, whitespace collapse, and entropy computation.
"""

import math
import urllib.parse
import unicodedata

class InputNormalizer:
    def __init__(self):
        # Mapping for common Cyrillic homoglyphs to Latin equivalents
        self.homoglyph_map = {
            'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j',
            'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'ѕ': 's',
            'А': 'A', 'С': 'C', 'Е': 'E', 'І': 'I', 'О': 'O',
            'Р': 'P', 'Х': 'X', 'У': 'Y', 'Н': 'H', 'М': 'M', 'Т': 'T'
        }

    def fold_homoglyphs(self, text: str) -> str:
        normalized = unicodedata.normalize('NFKC', text)
        return "".join(self.homoglyph_map.get(char, char) for char in normalized)

    def normalize(self, text: str) -> dict:
        if not text:
            return {
                "cleaned_text": "",
                "normalized_text": "",
                "entropy": 0.0
            }

        # 1. URL Decode
        try:
            decoded = urllib.parse.unquote(text)
        except Exception:
            decoded = text

        # 2. Strip zero-width characters
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        cleaned = decoded
        for zw in zero_width_chars:
            cleaned = cleaned.replace(zw, "")

        # 3. Fold Cyrillic homoglyphs
        normalized_text = self.fold_homoglyphs(cleaned)

        # 4. Collapse whitespace (normalize multiple whitespaces/tabs/newlines to single space and strip)
        import re
        collapsed_text = re.sub(r'\s+', ' ', normalized_text).strip()

        # 5. Compute Shannon entropy
        entropy = self.compute_entropy(collapsed_text)

        return {
            "cleaned_text": collapsed_text,
            "normalized_text": collapsed_text,
            "entropy": entropy
        }

    def compute_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return round(entropy, 4)
"""
Input normalizer module for AI-Sentinel Guardrails.
Handles zero-width stripping, homoglyph normalization, URL/HTML decoding, and whitespace cleaning.
"""

import re
import urllib.parse
import html

class InputNormalizer:
    # Homoglyph mapping table for common Cyrillic/Greek lookalikes to ASCII
    HOMOGLYPH_MAP = {
        '\u0430': 'a',  # Cyrillic small a
        '\u0435': 'e',  # Cyrillic small ie
        '\u043e': 'o',  # Cyrillic small o
        '\u0440': 'p',  # Cyrillic small er
        '\u0441': 'c',  # Cyrillic small es
        '\u0445': 'x',  # Cyrillic small ha
        '\u044b': 'y',  # Cyrillic small yeru
    }

    @classmethod
    def normalize(cls, prompt: str) -> dict:
        modifications = []
        original = prompt
        cleaned = prompt

        # 1. Decode URL encoding if present
        if '%' in cleaned:
            try:
                decoded = urllib.parse.unquote(cleaned)
                if decoded != cleaned:
                    cleaned = decoded
                    modifications.append("decoded_url_encoding")
            except Exception:
                pass

        # 2. Decode HTML entities
        if '&' in cleaned:
            decoded_html = html.unescape(cleaned)
            if decoded_html != cleaned:
                cleaned = decoded_html
                if "decoded_html_entities" not in modifications:
                    modifications.append("decoded_html_entities")

        # 3. Strip zero-width and invisible characters
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        for char in zero_width_chars:
            if char in cleaned:
                cleaned = cleaned.replace(char, "")
                if "stripped_invisible_chars" not in modifications:
                    modifications.append("stripped_invisible_chars")

        # 4. Normalize homoglyphs
        new_cleaned = []
        homoglyph_found = False
        for char in cleaned:
            if char in cls.HOMOGLYPH_MAP:
                new_cleaned.append(cls.HOMOGLYPH_MAP[char])
                homoglyph_found = True
            else:
                new_cleaned.append(char)
        cleaned = "".join(new_cleaned)
        if homoglyph_found and "normalized_homoglyphs" not in modifications:
            modifications.append("normalized_homoglyphs")

        # 5. Normalize whitespace
        normalized_ws = re.sub(r'\s+', ' ', cleaned).strip()
        if normalized_ws != cleaned:
            if "normalized_whitespace" not in modifications:
                modifications.append("normalized_whitespace")
        cleaned = normalized_ws

        return {
            "original_text": original,
            "cleaned_text": cleaned,
            "modifications": modifications
        }
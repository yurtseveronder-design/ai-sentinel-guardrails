"""
Advanced input normalizer and sanitization engine for AI-Sentinel Guardrails.
Handles zero-width character stripping, Unicode NFKC normalization, HTML/URL entity decoding,
and whitespace collapse.
"""

import unicodedata
import re
import html
import urllib.parse

class InputNormalizer:
    """
    Robust input normalizer to defeat prompt smuggling, invisible character evasion,
    HTML/URL encoding, and formatting-based jailbreaks.
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

        # 1. Decode HTML entities
        decoded_html = html.unescape(text)
        if decoded_html != text:
            text = decoded_html
            modifications.append("decoded_html_entities")

        # 2. Decode URL encoding
        try:
            decoded_url = urllib.parse.unquote(text)
            if decoded_url != text:
                text = decoded_url
                modifications.append("decoded_url_encoding")
        except Exception:
            pass

        # 3. Strip zero-width / invisible characters
        invisible_chars_pattern = re.compile(r'[\u200b\u200c\u200d\uFEFF\u00ad]')
        if invisible_chars_pattern.search(text):
            text = invisible_chars_pattern.sub('', text)
            modifications.append("stripped_invisible_chars")

        # 4. Unicode NFKC Normalization (handles full-width characters)
        normalized_unicode = unicodedata.normalize('NFKC', text)
        if normalized_unicode != original_text and normalized_unicode != text:
            text = normalized_unicode
            modifications.append("unicode_nfkc")

        # 5. Collapse excessive whitespace
        cleaned = text.strip()
        collapsed_whitespace = re.sub(r'[ \t\r\n]+', ' ', cleaned)
        if collapsed_whitespace != cleaned:
            cleaned = collapsed_whitespace
            modifications.append("normalized_whitespace")

        return {
            "cleaned_text": cleaned,
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
"""
Production-grade input normalizer and sanitization engine for AI-Sentinel Guardrails.
Features exhaustive multi-stage decoding, homoglyph neutralization, invisible character
stripping, Unicode NFKC normalization, and whitespace collapse.
"""

import unicodedata
import re
import html
import urllib.parse

class InputNormalizer:
    """
    Robust, multi-layered input normalizer designed to defeat prompt smuggling,
    invisible character injection, homoglyph substitution, and encoding evasion.
    """

    # Comprehensive homoglyph mapping (Cyrillic, Greek, and Full-Width lookalikes to Latin equivalents)
    HOMOGLYPH_MAP = {
        # Cyrillic lowercase & uppercase
        '\u0430': 'a', '\u0410': 'A',
        '\u0432': 'v', '\u0412': 'B',
        '\u0435': 'e', '\u0415': 'E',
        '\u043e': 'o', '\u041e': 'O',
        '\u0440': 'p', '\u0420': 'P',
        '\u0441': 'c', '\u0421': 'C',
        '\u0445': 'x', '\u0425': 'X',
        '\u0456': 'i', '\u0406': 'I',
        '\u0455': 's', '\u0405': 'S',
        '\u04bb': 'h',
        # Greek lookalikes
        '\u03bf': 'o', '\u0391': 'A',
        '\u0392': 'B', '\u0395': 'E',
        '\u0397': 'H', '\u0399': 'I',
        '\u039a': 'K', '\u039c': 'M',
        '\u039d': 'N', '\u039f': 'O',
        '\u03a1': 'P', '\u03a4': 'T',
        '\u03a7': 'X', '\u03a5': 'Y',
        # Full-width ASCII variants
        **{chr(code): chr(code - 65248) for code in range(65301, 65375)}
    }

    @classmethod
    def _normalize_homoglyphs(cls, text: str) -> str:
        return "".join(cls.HOMOGLYPH_MAP.get(char, char) for char in text)

    @staticmethod
    def normalize(text: str) -> dict:
        if not isinstance(text, str):
            return {"cleaned_text": str(text), "modifications": []}

        modifications = []
        original_text = text

        # 1. Recursive HTML entity decoding
        for _ in range(2):
            decoded_html = html.unescape(text)
            if decoded_html == text:
                break
            text = decoded_html
            if "decoded_html_entities" not in modifications:
                modifications.append("decoded_html_entities")

        # 2. Multi-pass URL decoding
        for _ in range(2):
            try:
                decoded_url = urllib.parse.unquote(text)
                if decoded_url == text:
                    break
                text = decoded_url
                if "decoded_url_encoding" not in modifications:
                    modifications.append("decoded_url_encoding")
            except Exception:
                break

        # 3. Strip zero-width, invisible formatting, and bidirectional override characters
        invisible_chars_pattern = re.compile(
            r'[\u200b\u200c\u200d\uFEFF\u00ad\u2060\u180e\u202a\u202b\u202c\u202d\u202e]'
        )
        if invisible_chars_pattern.search(text):
            text = invisible_chars_pattern.sub('', text)
            modifications.append("stripped_invisible_chars")

        # 4. Unicode NFKC Normalization (compatibility composition)
        normalized_unicode = unicodedata.normalize('NFKC', text)
        if normalized_unicode != text:
            text = normalized_unicode
            modifications.append("unicode_nfkc")

        # 5. Homoglyph neutralization
        normalized_homoglyphs = InputNormalizer._normalize_homoglyphs(text)
        if normalized_homoglyphs != text:
            text = normalized_homoglyphs
            modifications.append("normalized_homoglyphs")

        # 6. Collapse excessive whitespace and control characters
        cleaned = text.strip()
        collapsed_whitespace = re.sub(r'[ \t\r\n\v\f]+', ' ', cleaned)
        if collapsed_whitespace != cleaned:
            cleaned = collapsed_whitespace
            modifications.append("normalized_whitespace")

        return {
            "cleaned_text": cleaned,
            "modifications": modifications
        }

    @classmethod
    def full_normalize(cls, text: str) -> str:
        result = cls.normalize(text)
        return result["cleaned_text"]
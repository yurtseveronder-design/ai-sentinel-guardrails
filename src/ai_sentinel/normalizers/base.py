"""
Live normalizer module for AI Sentinel.
Handles zero-width stripping, URL decoding, Cyrillic homoglyph folding, 
whole-token Base64 decoding, whitespace collapse, entropy calculation, 
and oversize input rejection (> 8192 chars).
"""

import math
import base64
import re
import urllib.parse
import unicodedata

class InputNormalizer:
    def __init__(self, max_length: int = 8192):
        self.max_length = max_length
        self.homoglyph_map = {
            'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j',
            'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'ѕ': 's',
            'А': 'A', 'С': 'C', 'Е': 'E', 'І': 'I', 'О': 'O',
            'Р': 'P', 'Х': 'X', 'У': 'Y', 'Н': 'H', 'М': 'M', 'Т': 'T'
        }

    def fold_homoglyphs(self, text: str) -> str:
        normalized = unicodedata.normalize('NFKC', text)
        return "".join(self.homoglyph_map.get(char, char) for char in normalized)

    # Shorter tokens are ordinary words far more often than real payloads
    # ("Show", "test", "code" are all valid Base64).
    MIN_BASE64_TOKEN_LENGTH = 8
    MIN_PRINTABLE_RATIO = 0.9
    MIN_TEXT_RATIO = 0.6  # letters/spaces; real payloads are prose, not symbol noise

    def _try_decode_base64_token(self, token: str):
        """Return the decoded text if the token is plausible Base64 text, else None."""
        if len(token) < self.MIN_BASE64_TOKEN_LENGTH or len(token) % 4 != 0:
            return None
        if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', token):
            return None
        try:
            decoded = base64.b64decode(token, validate=True).decode('utf-8')
        except Exception:
            return None
        if not decoded:
            return None
        printable = sum(1 for ch in decoded if ch.isprintable() or ch.isspace())
        if printable / len(decoded) < self.MIN_PRINTABLE_RATIO:
            return None
        texty = sum(1 for ch in decoded if ch.isalpha() or ch.isspace())
        if texty / len(decoded) < self.MIN_TEXT_RATIO:
            return None
        return decoded

    def decode_base64_tokens(self, text: str) -> str:
        """Append the decoded form after each plausible Base64 token.

        The original token is kept, so a normal word that happens to look like
        Base64 is never replaced by garbage.
        """
        tokens = re.findall(r'\S+|\s+', text)
        out = []
        for token in tokens:
            decoded = self._try_decode_base64_token(token)
            out.append(token if decoded is None else f"{token} {decoded}")
        return "".join(out)

    def normalize(self, text: str) -> dict:
        if not text:
            return {
                "cleaned_text": "",
                "normalized_text": "",
                "entropy": 0.0,
                "status": "ALLOW"
            }

        # Prevent silent truncation: reject oversize input exceeding max_length
        if len(text) > self.max_length:
            return {
                "cleaned_text": "",
                "normalized_text": "",
                "entropy": 0.0,
                "status": "REJECT_OVERSIZE",
                "error": f"Input exceeds maximum allowed length of {self.max_length} characters."
            }

        # 1. URL Decode
        try:
            decoded = urllib.parse.unquote(text)
        except Exception:
            decoded = text

        # 2. Decode whole-token Base64
        b64_decoded = self.decode_base64_tokens(decoded)

        # 3. Strip zero-width characters
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        cleaned = b64_decoded
        for zw in zero_width_chars:
            cleaned = cleaned.replace(zw, "")

        # 4. Fold Cyrillic homoglyphs
        normalized_text = self.fold_homoglyphs(cleaned)

        # 5. Collapse whitespace
        collapsed_text = re.sub(r'\s+', ' ', normalized_text).strip()

        # 6. Compute Shannon entropy
        entropy = self.compute_entropy(collapsed_text)

        return {
            "cleaned_text": collapsed_text,
            "normalized_text": collapsed_text,
            "entropy": entropy,
            "status": "ALLOW"
        }

    def compute_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return round(entropy, 4)
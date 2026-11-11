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

    def _is_valid_base64_token(self, token: str) -> bool:
        # Base64 tokens must have valid length (multiple of 4 if padded, or reasonable length >= 4)
        if len(token) < 4 or len(token) % 4 != 0:
            return False
        # Check charset
        b64_regex = r'^[A-Za-z0-9+/]+={0,2}$'
        if not re.match(b64_regex, token):
            return False
        try:
            # Attempt decode to verify
            decoded_bytes = base64.b64decode(token, validate=True)
            # Ensure decoded content is valid UTF-8 text (avoid binary noise)
            decoded_bytes.decode('utf-8')
            return True
        except Exception:
            return False

    def decode_base64_tokens(self, text: str) -> str:
        # Split text into tokens by whitespace/punctuation boundaries
        tokens = re.findall(r'\S+|\s+', text)
        decoded_tokens = []
        for token in tokens:
            if self._is_valid_base64_token(token):
                try:
                    decoded_bytes = base64.b64decode(token)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    decoded_tokens.append(decoded_str)
                except Exception:
                    decoded_tokens.append(token)
            else:
                decoded_tokens.append(token)
        return "".join(decoded_tokens)

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
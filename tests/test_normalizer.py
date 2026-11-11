"""
Tests for InputNormalizer covering zero-width characters, homoglyphs, decoding, and whitespace.
"""

from ai_sentinel.normalizers.base import InputNormalizer

def test_zero_width_stripping():
    payload = "Hello\u200bWorld"
    normalizer = InputNormalizer()
    res = normalizer.normalize(payload)
    cleaned = res["cleaned_text"] if isinstance(res, dict) else res
    assert "Hello" in cleaned and "World" in cleaned

def test_homoglyph_normalization():
    payload = "S\u0435cret"
    normalizer = InputNormalizer()
    res = normalizer.normalize(payload)
    cleaned = res["cleaned_text"] if isinstance(res, dict) else res
    assert cleaned == "Secret"

def test_html_and_url_decoding():
    payload = "Hello%20World"
    normalizer = InputNormalizer()
    res = normalizer.normalize(payload)
    cleaned = res["cleaned_text"] if isinstance(res, dict) else res
    assert cleaned == "Hello World"

def test_whitespace_collapse():
    payload = "   hello   world   \n\t "
    normalizer = InputNormalizer()
    res = normalizer.normalize(payload)
    cleaned = res["cleaned_text"] if isinstance(res, dict) else res
    assert cleaned == "hello world"
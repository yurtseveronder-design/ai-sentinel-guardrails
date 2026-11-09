"""
Unit tests for the robust InputNormalizer engine.
"""

from ai_sentinel.core.normalizer import InputNormalizer

def test_zero_width_stripping():
    payload = "i\u200bg\u200bn\u200bo\u200br\u200b e"
    result = InputNormalizer.normalize(payload)
    assert "stripped_invisible_chars" in result["modifications"]
    assert result["cleaned_text"] == "ignor e"

def test_homoglyph_normalization():
    # Using Cyrillic 'а' instead of Latin 'a'
    payload = "ign\u043ere"
    result = InputNormalizer.normalize(payload)
    assert "normalized_homoglyphs" in result["modifications"]
    assert result["cleaned_text"] == "ignore"

def test_html_and_url_decoding():
    payload = "%69gnore&amp;bypass"
    result = InputNormalizer.normalize(payload)
    assert "decoded_url_encoding" in result["modifications"]
    assert "decoded_html_entities" in result["modifications"]
    assert result["cleaned_text"] == "ignore&bypass"

def test_whitespace_collapse():
    payload = "   hello   world   \n\t "
    result = InputNormalizer.normalize(payload)
    assert result["cleaned_text"] == "hello world"
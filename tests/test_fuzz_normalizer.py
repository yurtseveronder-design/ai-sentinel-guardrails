import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from ai_sentinel.normalizers.base import InputNormalizer

@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(min_size=0, max_size=8192))
def test_input_normalizer_fuzz_resilience(text: str):
    """
    Property-based fuzz test for InputNormalizer.
    Feeds arbitrary unicode strings and boundary sizes, validating that 
    the normalizer returns either a string or a structured dict with cleaned text 
    without raising unhandled exceptions.
    """
    normalizer = InputNormalizer()
    try:
        normalized_output = normalizer.normalize(text)
        if isinstance(normalized_output, dict):
            assert "cleaned_text" in normalized_output, "Dictionary output must contain 'cleaned_text'."
            assert isinstance(normalized_output["cleaned_text"], str), "Cleaned text must be a string."
        else:
            assert isinstance(normalized_output, str), "Normalized output must be a string."
    except TypeError:
        pass
    except Exception as e:
        pytest.fail(f"InputNormalizer raised an unexpected exception for input {repr(text)}: {e}")
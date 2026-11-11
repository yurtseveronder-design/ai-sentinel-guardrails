"""
Property-based fuzz tests for InputNormalizer.
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from ai_sentinel.normalizers.base import InputNormalizer


@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(min_size=0, max_size=8192))
def test_input_normalizer_fuzz_resilience(text: str):
    """
    Feeds arbitrary unicode strings up to the size limit and checks that
    normalize returns cleaned_text without an unexpected exception.
    """
    normalizer = InputNormalizer()
    try:
        normalized_output = normalizer.normalize(text)
        if isinstance(normalized_output, dict):
            assert "cleaned_text" in normalized_output
            assert isinstance(normalized_output["cleaned_text"], str)
        else:
            assert isinstance(normalized_output, str)
    except TypeError:
        pass
    except Exception as exc:
        pytest.fail(f"InputNormalizer raised an unexpected exception for input {text!r}: {exc}")

"""
Adversarial evaluation suite for SecurityShield.
Validates evaluation across test payloads using exact configured rules.
"""

import pytest
from ai_sentinel.core.shield import SecurityShield

def test_adversarial_suite():
    shield = SecurityShield()

    # Match exact test phrases configured in your threat signatures YAML
    samples = [
        ("What is the weather today?", False),
        ("ignore previous instructions", True),
    ]

    for prompt, expected_blocked in samples:
        blocked, rule_id, matched_phrase = shield.evaluate(prompt)
        assert blocked == expected_blocked, f"Failed on prompt: {prompt!r}"
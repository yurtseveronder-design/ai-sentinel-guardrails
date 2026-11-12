"""
Adversarial evaluation tests for AI Sentinel.

Cases are loaded from tests/data/adversarial_dataset.json.
"""

import json
from pathlib import Path

import pytest

from ai_sentinel.core.shield import SecurityShield

_DATASET_PATH = Path(__file__).resolve().parent / "data" / "adversarial_dataset.json"
_CASES = json.loads(_DATASET_PATH.read_text(encoding="utf-8"))

_RULE_IDS = {
    "benign": None,
    "pii": "email_pii_leak",
    "secret": "api_key_secret_leak",
    "zero_width_injection": "prompt_injection_override",
    "homoglyph_secret": "secret_keyword",
    "base64_payload": "system_attack_instruction",
    "multilingual_injection": "multilingual_instruction",
}


def _parameters():
    return [
        pytest.param(item, id=f"{index}-{item['category']}")
        for index, item in enumerate(_CASES)
    ]


@pytest.mark.parametrize("item", _parameters())
def test_adversarial_case(item):
    result = SecurityShield().evaluate(item["prompt"])
    expected_rule = _RULE_IDS[item["category"]]
    expected_action = item.get(
        "expected_action", "BLOCK" if item["expected_blocked"] else "ALLOW"
    )
    if expected_action != "ALLOW":
        assert result["action"] == expected_action
        assert expected_rule in result["matched_rules"]
    else:
        assert result["action"] == "ALLOW"
        assert result["matched_rules"] == []

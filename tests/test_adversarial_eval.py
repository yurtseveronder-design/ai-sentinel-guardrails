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
    parameters = []
    for index, item in enumerate(_CASES):
        case_id = f"{index}-{item['category']}"
        if item["category"] == "multilingual_injection":
            parameters.append(
                pytest.param(
                    item,
                    id=case_id,
                    marks=pytest.mark.xfail(
                        reason="Multilingual instruction signatures are not implemented",
                        strict=True,
                    ),
                )
            )
        else:
            parameters.append(pytest.param(item, id=case_id))
    return parameters


@pytest.mark.parametrize("item", _parameters())
def test_adversarial_case(item):
    result = SecurityShield().evaluate(item["prompt"])
    expected_rule = _RULE_IDS[item["category"]]
    if item["expected_blocked"]:
        assert result["action"] == "BLOCK"
        assert expected_rule in result["matched_rules"]
    else:
        assert result["action"] == "ALLOW"
        assert result["matched_rules"] == []

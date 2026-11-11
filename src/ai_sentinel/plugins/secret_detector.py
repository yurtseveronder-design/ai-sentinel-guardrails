"""
Secret and entropy detector plugin for AI Sentinel.

Threat signatures are loaded from config/threat_signatures.yaml inside the
package. A missing file or a file with no patterns refuses to start.
"""

import math
import re
from importlib.resources import files
from pathlib import Path

import yaml


class SecretDetectorPlugin:
    def __init__(self, config_path: str = "config/threat_signatures.yaml"):
        self.config_path = config_path
        self.rules = self._load_rules()

    def _read_config_text(self) -> str:
        path = Path(self.config_path)
        if path.is_absolute():
            if not path.is_file():
                raise RuntimeError(
                    "AI-Sentinel refused to start: threat signatures file is missing "
                    f"({path})"
                )
            return path.read_text(encoding="utf-8")

        resource = files("ai_sentinel").joinpath(*path.parts)
        if not resource.is_file():
            raise RuntimeError(
                "AI-Sentinel refused to start: threat signatures file is missing "
                f"({self.config_path})"
            )
        return resource.read_text(encoding="utf-8")

    def _load_rules(self) -> list:
        try:
            data = yaml.safe_load(self._read_config_text())
        except yaml.YAMLError as exc:
            raise RuntimeError(
                "AI-Sentinel refused to start: threat signatures file is invalid"
            ) from exc

        raw_rules = data.get("rules") if isinstance(data, dict) else None
        if not isinstance(raw_rules, list):
            raise RuntimeError(
                "AI-Sentinel refused to start: threat signatures file has no patterns"
            )

        loaded = []
        for rule in raw_rules:
            if not isinstance(rule, dict):
                continue
            pattern = rule.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                continue
            rule_id = rule.get("id") or "unknown_rule"
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                raise RuntimeError(
                    "AI-Sentinel refused to start: threat signatures file has an "
                    f"invalid pattern ({rule_id})"
                ) from exc
            loaded.append({"id": rule_id, "pattern": compiled})

        if not loaded:
            raise RuntimeError(
                "AI-Sentinel refused to start: threat signatures file has no patterns"
            )
        return loaded

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        from collections import Counter
        counts = Counter(text)
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def validate(self, text: str, strict: bool = False) -> dict:
        matched_rules = []
        reasons = []

        for rule in self.rules:
            if rule["pattern"].search(text):
                matched_rules.append(rule["id"])

        entropy_val = self._calculate_entropy(text)
        is_high_entropy = entropy_val > 4.5
        if is_high_entropy:
            reasons.append("high_entropy_detected")

        action = "ALLOW"
        risk_level = "LOW"
        should_block = False

        if matched_rules:
            should_block = True
            action = "BLOCK"
            risk_level = "HIGH"
        elif is_high_entropy and strict:
            should_block = True
            action = "BLOCK"
            risk_level = "MEDIUM"
        elif is_high_entropy:
            risk_level = "MEDIUM"

        return {
            "action": action,
            "flagged": should_block,
            "risk_level": risk_level,
            "matched_rules": matched_rules,
            "reasons": reasons,
        }

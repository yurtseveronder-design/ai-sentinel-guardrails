"""
Secret and entropy detector plugin for AI Sentinel.
"""

import os
import yaml
import re
import math

class SecretDetectorPlugin:
    def __init__(self, config_path="config/threat_signatures.yaml"):
        self.config_path = config_path
        self.rules = self._load_rules()

    def _load_rules(self) -> list:
        if not os.path.exists(self.config_path):
            return []
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("rules", [])
        except Exception:
            return []

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0
        length = len(text)
        from collections import Counter
        counts = Counter(text)
        for count in counts.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        return entropy

    def validate(self, text: str, strict: bool = False) -> dict:
        matched_rules = []
        reasons = []

        # 1. Check Signature Regex Rules
        for rule in self.rules:
            pattern = rule.get("pattern", "")
            if pattern and isinstance(pattern, str):
                if re.search(pattern, text, re.IGNORECASE):
                    matched_rules.append(rule.get("id", "unknown_rule"))

        # 2. Check Entropy
        entropy_val = self._calculate_entropy(text)
        high_entropy_threshold = 4.5  # Example threshold for high entropy (JSON/code/keys)
        is_high_entropy = entropy_val > high_entropy_threshold

        if is_high_entropy:
            reasons.append("high_entropy_detected")

        # 3. Decision Logic
        # Block if a rule matches OR (strict mode is True AND high entropy is present)
        should_block = False
        action = "ALLOW"
        risk_level = "LOW"

        if matched_rules:
            should_block = True
            action = "BLOCK"
            risk_level = "HIGH"
        elif is_high_entropy and strict:
            should_block = True
            action = "BLOCK"
            risk_level = "MEDIUM"
        elif is_high_entropy:
            # High entropy alone is MEDIUM and a reason, but does NOT block by default
            risk_level = "MEDIUM"

        return {
            "action": action,
            "flagged": should_block,
            "risk_level": risk_level,
            "matched_rules": matched_rules,
            "reasons": reasons
        }
"""
Secret detector plugin for AI Sentinel.
Loads threat signatures from YAML and scans input texts for regex pattern matches.
"""

import os
import yaml
import re

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

    def validate(self, text: str) -> dict:
        matched_rules = []
        for rule in self.rules:
            pattern = rule.get("pattern", "")
            if isinstance(pattern, (list, tuple)):
                pattern = "".join(str(p) for p in pattern)
            
            if pattern and isinstance(pattern, str):
                if re.search(pattern, text, re.IGNORECASE):
                    matched_rules.append(rule.get("id", "unknown_rule"))

        if matched_rules:
            return {
                "action": "BLOCK",
                "flagged": True,
                "matched_rules": matched_rules
            }

        return {
            "action": "ALLOW",
            "flagged": False,
            "matched_rules": []
        }
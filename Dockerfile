"""
Secret detector plugin for AI Sentinel.
"""

import os
import yaml
from ai_sentinel.core.base import BaseGuardrail

class SecretDetectorPlugin(BaseGuardrail):
    def __init__(self, config_path="config/threat_signatures.yaml"):
        self.patterns = []
        self._load_config(config_path)

    def _load_config(self, config_path):
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                # Extract regex patterns from config, storing patterns and not sample strings
                for rule in data.get("secrets", []):
                    if "pattern" in rule:
                        self.patterns.append(rule["pattern"])
        
        # Fallback if config is missing or lacks secrets
        if not self.patterns:
            self.patterns.append(r"sk-[A-Za-z0-9-]{20,}")

    def validate(self, text: str) -> dict:
        import re
        matched_rules = []
        for pattern in self.patterns:
            if re.search(pattern, text):
                matched_rules.append(pattern)

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
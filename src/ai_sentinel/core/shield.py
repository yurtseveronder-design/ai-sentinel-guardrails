"""
SecurityShield implementation.
"""

import os
import yaml
from ai_sentinel.guardrails.base import BaseGuardrail, GuardrailResult

class SecurityShield(BaseGuardrail):
    def __init__(self, config_path="config/threat_signatures.yaml"):
        self.rules = []
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    self.rules = data["rules"]

    def evaluate(self, text: str) -> GuardrailResult:
        if not isinstance(text, str):
            text = str(text)

        lower_text = text.lower()
        matched_rules = []
        
        for rule in self.rules:
            phrase = rule.get("phrase", "")
            rule_id = rule.get("id", "unknown_rule")
            if phrase and phrase.lower() in lower_text:
                matched_rules.append(rule_id)

        flagged = len(matched_rules) > 0
        action = "BLOCK" if flagged else "ALLOW"

        return GuardrailResult(
            action=action,
            flagged=flagged,
            matched_rules=matched_rules,
            sanitized_text=text
        )
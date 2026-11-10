"""
SecurityShield module for evaluating prompts against loaded threat signatures.
"""

import os
import yaml

class SecurityShield:
    def __init__(self, config_path="config/threat_signatures.yaml"):
        self.rules = []
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    self.rules = data["rules"]

    def evaluate(self, text: str):
        """
        Evaluates input text against threat signature rules.
        Returns:
            tuple: (blocked: bool, rule_id: str or None, matched_phrase: str or None)
        """
        if not isinstance(text, str):
            text = str(text)

        lower_text = text.lower()
        for rule in self.rules:
            phrase = rule.get("phrase", "")
            if phrase and phrase.lower() in lower_text:
                return True, rule.get("id"), phrase

        return False, None, None
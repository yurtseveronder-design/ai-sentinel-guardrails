"""
Security Shield module for AI-Sentinel Guardrails.
Combines rule-based YAML threat signatures with semantic similarity detection.
"""

import os
import re
import yaml
from typing import Dict, Any, List
from ai_sentinel.core.semantic_shield import SemanticShield

class SecurityShield:
    _rules = None

    @classmethod
    def _load_rules(cls) -> List[Dict[str, Any]]:
        if cls._rules is not None:
            return cls._rules
        
        # Try multiple relative paths to ensure rules are always found
        possible_paths = [
            os.path.join(os.getcwd(), "config", "threat_signatures.yaml"),
            os.path.join(os.path.dirname(__file__), "..", "..", "config", "threat_signatures.yaml"),
            "config/threat_signatures.yaml"
        ]
        
        for rules_path in possible_paths:
            if os.path.exists(rules_path):
                with open(rules_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "rules" in data:
                        cls._rules = data.get("rules", [])
                        return cls._rules

        cls._rules = []
        return cls._rules

    @classmethod
    def evaluate(cls, text: str) -> Dict[str, Any]:
        """
        Evaluates text against YAML signature rules and semantic attack clusters.
        Always returns a standardized dictionary guaranteed to have the 'blocked' key.
        """
        if not text or not text.strip():
            return {"blocked": False}

        rules = cls._load_rules()
        lower_text = text.lower()

        for rule in rules:
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            
            matched = False
            cleaned_pattern = pattern.replace("\\\\", "\\")

            try:
                if re.search(cleaned_pattern, text, re.IGNORECASE) or re.search(cleaned_pattern.lower(), lower_text, re.IGNORECASE):
                    matched = True
            except Exception:
                pass

            if not matched and pattern.lower() in lower_text:
                matched = True

            if matched:
                return {
                    "blocked": True,
                    "rule_id": rule.get("id", "SIG-001"),
                    "matched_pattern": rule.get("name", pattern),
                    "severity": rule.get("severity", "high")
                }

        # Stage 2: Semantic Similarity Detection (Fail-open)
        semantic_result = SemanticShield.evaluate(text)
        if semantic_result.get("blocked"):
            return semantic_result

        return {"blocked": False}
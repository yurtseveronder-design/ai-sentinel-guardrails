"""
Security Shield module for AI-Sentinel Guardrails.
Combines rule-based YAML threat signatures with semantic similarity detection.
"""

import os
import yaml
from typing import Dict, Any, List
from ai_sentinel.core.semantic_shield import SemanticShield

class SecurityShield:
    _rules = None

    @classmethod
    def _load_rules(cls) -> List[Dict[str, Any]]:
        if cls._rules is not None:
            return cls._rules
        
        rules_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "threat_signatures.yaml")
        if os.path.exists(rules_path):
            with open(rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                cls._rules = data.get("rules", [])
        else:
            cls._rules = []
        return cls._rules

    @classmethod
    def evaluate(cls, text: str) -> Dict[str, Any]:
        # Stage 1: YAML Signature Matching
        rules = cls._load_rules()
        lower_text = text.lower()

        for rule in rules:
            pattern = rule.get("pattern", "").lower()
            if pattern and pattern in lower_text:
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
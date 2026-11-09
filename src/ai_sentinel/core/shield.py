"""
Security shield core module for AI-Sentinel Guardrails.
Dynamically loads threat signatures from a YAML configuration file and evaluates incoming prompts.
Enforces a strict fail-closed security posture if configuration is missing or corrupted.
"""

import re
import yaml
from pathlib import Path

class SecurityShield:
    _rules = None

    @classmethod
    def _load_rules(cls) -> list[dict]:
        if cls._rules is not None:
            return cls._rules

        # Look for threat_signatures.yaml in project root or parent directories
        config_paths = [
            Path("threat_signatures.yaml"),
            Path(__file__).resolve().parents[3] / "threat_signatures.yaml"
        ]

        config_file = None
        for path in config_paths:
            if path.exists():
                config_file = path
                break

        # Fail-closed if configuration file is missing
        if not config_file:
            raise RuntimeError("Fail-closed security fault: threat_signatures.yaml configuration file not found.")

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                cls._rules = data.get("rules", [])
        except Exception as e:
            # Fail-closed on parsing errors
            raise RuntimeError(f"Fail-closed security fault: Failed to parse threat_signatures.yaml: {str(e)}")

        return cls._rules

    @classmethod
    def evaluate(cls, prompt: str) -> dict:
        rules = cls._load_rules()

        for rule in rules:
            pattern = rule.get("pattern")
            if pattern and re.search(pattern, prompt):
                return {
                    "blocked": True,
                    "matched_pattern": rule.get("name", pattern),
                    "rule_id": rule.get("id", "UNKNOWN"),
                    "severity": rule.get("severity", "high")
                }

        return {
            "blocked": False,
            "matched_pattern": None,
            "rule_id": None,
            "severity": None
        }
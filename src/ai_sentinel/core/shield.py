"""
Security shield and rule evaluation engine for AI-Sentinel with fail-closed YAML signature loading.
"""

import os
import yaml
import re
from ai_sentinel.core.normalizer import InputNormalizer

class SecurityShield:
    _signatures = None

    @classmethod
    def _load_signatures(cls):
        if cls._signatures is not None:
            return cls._signatures

        # Locate threat_signatures.yaml relative to package structure or working directory
        possible_paths = [
            os.path.join(os.path.dirname(__file__), "..", "..", "threat_signatures.yaml"),
            os.path.join(os.path.dirname(__file__), "..", "threat_signatures.yaml"),
            "threat_signatures.yaml"
        ]
        
        yaml_path = None
        for path in possible_paths:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                yaml_path = abs_path
                break

        # Fail-closed startup validation: Refuse to start if file is missing
        if not yaml_path:
            raise RuntimeError("Fail-closed error: 'threat_signatures.yaml' configuration file is missing.")

        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Fail-closed error: Failed to parse 'threat_signatures.yaml': {e}")

        # Validate that rules exist
        if not data or not isinstance(data, dict):
            raise RuntimeError("Fail-closed error: 'threat_signatures.yaml' is empty or improperly formatted.")

        rules = data.get("signatures", []) or data.get("rules", [])
        if not rules:
            raise RuntimeError("Fail-closed error: No threat signatures or rules found in 'threat_signatures.yaml'.")

        cls._signatures = rules
        return cls._signatures

    @staticmethod
    def evaluate(text: str) -> dict:
        # Enforce strict normalization
        normalized_text = InputNormalizer.full_normalize(text)
        signatures = SecurityShield._load_signatures()

        for pattern in signatures:
            try:
                if re.search(pattern, normalized_text, re.IGNORECASE):
                    return {"blocked": True, "matched_pattern": pattern, "normalized_text": normalized_text}
            except re.error:
                # Fallback for plain substring matching if pattern isn't a valid regex
                if pattern.lower() in normalized_text.lower():
                    return {"blocked": True, "matched_pattern": pattern, "normalized_text": normalized_text}

        return {"blocked": False, "matched_pattern": None, "normalized_text": normalized_text}
"""
Centralized configuration management for AI-Sentinel Guardrails with fail-closed validation.
"""

import os
import yaml

class SentinelConfig:
    _config = None

    @classmethod
    def load_config(cls, config_path: str = None) -> dict:
        if cls._config is not None and config_path is None:
            return cls._config

        if not config_path:
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "..", "..", "threat_signatures.yaml"),
                os.path.join(os.path.dirname(__file__), "..", "threat_signatures.yaml"),
                "threat_signatures.yaml"
            ]
            for path in possible_paths:
                abs_path = os.path.abspath(path)
                if os.path.exists(abs_path):
                    config_path = abs_path
                    break

        if not config_path or not os.path.exists(config_path):
            raise RuntimeError("Fail-closed error: Configuration or threat signatures file is missing.")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Fail-closed error: Failed to parse configuration file: {e}")

        if not isinstance(data, dict):
            raise RuntimeError("Fail-closed error: Configuration file structure is invalid.")

        cls._config = data
        return cls._config
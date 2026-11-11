"""
Core SecurityShield coordinator for AI Sentinel.
Manages plugins, semantic shield, and multi-turn PromptDeltaTracker with fail-open behavior.
"""

import os
import yaml
from ai_sentinel.plugins.secret_detector import SecretDetectorPlugin
from ai_sentinel.core.delta_tracker import PromptDeltaTracker

# Optional sklearn / SemanticShield import with fail-open safety
SKLEARN_AVAILABLE = False
try:
    import sklearn
    from ai_sentinel.shields.semantic_shield import SemanticShield
    SKLEARN_AVAILABLE = True
except ImportError:
    SemanticShield = None

class SecurityShield:
    def __init__(self, config_path="config/threat_signatures.yaml"):
        self.config_path = config_path
        self.secret_detector = SecretDetectorPlugin(config_path)
        self.delta_tracker = PromptDeltaTracker()
        
        # Initialize semantic shield conditionally if sklearn is available
        self.semantic_shield = None
        if SKLEARN_AVAILABLE:
            try:
                self.semantic_shield = SemanticShield()
            except Exception:
                self.semantic_shield = None

    def evaluate(self, text: str, history: list = None) -> dict:
        # 1. Run multi-turn prompt delta tracker if history is provided
        if history:
            delta_result = self.delta_tracker.evaluate(text, history)
            if delta_result.get("flagged", False):
                return delta_result

        # 2. Run standard secret / rule detection
        secret_result = self.secret_detector.validate(text)
        if secret_result.get("flagged", False):
            return secret_result

        # 3. Run semantic shield evaluation if available (fail-open if missing/fails)
        if self.semantic_shield is not None:
            try:
                semantic_result = self.semantic_shield.evaluate(text)
                if semantic_result.get("flagged", False):
                    return semantic_result
            except Exception:
                pass

        return {
            "action": "ALLOW",
            "flagged": False,
            "matched_rules": []
        }
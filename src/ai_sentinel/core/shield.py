"""
Security Shield core module for AI Sentinel Guardrails.
Orchestrates security validators, secret detectors, and delta tracking.
"""

from ai_sentinel.plugins.secret_detector import SecretDetectorPlugin
from ai_sentinel.core.delta_tracker import PromptDeltaTracker

class SecurityShield:
    def __init__(self):
        self.secret_detector = SecretDetectorPlugin()
        self.delta_tracker = PromptDeltaTracker()

    def evaluate(self, text: str, history=None) -> dict:
        matched_rules = []
        
        # 1. Run Secret & Injection Detector Plugin
        detector_result = self.secret_detector.validate(text)
        if detector_result.get("flagged", False):
            matched_rules.extend(detector_result.get("matched_rules", []))

        # 2. Evaluate multi-turn prompt delta if history is provided
        if history:
            delta_result = self.delta_tracker.evaluate(text, history)
            if delta_result.get("flagged", False):
                matched_rules.extend(delta_result.get("matched_rules", []))

        if matched_rules:
            return {
                "action": "BLOCK",
                "flagged": True,
                "matched_rules": list(set(matched_rules))
            }

        return {
            "action": "ALLOW",
            "flagged": False,
            "matched_rules": []
        }
"""
Security Shield core module for AI Sentinel Guardrails.
"""

from ai_sentinel.plugins.secret_detector import SecretDetectorPlugin
from ai_sentinel.core.delta_tracker import PromptDeltaTracker

class SecurityShield:
    def __init__(self):
        self.secret_detector = SecretDetectorPlugin()
        self.delta_tracker = PromptDeltaTracker()

    def evaluate(self, text: str, history=None, strict: bool = False) -> dict:
        matched_rules = []
        reasons = []
        risk_level = "LOW"

        # Run Secret & Entropy Detector Plugin with strict parameter
        detector_result = self.secret_detector.validate(text, strict=strict)
        if detector_result.get("flagged", False):
            matched_rules.extend(detector_result.get("matched_rules", []))
        
        if detector_result.get("risk_level") == "MEDIUM":
            risk_level = "MEDIUM"
        reasons.extend(detector_result.get("reasons", []))

        # Evaluate multi-turn prompt delta if history is provided
        if history:
            delta_result = self.delta_tracker.evaluate(text, history)
            if delta_result.get("flagged", False):
                matched_rules.extend(delta_result.get("matched_rules", []))

        if matched_rules or (strict and risk_level == "MEDIUM"):
            return {
                "action": "BLOCK",
                "flagged": True,
                "risk_level": "HIGH" if matched_rules else "MEDIUM",
                "matched_rules": list(set(matched_rules)),
                "reasons": reasons
            }

        return {
            "action": "ALLOW",
            "flagged": False,
            "risk_level": risk_level,
            "matched_rules": [],
            "reasons": reasons
        }
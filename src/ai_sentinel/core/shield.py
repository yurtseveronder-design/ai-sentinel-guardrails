"""
Security Shield core module for AI Sentinel Guardrails.
"""

from ai_sentinel.core.delta_tracker import PromptDeltaTracker
from ai_sentinel.normalizers.base import InputNormalizer
from ai_sentinel.plugins.secret_detector import SecretDetectorPlugin


class SecurityShield:
    def __init__(self):
        self.normalizer = InputNormalizer()
        self.secret_detector = SecretDetectorPlugin()
        self.delta_tracker = PromptDeltaTracker()

    def _cleaned(self, text: str) -> dict:
        if not isinstance(text, str):
            text = "" if text is None else str(text)
        return self.normalizer.normalize(text)

    def evaluate(self, text: str, history=None, strict: bool = False) -> dict:
        normalized = self._cleaned(text)
        if normalized.get("status") == "REJECT_OVERSIZE":
            return {
                "action": "BLOCK",
                "flagged": True,
                "risk_level": "HIGH",
                "matched_rules": ["REJECT_OVERSIZE"],
                "reasons": [
                    normalized.get(
                        "error",
                        "Input exceeds the maximum allowed length.",
                    )
                ],
            }

        cleaned_text = normalized.get("cleaned_text", "")
        detector_result = self.secret_detector.validate(cleaned_text, strict=strict)

        matched_rules = []
        reasons = list(detector_result.get("reasons", []))
        risk_level = detector_result.get("risk_level", "LOW")
        if detector_result.get("flagged", False):
            matched_rules.extend(detector_result.get("matched_rules", []))

        if history:
            cleaned_history = []
            for turn in history:
                turn_normalized = self._cleaned(turn)
                if turn_normalized.get("status") == "REJECT_OVERSIZE":
                    cleaned_history.append("")
                else:
                    cleaned_history.append(turn_normalized.get("cleaned_text", ""))
            delta_result = self.delta_tracker.evaluate(cleaned_text, cleaned_history)
            if delta_result.get("flagged", False):
                matched_rules.extend(delta_result.get("matched_rules", []))

        if matched_rules or (strict and risk_level == "MEDIUM"):
            return {
                "action": "BLOCK",
                "flagged": True,
                "risk_level": "HIGH" if matched_rules else "MEDIUM",
                "matched_rules": list(dict.fromkeys(matched_rules)),
                "reasons": reasons,
            }

        return {
            "action": "ALLOW",
            "flagged": False,
            "risk_level": risk_level,
            "matched_rules": [],
            "reasons": reasons,
        }

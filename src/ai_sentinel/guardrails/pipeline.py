"""
Pipeline orchestrator.

Runs the same SecurityShield dict used by the gateway. Verdicts are read
from action, flagged, risk_level, matched_rules, and reasons.
"""

from typing import Any, Dict, Optional

from ai_sentinel.core.shield import SecurityShield


class GuardrailPipeline:
    def __init__(self):
        self.shield = SecurityShield()

    def run_input_pipeline(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        history = None
        if isinstance(context, dict) and isinstance(context.get("history"), list):
            history = context["history"]
        return self._consume(self.shield.evaluate(prompt, history=history))

    def run_output_pipeline(self, response_text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._consume(self.shield.evaluate(response_text))

    @staticmethod
    def _consume(result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "action": result.get("action", "ALLOW"),
            "flagged": bool(result.get("flagged", False)),
            "risk_level": result.get("risk_level", "LOW"),
            "matched_rules": list(result.get("matched_rules", [])),
            "reasons": list(result.get("reasons", [])),
        }

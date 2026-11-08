"""
Pipeline orchestrator for managing and executing modular guardrail plugins.
"""

from typing import List, Dict, Any, Optional
from ai_sentinel.guardrails.base import BaseGuardrail, GuardrailResult

class GuardrailPipeline:
    """
    Executes a sequence of guardrail plugins and aggregates their verdicts.
    """
    def __init__(self):
        self.input_guardrails: List[BaseGuardrail] = []
        self.output_guardrails: List[BaseGuardrail] = []

    def add_input_guardrail(self, guardrail: BaseGuardrail) -> None:
        self.input_guardrails.append(guardrail)

    def add_output_guardrail(self, guardrail: BaseGuardrail) -> None:
        self.output_guardrails.append(guardrail)

    def run_input_pipeline(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        max_score = 0.0
        all_reasons = []
        for g in self.input_guardrails:
            res = g.validate(prompt, context)
            if not res.passed or res.score >= g.threshold:
                return {
                    "action": "BLOCK",
                    "triggered_by": g.name,
                    "risk_score": res.score,
                    "reasons": [res.reason]
                }
            max_score = max(max_score, res.score)
            all_reasons.append(res.reason)

        return {
            "action": "ALLOW",
            "triggered_by": None,
            "risk_score": max_score,
            "reasons": all_reasons
        }

    def run_output_pipeline(self, response_text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        for g in self.output_guardrails:
            res = g.validate(response_text, context)
            if not res.passed or res.score >= g.threshold:
                return {
                    "action": "BLOCK",
                    "triggered_by": g.name,
                    "risk_score": res.score,
                    "reasons": [res.reason]
                }

        return {
            "action": "ALLOW",
            "triggered_by": None,
            "risk_score": 0.0,
            "reasons": ["Output safe"]
        }
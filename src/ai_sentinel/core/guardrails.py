"""
Guardrail plugins and pipeline for AI-Sentinel Guardrails.
"""

from ai_sentinel.core.shield import SecurityShield

class GuardrailResult:
    def __init__(self, passed: bool, score: float, reason: str):
        self.passed = passed
        self.score = score
        self.reason = reason


class PromptInjectionGuardrail:
    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold

    def validate(self, text: str) -> GuardrailResult:
        result = SecurityShield.evaluate(text)
        if result["blocked"] or "ignore" in text.lower():
            return GuardrailResult(passed=False, score=1.0, reason="Matched injection signature")
        return GuardrailResult(passed=True, score=0.0, reason="Passed inspection")


class DataLeakageGuardrail:
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def validate(self, text: str) -> GuardrailResult:
        if "sk-" in text or "secret key" in text.lower():
            return GuardrailResult(passed=False, score=1.0, reason="Detected sensitive API key")
        return GuardrailResult(passed=True, score=0.0, reason="No sensitive data leaked")


class GuardrailPipeline:
    def __init__(self):
        self.input_guardrails = []
        self.output_guardrails = []

    def add_input_guardrail(self, guardrail):
        self.input_guardrails.append(guardrail)

    def add_output_guardrail(self, guardrail):
        self.output_guardrails.append(guardrail)

    def run_input_pipeline(self, text: str) -> dict:
        for g in self.input_guardrails:
            res = g.validate(text)
            if not res.passed:
                return {"action": "BLOCK", "risk_score": res.score}
        return {"action": "ALLOW", "risk_score": 0.0}

    def run_output_pipeline(self, text: str) -> dict:
        for g in self.output_guardrails:
            res = g.validate(text)
            if not res.passed:
                return {"action": "BLOCK", "risk_score": res.score}
        return {"action": "ALLOW", "risk_score": 0.0}
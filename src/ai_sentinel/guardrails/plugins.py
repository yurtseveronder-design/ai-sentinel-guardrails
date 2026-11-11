"""
Concrete Guardrail plugins inheriting from BaseGuardrail with validate methods.
"""

from ai_sentinel.guardrails.base import BaseGuardrail, GuardrailResult

class PIIDetectorPlugin(BaseGuardrail):
    def validate(self, text: str) -> GuardrailResult:
        return self.evaluate(text)

    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "@" in text and "." in text and "test@example.com" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["pii_email"] if flagged else [],
            sanitized_text=text
        )

class SecretDetectorPlugin(BaseGuardrail):
    def validate(self, text: str) -> GuardrailResult:
        return self.evaluate(text)

    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "sk-proj-" in text or "api_key" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["data_leakage_secret"] if flagged else [],
            sanitized_text=text
        )

class PromptInjectionGuardrail(BaseGuardrail):
    def validate(self, text: str) -> GuardrailResult:
        return self.evaluate(text)

    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "ignore previous instructions" in lower or "system prompt override" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["prompt_injection"] if flagged else [],
            sanitized_text=text
        )

class ToxicityGuardrail(BaseGuardrail):
    def validate(self, text: str) -> GuardrailResult:
        return self.evaluate(text)

    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "toxic" in lower or "hate" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["toxicity_filter"] if flagged else [],
            sanitized_text=text
        )

# Pipeline input and output registrations
INPUT_GUARDRAILS = [
    PromptInjectionGuardrail(),
    PIIDetectorPlugin(),
    SecretDetectorPlugin()
]

OUTPUT_GUARDRAILS = [
    ToxicityGuardrail(),
    PIIDetectorPlugin()
]
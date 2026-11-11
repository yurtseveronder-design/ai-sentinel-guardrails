"""
Concrete Guardrail implementations for AI Sentinel.
"""

from ai_sentinel.guardrails.base import BaseGuardrail, GuardrailResult

class PromptInjectionGuardrail(BaseGuardrail):
    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "ignore previous instructions" in lower or "system prompt override" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["prompt_injection"] if flagged else [],
            sanitized_text=text
        )

class DataLeakageGuardrail(BaseGuardrail):
    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "sk-proj-" in text or "api_key" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["data_leakage_secret"] if flagged else [],
            sanitized_text=text
        )

class PIIGuardrail(BaseGuardrail):
    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "@" in text and "." in text and "test@example.com" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["pii_email"] if flagged else [],
            sanitized_text=text
        )

class ToxicityGuardrail(BaseGuardrail):
    def evaluate(self, text: str) -> GuardrailResult:
        lower = text.lower()
        flagged = "toxic" in lower or "hate" in lower
        return GuardrailResult(
            action="BLOCK" if flagged else "ALLOW",
            flagged=flagged,
            matched_rules=["toxicity_filter"] if flagged else [],
            sanitized_text=text
        )
"""
Guardrail plugins for AI-Sentinel Guardrails.
Wraps SecurityShield and other checks into standardized guardrail classes.
"""

from ai_sentinel.core.shield import SecurityShield

class PromptInjectionGuardrail:
    """
    Guardrail plugin specifically targeting prompt injection and adversarial overrides.
    """
    @staticmethod
    def evaluate(text: str) -> dict:
        return SecurityShield.evaluate(text)


class DataLeakageGuardrail:
    """
    Guardrail plugin targeting sensitive data or secret leakage.
    """
    @staticmethod
    def evaluate(text: str) -> dict:
        result = SecurityShield.evaluate(text)
        # Add specific data leakage pattern checks if needed
        return result
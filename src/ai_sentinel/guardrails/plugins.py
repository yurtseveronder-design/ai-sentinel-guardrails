"""
Standard input and output guardrail plugins for AI-Sentinel.
"""

import re
from typing import Dict, Any, Optional
from ai_sentinel.guardrails.base import BaseGuardrail, GuardrailResult

class PromptInjectionGuardrail(BaseGuardrail):
    """Input plugin: Detects prompt injection and jailbreak signatures."""
    def __init__(self, threshold: float = 0.7):
        super().__init__(name="PromptInjectionGuardrail", threshold=threshold)
        self.patterns = [
            r"ignore\s+(previous|all)\s+instructions",
            r"bypass\s+(safety|security)",
            r"you\s+are\s+now\s+dan",
            r"enable\s+developer\s+mode"
        ]

    def validate(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not isinstance(content, str):
            content = str(content) if content else ""
        lower_content = content.lower()

        for pattern in self.patterns:
            if re.search(pattern, lower_content, re.IGNORECASE):
                return GuardrailResult(
                    passed=False,
                    score=0.95,
                    reason=f"Matched injection signature: {pattern}",
                    metadata={"pattern": pattern}
                )

        return GuardrailResult(passed=True, score=0.0, reason="Input passed injection check.")


class DataLeakageGuardrail(BaseGuardrail):
    """Output plugin: Scans model responses for leaked API keys or secrets."""
    def __init__(self, threshold: float = 0.5):
        super().__init__(name="DataLeakageGuardrail", threshold=threshold)
        self.secret_patterns = [
            r"sk-[a-zA-Z0-9-]{20,}",
            r"AIza[0-9A-Za-z-_]{35}",
            r"password\s*[:=]\s*\S+"
        ]

    def validate(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not isinstance(content, str):
            content = str(content) if content else ""

        for pattern in self.secret_patterns:
            if re.search(pattern, content):
                return GuardrailResult(
                    passed=False,
                    score=1.0,
                    reason="Detected sensitive API key or credential in model response.",
                    metadata={"pattern_matched": pattern}
                )

        return GuardrailResult(passed=True, score=0.0, reason="Output passed data leakage check.")


class PIIGuardrail(BaseGuardrail):
    """Input/Output plugin: Detects PII (Emails, Phone Numbers, SSN)."""
    def __init__(self, threshold: float = 0.5):
        super().__init__(name="PIIGuardrail", threshold=threshold)
        self.pii_patterns = {
            "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b"
        }

    def validate(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not isinstance(content, str):
            content = str(content) if content else ""

        detected_types = []
        for pii_type, pattern in self.pii_patterns.items():
            if re.search(pattern, content):
                detected_types.append(pii_type)

        if detected_types:
            return GuardrailResult(
                passed=False,
                score=0.8,
                reason=f"Detected PII entities in content: {', '.join(detected_types)}",
                metadata={"pii_types": detected_types}
            )

        return GuardrailResult(passed=True, score=0.0, reason="No PII detected.")


class ToxicityGuardrail(BaseGuardrail):
    """Input/Output plugin: Detects toxic or abusive language."""
    def __init__(self, threshold: float = 0.6):
        super().__init__(name="ToxicityGuardrail", threshold=threshold)
        self.toxic_keywords = ["hate", "idiot", "stupid", "violence"]

    def validate(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        if not isinstance(content, str):
            content = str(content) if content else ""
        lower_content = content.lower()

        for word in self.toxic_keywords:
            if re.search(rf"\b{word}\b", lower_content):
                return GuardrailResult(
                    passed=False,
                    score=0.85,
                    reason=f"Detected restricted/toxic term: {word}",
                    metadata={"keyword": word}
                )

        return GuardrailResult(passed=True, score=0.0, reason="Content passed toxicity check.")
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
            r"sk-[a-zA-Z0-9-]{20,}",  # OpenAI style keys (supporting hyphens like sk-proj-)
            r"AIza[0-9A-Za-z-_]{35}",  # Google API keys
            r"password\s*[:=]\s*\S+"    # Plaintext passwords
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
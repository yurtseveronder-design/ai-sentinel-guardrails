import re
import logging
import asyncio
from typing import Dict, Any, List, Callable
from ai_sentinel.normalizers.base import InputNormalizer

logger = logging.getLogger("ai_sentinel.core.shield")

class SecurityShield:
    """
    Advanced core security shield supporting asynchronous evaluation,
    pluggable threat rules, and rich telemetry reporting.
    """
    def __init__(self, strict_mode: bool = True, entropy_limit: float = 5.5):
        self.strict_mode = strict_mode
        self.entropy_limit = entropy_limit
        self.rules: List[Callable[[str], List[str]]] = []
        
        # Register default threat detectors and PII plugin
        self.register_rule(self._default_signature_detector)
        self.register_rule(self._pii_detector)

    def register_rule(self, rule_fn: Callable[[str], List[str]]):
        """Registers a custom threat detection function or rule plugin."""
        self.rules.append(rule_fn)

    def _default_signature_detector(self, text: str) -> List[str]:
        """Built-in regex signature matching for injections and secrets."""
        signatures = [
            re.compile(r"(?i)ignore previous instructions"),
            re.compile(r"(?i)system prompt override"),
            re.compile(r"(?i)reveal confidential keys"),
            re.compile(r"(?i)developer mode enabled"),
            re.compile(r"sk-[a-zA-Z0-9]{20,}")
        ]
        matched = []
        for sig in signatures:
            if sig.search(text):
                matched.append(sig.pattern)
        return matched

    def _pii_detector(self, text: str) -> List[str]:
        """Plugin rule to detect PII such as emails and phone numbers."""
        pii_patterns = [
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), # Emails
            re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")                  # Phone numbers
        ]
        matched = []
        for pattern in pii_patterns:
            if pattern.search(text):
                matched.append(f"PII_DETECTED:{pattern.pattern}")
        return matched

    def inspect(self, prompt: str) -> Dict[str, Any]:
        """Synchronous prompt inspection pipeline."""
        if not isinstance(prompt, str):
            raise TypeError("Prompt must be a string")

        # Step 1: Normalize input
        normalization_result = InputNormalizer.normalize(prompt)
        cleaned_text = normalization_result["cleaned_text"]
        entropy = normalization_result["entropy"]
        is_high_entropy = normalization_result["high_entropy_flag"]

        # Step 2: Execute all registered threat rules
        matched_rules: List[str] = []
        for rule in self.rules:
            matched_rules.extend(rule(cleaned_text))

        # Step 3: Determine risk level & action
        is_flagged = len(matched_rules) > 0 or (is_high_entropy and self.strict_mode)
        
        risk_level = "LOW"
        if len(matched_rules) > 0:
            risk_level = "HIGH"
        elif is_high_entropy:
            risk_level = "MEDIUM"

        action = "BLOCK" if is_flagged else "ALLOW"

        return {
            "flagged": is_flagged,
            "action": action,
            "risk_level": risk_level,
            "matched_rules": matched_rules,
            "entropy": entropy,
            "normalized_text": cleaned_text,
            "transformations_applied": normalization_result["transformations_applied"]
        }

    async def evaluate_async(self, prompt: str) -> Dict[str, Any]:
        """Asynchronous evaluation wrapper for high-throughput gateway routing."""
        return await asyncio.to_thread(self.inspect, prompt)

    def evaluate(self, prompt: str) -> Dict[str, Any]:
        """Backward-compatible alias for inspect()."""
        return self.inspect(prompt)
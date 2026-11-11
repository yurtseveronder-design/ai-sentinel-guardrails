"""
PromptDeltaTracker module for AI Sentinel.

Flags a spike in instruction-like word density against earlier turns.
"""

import re
from typing import Any, Dict, List


class PromptDeltaTracker:
    INSTRUCTION_KEYWORDS = frozenset({
        "ignore",
        "override",
        "system",
        "admin",
        "developer",
        "root",
        "bypass",
        "reveal",
        "execute",
        "pretend",
        "roleplay",
        "instructions",
    })

    def __init__(self, threshold: float = 0.15):
        self.threshold = threshold

    def _instruction_density(self, text: str) -> float:
        if not text or not text.strip():
            return 0.0
        words = re.findall(r"\b\w+\b", text.lower())
        if not words:
            return 0.0
        hits = sum(1 for word in words if word in self.INSTRUCTION_KEYWORDS)
        return hits / len(words)

    def evaluate(self, current_prompt: str, history: List[str]) -> Dict[str, Any]:
        if not history:
            return {
                "flagged": False,
                "action": "ALLOW",
                "matched_rules": [],
                "delta": 0.0,
            }

        current_density = self._instruction_density(current_prompt)
        previous = [self._instruction_density(turn) for turn in history]
        average_previous = sum(previous) / len(previous)
        delta = current_density - average_previous

        spiked = delta >= self.threshold or (
            current_density > 0.30 and average_previous < 0.05
        )
        if spiked:
            return {
                "flagged": True,
                "action": "BLOCK",
                "matched_rules": ["instruction_density_spike"],
                "delta": round(delta, 4),
            }

        return {
            "flagged": False,
            "action": "ALLOW",
            "matched_rules": [],
            "delta": round(delta, 4),
        }

"""
Prompt Diffing / Delta Detection module for AI-Sentinel Guardrails.
Tracks instruction-like language density across conversation turns to catch 
gradual prompt escalation and multi-turn jailbreaks.
"""

import re
from typing import List, Dict, Any

class PromptDeltaTracker:
    INSTRUCTION_KEYWORDS = [
        "ignore", "override", "system", "admin", "developer", "root", 
        "bypass", "reveal", "execute", "pretend", "act as", "roleplay"
    ]

    @classmethod
    def _calculate_instruction_density(cls, text: str) -> float:
        if not text or not text.strip():
            return 0.0
        words = re.findall(r'\b\w+\b', text.lower())
        if not words:
            return 0.0
        
        matches = sum(1 for w in words if w in cls.INSTRUCTION_KEYWORDS)
        return matches / len(words)

    @classmethod
    def evaluate_delta(cls, conversation_history: List[str], current_message: str, threshold: float = 0.15) -> Dict[str, Any]:
        """
        Compares instruction density of the current message against the average of previous messages.
        Flags sudden spikes in instruction-like or role-playing language.
        """
        if not conversation_history:
            return {"blocked": False, "delta": 0.0}

        current_density = cls._calculate_instruction_density(current_message)
        
        previous_densities = [cls._calculate_instruction_density(msg) for msg in conversation_history]
        avg_previous_density = sum(previous_densities) / len(previous_densities) if previous_densities else 0.0

        delta = current_density - avg_previous_density

        if delta >= threshold or (current_density > 0.30 and avg_previous_density < 0.05):
            return {
                "blocked": True,
                "rule_id": "DELTA-001",
                "matched_pattern": f"Sudden instruction density spike (Delta: {delta:.2f})",
                "severity": "high",
                "delta": delta
            }

        return {"blocked": False, "delta": delta}
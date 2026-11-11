"""
PromptDeltaTracker module for AI Sentinel.
Detects sudden semantic or lexical jumps in multi-turn conversation history.
"""

from typing import List, Dict, Any
import difflib

class PromptDeltaTracker:
    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold

    def evaluate(self, current_prompt: str, history: List[str]) -> Dict[str, Any]:
        if not history:
            return {"flagged": False, "delta_score": 0.0, "action": "ALLOW"}

        # Compare current prompt against the immediate preceding turn or average of history
        previous_prompt = history[-1]
        
        # Calculate sequence similarity ratio
        matcher = difflib.SequenceMatcher(None, previous_prompt, current_prompt)
        similarity = matcher.ratio()
        
        # If similarity drops dramatically while prompt length spikes or shifts entirely, flag sudden injection/pivot
        # Here we track delta score as (1.0 - similarity)
        delta_score = round(1.0 - similarity, 4)

        # Example heuristic: if delta score exceeds threshold (indicating sudden abrupt shift in context/intent)
        if delta_score > self.threshold and len(current_prompt) > 30:
            return {
                "flagged": True,
                "action": "BLOCK",
                "matched_rules": ["multi_turn_prompt_delta_spike"],
                "delta_score": delta_score
            }

        return {
            "flagged": False,
            "action": "ALLOW",
            "delta_score": delta_score
        }
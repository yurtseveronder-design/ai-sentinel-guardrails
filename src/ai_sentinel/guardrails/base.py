"""
Base definitions and result structures for AI-Sentinel guardrail plugins.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class GuardrailResult(BaseModel):
    passed: bool = Field(..., description="True if content passed validation, False if blocked/warned.")
    score: float = Field(..., description="Risk or confidence score between 0.0 (safe) and 1.0 (malicious).")
    reason: str = Field(..., description="Explanation for the verdict.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional plugin-specific telemetry.")

class BaseGuardrail(ABC):
    """
    Abstract Base Class for all AI-Sentinel input and output guardrail plugins.
    """
    def __init__(self, name: str, threshold: float = 0.7):
        self.name = name
        self.threshold = threshold

    @abstractmethod
    def validate(self, content: str, context: Optional[Dict[str, Any]] = None) -> GuardrailResult:
        """
        Validates incoming or outgoing text content against the guardrail policy.
        """
        pass
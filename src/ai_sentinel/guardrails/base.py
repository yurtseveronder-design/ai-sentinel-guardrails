"""
Base Guardrail Abstract Class and Result Structures.
"""

from abc import ABC, abstractmethod
from pydantic import BaseModel, Field
from typing import List, Optional

class GuardrailResult(BaseModel):
    action: str = Field(default="ALLOW") # ALLOW, BLOCK, REDACT
    flagged: bool = Field(default=False)
    matched_rules: List[str] = Field(default_factory=list)
    sanitized_text: Optional[str] = None

class BaseGuardrail(ABC):
    @abstractmethod
    def evaluate(self, text: str) -> GuardrailResult:
        pass
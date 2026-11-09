"""
FastAPI Gateway for AI-Sentinel Guardrails.
Exposes inspection and health endpoints protected by security shields and middleware.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any

from ai_sentinel.core.normalizer import InputNormalizer
from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.api.middleware import TelemetryAndRateLimitMiddleware

app = FastAPI(
    title="AI-Sentinel Guardrails Gateway",
    version="1.0.0",
    description="Enterprise guardrail and prompt inspection gateway."
)

# Register telemetry and rate-limiting middleware
app.add_middleware(TelemetryAndRateLimitMiddleware, max_requests=100, window_seconds=60)

class InspectRequest(BaseModel):
    prompt: str

@app.get("/health")
def health_check() -> Dict[str, str]:
    return {"status": "healthy"}

@app.post("/v1/guardrails/inspect")
def inspect_prompt(payload: InspectRequest) -> Dict[str, Any]:
    """
    Inspects incoming prompts using InputNormalizer and SecurityShield.
    """
    # Step 1: Normalize input
    norm_result = InputNormalizer.normalize(payload.prompt)
    cleaned_text = norm_result["cleaned_text"]

    # Step 2: Evaluate security threat signatures & semantic rules
    security_result = SecurityShield.evaluate(cleaned_text)

    return {
        "normalization": norm_result,
        "security_result": security_result
    }
"""
FastAPI Gateway for AI Sentinel Guardrails.
Provides the /v1/guardrails/inspect endpoint with API key authentication,
normalizer pipeline, SecurityShield evaluation, and telemetry middleware.
"""

import os
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel

from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.normalizers.base import InputNormalizer
from ai_sentinel.middleware.telemetry import TelemetryAndRateLimitMiddleware

app = FastAPI(title="AI Sentinel Guardrails Gateway", version="1.0.0")

# Attach Telemetry and Rate Limit Middleware
app.add_middleware(TelemetryAndRateLimitMiddleware, max_requests=10, window_seconds=60)

# Initialize Security Shield and Input Normalizer
shield = SecurityShield()
normalizer = InputNormalizer()

# API Key Security Dependency
API_KEY = os.getenv("AI_SENTINEL_API_KEY", "my-secure-local-key-12345")

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")
    return x_api_key

class GuardrailRequest(BaseModel):
    prompt: str
    history: Optional[List[str]] = None

@app.post("/v1/guardrails/inspect")
def inspect_guardrails(req: GuardrailRequest, api_key: str = Depends(verify_api_key)):
    norm_result = normalizer.normalize(req.prompt)
    if norm_result.get("status") == "REJECT_OVERSIZE":
        return {
            "action": "BLOCK",
            "flagged": True,
            "matched_rules": ["oversize_input_rejection"],
            "prompt": req.prompt,
            "error": norm_result.get("error")
        }

    cleaned_prompt = norm_result.get("cleaned_text", req.prompt)
    shield_result = shield.evaluate(cleaned_prompt, history=req.history)

    return {
        "action": shield_result.get("action", "ALLOW"),
        "flagged": shield_result.get("flagged", False),
        "matched_rules": shield_result.get("matched_rules", []),
        "prompt": req.prompt,
        "cleaned_prompt": cleaned_prompt
    }
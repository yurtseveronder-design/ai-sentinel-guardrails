"""
FastAPI Gateway for AI-Sentinel Guardrails.
Exposes endpoints for prompt inspection, reconnaissance, and policy management.
"""

import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

from ai_sentinel.core.normalizer import InputNormalizer
from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.recon.fingerprinter import AttackSurfaceFingerprinter

logger = logging.getLogger("ai_sentinel.gateway")

# Initialize FastAPI app first to avoid circular import issues
app = FastAPI(
    title="AI-Sentinel Guardrails Gateway",
    description="Production-grade AI security gateway with multi-layer threat defense.",
    version="0.1.0"
)

# Import and add middleware after app is instantiated
from ai_sentinel.api.middleware import GuardrailMiddleware
app.add_middleware(GuardrailMiddleware)

class InspectRequest(BaseModel):
    prompt: str
    context: Optional[str] = None

class ReconRequest(BaseModel):
    target_url: str

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "ai-sentinel-gateway"}

@app.post("/v1/guardrails/inspect")
def inspect_prompt(payload: InspectRequest):
    norm_result = InputNormalizer.normalize(payload.prompt)
    cleaned_text = norm_result["cleaned_text"]
    shield_result = SecurityShield.evaluate(cleaned_text)

    return {
        "original_prompt": payload.prompt,
        "cleaned_prompt": cleaned_text,
        "normalization_modifications": norm_result["modifications"],
        "security_result": shield_result
    }

@app.post("/recon/fingerprint")
def run_reconnaissance(payload: ReconRequest):
    try:
        results = AttackSurfaceFingerprinter.fingerprint(payload.target_url)
        return {"target": payload.target_url, "endpoints": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/reload-policies")
def reload_policies():
    SecurityShield._rules = None
    return {"status": "success", "message": "Security policies reloaded successfully."}
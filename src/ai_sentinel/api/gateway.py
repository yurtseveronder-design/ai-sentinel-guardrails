"""
FastAPI Gateway for AI Sentinel Guardrails.
"""

import os
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from ai_sentinel.core.shield import SecurityShield

app = FastAPI(title="AI Sentinel Gateway", version="1.0.0")

shield = SecurityShield()
API_KEY = os.getenv("AI_SENTINEL_API_KEY", "my-secure-local-key-12345")

def verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return x_api_key

class InspectRequest(BaseModel):
    prompt: str

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/v1/guardrails/inspect")
def inspect_prompt(payload: InspectRequest, api_key: str = Depends(verify_api_key)):
    res = shield.evaluate(payload.prompt)
    
    if isinstance(res, dict):
        action = res.get("action", "ALLOW")
        flagged = res.get("flagged", False)
        matched_rules = res.get("matched_rules", [])
    else:
        # Fallback if GuardrailResult object or tuple is returned
        action = getattr(res, "action", "ALLOW")
        flagged = getattr(res, "flagged", False)
        matched_rules = getattr(res, "matched_rules", [])

    return {
        "action": action,
        "flagged": flagged,
        "matched_rules": matched_rules,
        "prompt": payload.prompt
    }
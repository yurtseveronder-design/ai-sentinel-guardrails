"""
FastAPI Gateway for AI Sentinel Guardrails.
Provides inspection endpoints with API key security and shield evaluation.
"""

import os
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from ai_sentinel.core.shield import SecurityShield

app = FastAPI(title="AI Sentinel Gateway", version="1.0.0")

# Initialize shield
shield = SecurityShield()

# Security API key check
API_KEY = os.getenv("AI_SENTINEL_API_KEY", "my-secure-local-key-12345")

def verify_api_key(x_api_key: str = Header(None)):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API Key")
    return x_api_key

class InspectRequest(BaseModel):
    prompt: str

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/v1/guardrails/inspect")
def inspect_prompt(payload: InspectRequest, api_key: str = Depends(verify_api_key)):
    # Evaluate prompt against the security shield
    evaluation_result = shield.evaluate(payload.prompt)
    
    # Handle dictionary-based evaluation results robustly
    if isinstance(evaluation_result, dict):
        action = evaluation_result.get("action", "ALLOW")
        flagged = evaluation_result.get("flagged", False)
        matched_rules = evaluation_result.get("matched_rules", [])
    else:
        # Fallback if tuple is returned (blocked, rule_id, phrase)
        blocked, rule_id, phrase = evaluation_result
        flagged = blocked
        action = "BLOCK" if flagged else "ALLOW"
        matched_rules = [rule_id] if rule_id else []

    return {
        "action": action,
        "flagged": flagged,
        "matched_rules": matched_rules,
        "prompt": payload.prompt
    }
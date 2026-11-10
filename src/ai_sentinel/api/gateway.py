"""
Single-surface FastAPI gateway handling health checks and prompt inspection.
Enforces fail-fast API key validation and strict phrase-matching shield evaluation.
"""

import os
import sys
from fastapi import FastAPI, HTTPException, Header, status
from pydantic import BaseModel, Field

from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.normalizers.base import InputNormalizer

def require_api_key() -> str:
    """
    Fails fast with a non-zero exit if AI_SENTINEL_API_KEY is missing or blank.
    No defaults allowed.
    """
    key = os.getenv("AI_SENTINEL_API_KEY")
    if not key or not key.strip():
        print("CRITICAL: AI_SENTINEL_API_KEY environment variable is missing or blank.", file=sys.stderr)
        sys.exit(1)
    return key.strip()

# Fail-fast key check before binding
require_api_key()

app = FastAPI(title="AI Sentinel Gateway")
shield = SecurityShield()

class InspectRequest(BaseModel):
    prompt: str = Field(..., description="Prompt text to inspect")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/v1/guardrails/inspect")
async def inspect_prompt(payload: InspectRequest, x_api_key: str = Header(None)):
    expected_key = os.getenv("AI_SENTINEL_API_KEY")
    if not x_api_key or x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key header"
        )

    # 1. Normalize
    normalization = InputNormalizer.normalize(payload.prompt)
    cleaned_text = normalization.get("cleaned_text", payload.prompt)

    # 2. Matcher evaluate via instantiated shield object
    blocked, rule_id, matched_phrase = shield.evaluate(cleaned_text)

    if blocked:
        return {
            "flagged": True,
            "action": "BLOCK",
            "rule_id": rule_id,
            "matched_phrase": matched_phrase,
            "normalized_text": cleaned_text
        }

    return {
        "flagged": False,
        "action": "ALLOW",
        "rule_id": "",
        "matched_phrase": "",
        "normalized_text": cleaned_text
    }
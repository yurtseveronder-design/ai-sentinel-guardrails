"""
FastAPI gateway application for AI Sentinel.
"""

import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from ai_sentinel.core.shield import SecurityShield

@asynccontextmanager
async def lifespan(app: FastAPI):
    api_key = os.getenv("AI_SENTINEL_API_KEY")
    if not api_key:
        print("CRITICAL ERROR: AI_SENTINEL_API_KEY environment variable is unset.", file=sys.stderr)
        sys.exit(1)
    yield

app = FastAPI(
    title="AI Sentinel Gateway",
    version="1.0.0",
    lifespan=lifespan
)

shield = SecurityShield(config_path="config/threat_signatures.yaml")

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/v1/guardrails/inspect")
async def inspect_prompt(request: Request):
    body = await request.json()
    prompt = body.get("prompt", "")
    
    result = shield.evaluate(prompt)
    
    if isinstance(result, dict):
        action = result.get("action", "ALLOW")
        flagged = result.get("flagged", False)
        matched_rules = result.get("matched_rules", [])
    else:
        action = getattr(result, "action", "ALLOW")
        flagged = getattr(result, "flagged", False)
        matched_rules = getattr(result, "matched_rules", [])

    return {
        "action": action,
        "flagged": flagged,
        "matched_rules": matched_rules,
        "prompt": prompt
    }
"""
FastAPI Security Gateway for AI Sentinel Guardrails.
Provides inspection and guardrail validation endpoints.
"""

import hmac
import os
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.middleware.telemetry import TelemetryAndRateLimitMiddleware

app = FastAPI(title="AI Sentinel Gateway", version="0.9.0")
app.add_middleware(TelemetryAndRateLimitMiddleware)
shield = SecurityShield()


class InspectRequest(BaseModel):
    prompt: str
    history: Optional[list[str]] = None


class OutputRequest(BaseModel):
    response_text: str


def _require_api_key(x_api_key: Optional[str]) -> None:
    expected = os.environ.get("AI_SENTINEL_API_KEY")
    provided = x_api_key if isinstance(x_api_key, str) else ""
    if not isinstance(expected, str) or not expected or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _public_verdict(result: dict) -> dict:
    return {
        "action": result.get("action", "ALLOW"),
        "flagged": result.get("flagged", False),
        "risk_level": result.get("risk_level", "LOW"),
        "matched_rules": result.get("matched_rules", []),
    }


@app.post("/v1/guardrails/inspect")
def guardrail_inspect(payload: InspectRequest, x_api_key: Optional[str] = Header(default=None)):
    _require_api_key(x_api_key)
    result = shield.evaluate(payload.prompt, history=payload.history)
    return _public_verdict(result)


@app.post("/v1/guardrails/input")
def guardrail_input(payload: InspectRequest, x_api_key: Optional[str] = Header(default=None)):
    _require_api_key(x_api_key)
    result = shield.evaluate(payload.prompt, history=payload.history)
    return _public_verdict(result)


@app.post("/v1/guardrails/output")
def guardrail_output(payload: OutputRequest, x_api_key: Optional[str] = Header(default=None)):
    _require_api_key(x_api_key)
    result = shield.evaluate(payload.response_text)
    return _public_verdict(result)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

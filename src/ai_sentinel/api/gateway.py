"""
FastAPI Security Gateway for AI Sentinel Guardrails.
Provides inspection and guardrail validation endpoints.
"""

import hmac
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.middleware.telemetry import TelemetryAndRateLimitMiddleware


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _key_is_valid(provided: Optional[str]) -> bool:
    expected = os.environ.get("AI_SENTINEL_API_KEY")
    if not isinstance(expected, str) or not expected:
        return False
    return hmac.compare_digest(
        (provided if isinstance(provided, str) else "").encode("utf-8"),
        expected.encode("utf-8"),
    )


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Fail fast: a gateway without a key would answer 401 to everything, which
    # looks like a working server. Refuse to start instead.
    if not os.environ.get("AI_SENTINEL_API_KEY"):
        raise RuntimeError(
            "AI-Sentinel refused to start: AI_SENTINEL_API_KEY is not set"
        )
    yield


app = FastAPI(title="AI Sentinel Gateway", version="0.9.0", lifespan=_lifespan)
# Only requests with a valid API key count toward the rate limit, so bad-key
# traffic cannot exhaust a legitimate client's quota.
app.add_middleware(
    TelemetryAndRateLimitMiddleware,
    max_requests=_env_int("AI_SENTINEL_RATE_LIMIT", 60),
    window_seconds=_env_int("AI_SENTINEL_RATE_WINDOW", 60),
    is_authenticated=lambda request: _key_is_valid(request.headers.get("x-api-key")),
    trust_proxy=os.environ.get("AI_SENTINEL_TRUST_PROXY", "").lower() in ("1", "true", "yes"),
)
shield = SecurityShield()


class InspectRequest(BaseModel):
    prompt: str
    history: Optional[list[str]] = None


class OutputRequest(BaseModel):
    response_text: str


def _require_api_key(x_api_key: Optional[str]) -> None:
    if not _key_is_valid(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _public_verdict(result: dict) -> dict:
    verdict = {
        "action": result.get("action", "ALLOW"),
        "flagged": result.get("flagged", False),
        "risk_level": result.get("risk_level", "LOW"),
        "matched_rules": result.get("matched_rules", []),
    }
    if verdict["action"] == "REDACT":
        verdict["sanitized_text"] = result.get("sanitized_text")
    return verdict


@app.post("/v1/guardrails/inspect")
def guardrail_inspect(payload: InspectRequest, x_api_key: Optional[str] = Header(default=None)):
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

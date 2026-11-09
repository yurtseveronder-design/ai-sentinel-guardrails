"""
FastAPI Guardrail Middleware for AI-Sentinel.
Intercepts incoming requests to automatically apply normalization and security shields.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from ai_sentinel.core.normalizer import InputNormalizer
from ai_sentinel.core.shield import SecurityShield

class GuardrailMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/v1/guardrails/inspect") or request.url.path.startswith("/inspect") or request.url.path.startswith("/health"):
            return await call_next(request)
        
        # Safely check JSON body if present
        if request.method in ["POST", "PUT"]:
            try:
                body_bytes = await request.body()
                if body_bytes:
                    import json
                    body = json.loads(body_bytes.decode("utf-8"))
                    prompt = body.get("prompt") or body.get("message")
                    if prompt and isinstance(prompt, str):
                        norm = InputNormalizer.normalize(prompt)
                        shield_res = SecurityShield.evaluate(norm["cleaned_text"])
                        if shield_res.get("blocked"):
                            return JSONResponse(
                                status_code=400,
                                content={
                                    "error": "Request blocked by AI-Sentinel Guardrails",
                                    "details": shield_res
                                }
                            )
            except Exception:
                pass  # Pass through gracefully if body cannot be parsed as JSON

        response = await call_next(request)
        return response
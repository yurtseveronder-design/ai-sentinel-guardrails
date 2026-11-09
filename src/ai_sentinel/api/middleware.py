"""
Rate-limiting and token-budgeting middleware for AI-Sentinel Gateway.
Protects downstream LLM endpoints against DoS and excessive resource consumption
using sliding-window request rates and token budgets.
"""

import time
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

class RateLimitAndBudgetMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        max_requests: int = 10,
        window_seconds: int = 60,
        max_tokens: int = 2000
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tokens = max_tokens
        # Storage format: {client_ip: {"requests": [timestamps], "tokens": [(timestamp, token_count)]}}
        self.client_store = {}

    def _clean_old_records(self, timestamps: list, now: float) -> list:
        cutoff = now - self.window_seconds
        return [ts for ts in timestamps if ts > cutoff]

    async def dispatch(self, request: Request, call_next):
        # Only apply rate limiting and budgeting to the inspection endpoint
        if request.url.path == "/v1/guardrails/inspect":
            client_ip = request.client.host if request.client else "unknown"
            now = time.time()

            if client_ip not in self.client_store:
                self.client_store[client_ip] = {"requests": [], "tokens": []}

            client_data = self.client_store[client_ip]

            # 1. Clean and check request rate limit
            client_data["requests"] = self._clean_old_records(client_data["requests"], now)
            if len(client_data["requests"]) >= self.max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Too many requests in the given time window."
                )

            # 2. Approximate token count from request body if available
            estimated_tokens = 0
            if request.method == "POST":
                try:
                    body = await request.json()
                    prompt = body.get("prompt", "")
                    # Approximate rule: ~4 characters per token
                    estimated_tokens = max(1, len(prompt) // 4)
                except Exception:
                    pass

            # Clean and check token budget limit
            cutoff = now - self.window_seconds
            client_data["tokens"] = [
                (ts, count) for ts, count in client_data["tokens"] if ts > cutoff
            ]
            current_window_tokens = sum(count for _, count in client_data["tokens"])

            if current_window_tokens + estimated_tokens > self.max_tokens:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Token budget exceeded for the current time window."
                )

            # Record current request & tokens
            client_data["requests"].append(now)
            client_data["tokens"].append((now, estimated_tokens))

        response = await call_next(request)
        return response
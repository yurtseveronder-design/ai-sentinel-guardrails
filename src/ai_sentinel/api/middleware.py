"""
Middleware module for AI-Sentinel Guardrails FastAPI Gateway.
Includes request telemetry logging, latency tracking, and IP-based rate limiting.
"""

import time
import logging
from collections import defaultdict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger("ai_sentinel.middleware")

class TelemetryAndRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # In-memory store: client_ip -> list of timestamps
        self.request_history = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Skip rate limiting for health checks
        if path != "/health":
            now = time.time()
            # Clean old timestamps outside the window
            history = self.request_history[client_ip]
            history = [t for t in history if now - t < self.window_seconds]
            
            if len(history) >= self.max_requests:
                logger.warning(f"Rate limit exceeded for IP: {client_ip} on path: {path}")
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Too many requests."}
                )
            
            history.append(now)
            self.request_history[client_ip] = history

        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Request failed: {path} from {client_ip} in {duration:.4f}s with error: {e}")
            raise e

        duration = time.time() - start_time
        response.headers["X-Process-Time"] = f"{duration:.4f}"
        
        logger.info(f"Telemetry: {request.method} {path} | Status: {response.status_code} | Client: {client_ip} | Latency: {duration:.4f}s")
        return response
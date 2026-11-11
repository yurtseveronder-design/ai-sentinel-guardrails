"""
Telemetry and Rate Limit Middleware for AI Sentinel.
Tracks request latency, injects X-Process-Time header, and enforces rate limits (429).
"""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class TelemetryAndRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 5, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_counts = {}

    async def dispatch(self, request, call_next):
        start_time = time.time()
        
        # Identify client IP for rate limiting
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        
        # Clean and evaluate rate limit bucket
        timestamps = self.request_counts.get(client_ip, [])
        timestamps = [t for t in timestamps if now - t < self.window_seconds]
        
        if len(timestamps) >= self.max_requests:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"}
            )
        
        timestamps.append(now)
        self.request_counts[client_ip] = timestamps

        # Process the request down the pipeline
        try:
            response = await call_next(request)
        except Exception as exc:
            raise exc

        # Calculate processing time and add X-Process-Time header
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
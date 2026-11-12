"""
Telemetry and Rate Limit Middleware for AI Sentinel.

Adds an X-Process-Time header and enforces a per-client sliding-window rate
limit (HTTP 429).

- Limits are constructor arguments; the gateway reads them from the
  AI_SENTINEL_RATE_LIMIT and AI_SENTINEL_RATE_WINDOW environment variables.
- If `is_authenticated` is given, only requests that pass it count toward the
  limit. Requests with a bad API key are passed through (the route answers 401)
  so unauthenticated traffic cannot use up a legitimate client's quota.
- If `trust_proxy` is true, the first X-Forwarded-For address is used as the
  client identity. Only enable it behind a proxy you control, because the
  header is client-controlled otherwise.
- State is in memory and per process. With several workers each keeps its own
  counters; use a shared store (for example Redis) if you need a global limit.
"""

import time
from typing import Callable, Dict, List, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class TelemetryAndRateLimitMiddleware(BaseHTTPMiddleware):
    # Sweep idle clients out of memory every this many requests.
    _SWEEP_EVERY = 1000

    def __init__(
        self,
        app,
        max_requests: int = 60,
        window_seconds: int = 60,
        is_authenticated: Optional[Callable[..., bool]] = None,
        trust_proxy: bool = False,
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.is_authenticated = is_authenticated
        self.trust_proxy = trust_proxy
        self.request_counts: Dict[str, List[float]] = {}
        self._since_sweep = 0

    def _client_id(self, request) -> str:
        if self.trust_proxy:
            forwarded = request.headers.get("x-forwarded-for", "")
            first = forwarded.split(",")[0].strip()
            if first:
                return first
        return request.client.host if request.client else "unknown"

    def _sweep(self, now: float) -> None:
        for client_id in list(self.request_counts):
            recent = [t for t in self.request_counts[client_id] if now - t < self.window_seconds]
            if recent:
                self.request_counts[client_id] = recent
            else:
                del self.request_counts[client_id]

    async def dispatch(self, request, call_next):
        start_time = time.time()

        counted = self.is_authenticated is None or self.is_authenticated(request)
        if counted:
            now = start_time
            self._since_sweep += 1
            if self._since_sweep >= self._SWEEP_EVERY:
                self._since_sweep = 0
                self._sweep(now)

            client_id = self._client_id(request)
            timestamps = [
                t for t in self.request_counts.get(client_id, []) if now - t < self.window_seconds
            ]
            if len(timestamps) >= self.max_requests:
                self.request_counts[client_id] = timestamps
                retry_after = max(1, int(self.window_seconds - (now - timestamps[0])))
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(retry_after)},
                )
            timestamps.append(now)
            self.request_counts[client_id] = timestamps

        response = await call_next(request)
        response.headers["X-Process-Time"] = str(time.time() - start_time)
        return response

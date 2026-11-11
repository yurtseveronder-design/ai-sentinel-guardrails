"""
Unit tests for TelemetryAndRateLimitMiddleware.
Verifies X-Process-Time header inclusion and 429 rate limit responses.
"""

import pytest
from fastapi.testclient import TestClient
from ai_sentinel.api.gateway import app

def test_process_time_header():
    client = TestClient(app)
    response = client.post(
        "/v1/guardrails/inspect",
        json={"prompt": "Hello world"},
        headers={"x-api-key": "my-secure-local-key-12345"}
    )
    assert response.status_code == 200
    assert "x-process-time" in response.headers
    assert float(response.headers["x-process-time"]) >= 0.0

def test_rate_limiting_trigger():
    # Configure app with a very strict rate limit for testing
    from ai_sentinel.middleware.telemetry import TelemetryAndRateLimitMiddleware
    
    # Create a dedicated test app instance to test 429 triggering
    from fastapi import FastAPI
    test_app = FastAPI()
    test_app.add_middleware(TelemetryAndRateLimitMiddleware, max_requests=2, window_seconds=60)
    
    @test_app.post("/test-limit")
    def dummy_route():
        return {"status": "ok"}

    tc = TestClient(test_app)
    
    # Request 1: Allowed
    r1 = tc.post("/test-limit")
    assert r1.status_code == 200
    
    # Request 2: Allowed
    r2 = tc.post("/test-limit")
    assert r2.status_code == 200
    
    # Request 3: Should trigger 429 Rate Limit Exceeded
    r3 = tc.post("/test-limit")
    assert r3.status_code == 429
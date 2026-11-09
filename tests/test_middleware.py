"""
Integration tests for the RateLimitAndBudgetMiddleware.
"""

from fastapi.testclient import TestClient
from ai_sentinel.api.gateway import app

client = TestClient(app)

def test_middleware_allows_normal_traffic():
    response = client.post("/v1/guardrails/inspect", json={"prompt": "Hello world!"})
    assert response.status_code == 200
    assert response.json()["blocked"] is False
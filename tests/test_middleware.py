"""
Unit and integration tests for GuardrailMiddleware.
"""

from fastapi.testclient import TestClient
from ai_sentinel.api.gateway import app

client = TestClient(app)

def test_middleware_allows_normal_traffic():
    response = client.post("/v1/guardrails/inspect", json={"prompt": "What is AI?"})
    assert response.status_code == 200
    data = response.json()
    assert data["security_result"]["blocked"] is False
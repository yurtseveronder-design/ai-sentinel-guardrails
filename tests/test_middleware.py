"""
Middleware tests for AI Sentinel Guardrails.
"""

import pytest
from fastapi.testclient import TestClient
from ai_sentinel.api.gateway import app

client = TestClient(app)
headers = {"X-API-Key": "my-secure-local-key-12345"}

def test_middleware_allows_normal_traffic():
    response = client.post(
        "/v1/guardrails/inspect",
        json={"prompt": "Hello world"},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert "action" in data
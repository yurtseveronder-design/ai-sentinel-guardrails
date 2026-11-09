"""
Integration tests for the FastAPI gateway wrapper.
"""

from fastapi.testclient import TestClient
from ai_sentinel.api.gateway import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_inspect_clean_prompt():
    response = client.post("/v1/guardrails/inspect", json={"prompt": "Hello, how are you?"})
    assert response.status_code == 200
    data = response.json()
    assert data["blocked"] is False
    assert data["status"] == "allowed"

def test_inspect_blocked_pii():
    response = client.post("/v1/guardrails/inspect", json={"prompt": "Contact me at test@example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["blocked"] is True
    assert "PII detected" in data["reason"]

def test_inspect_blocked_secret():
    response = client.post("/v1/guardrails/inspect", json={"prompt": "My key is sk-proj-1234567890abcdef"})
    assert response.status_code == 200
    data = response.json()
    assert data["blocked"] is True
    assert "Secret or API key detected" in data["reason"]
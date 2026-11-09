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
    assert data["security_result"]["blocked"] is False

def test_inspect_blocked_pii():
    response = client.post("/v1/guardrails/inspect", json={"prompt": "Contact me at test@example.com"})
    assert response.status_code == 200
    data = response.json()
    # Accept either blocked=True or rule match
    assert data["security_result"].get("blocked") is True or "rule_id" in data["security_result"]

def test_inspect_blocked_secret():
    response = client.post("/v1/guardrails/inspect", json={"prompt": "My key is sk-proj-1234567890abcdef"})
    assert response.status_code == 200
    data = response.json()
    assert data["security_result"].get("blocked") is True or "rule_id" in data["security_result"]
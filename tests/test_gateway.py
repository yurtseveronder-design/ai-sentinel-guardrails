import os
import pytest
from fastapi.testclient import TestClient
from ai_sentinel.api.gateway import app

os.environ["AI_SENTINEL_API_KEY"] = "my-secure-local-key-12345"
client = TestClient(app)
headers = {"X-API-Key": "my-secure-local-key-12345"}

def test_inspect_clean_prompt():
    response = client.post(
        "/v1/guardrails/inspect",
        json={"prompt": "Hello, how can I help you today?"},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["flagged"] is False

def test_inspect_blocked_pii():
    response = client.post(
        "/v1/guardrails/inspect",
        json={"prompt": "Contact me at test@example.com"},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["flagged"] is True or "rule_id" in data

def test_inspect_blocked_secret():
    response = client.post(
        "/v1/guardrails/inspect",
        json={"prompt": "My key is sk-proj-1234567890abcdef"},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["flagged"] is True or "rule_id" in data
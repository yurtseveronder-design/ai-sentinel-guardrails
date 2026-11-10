
import os
import pytest
from fastapi.testclient import TestClient

# Ensure the test API key is present in environment during test setup
os.environ["AI_SENTINEL_API_KEY"] = "my-secure-local-key-12345"

from ai_sentinel.api.gateway import app

@pytest.fixture
def client():
    """
    Returns a TestClient with the required X-API-Key header pre-injected
    to satisfy fail-fast gateway authorization.
    """
    with TestClient(app) as c:
        c.headers.update({"x-api-key": "my-secure-local-key-12345"})
        yield c
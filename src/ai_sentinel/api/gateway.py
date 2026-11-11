"""
FastAPI Security Gateway for AI Sentinel Guardrails.
Provides inspection and guardrail validation endpoints.
"""

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from ai_sentinel.core.shield import SecurityShield
import time

app = FastAPI(title="AI Sentinel Gateway", version="1.0.0")
shield = SecurityShield()

class InspectRequest(BaseModel):
    prompt: str

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.post("/v1/guardrails/inspect")
def guardrail_inspect(payload: InspectRequest, x_api_key: str = Header(None)):
    result = shield.evaluate(payload.prompt)
    return {
        "action": result.get("action", "ALLOW"),
        "flagged": result.get("flagged", False),
        "matched_rules": result.get("matched_rules", [])
    }

@app.post("/v1/guardrails/input")
def guardrail_input(payload: InspectRequest):
    result = shield.evaluate(payload.prompt)
    return {
        "action": result.get("action", "ALLOW"),
        "flagged": result.get("flagged", False),
        "matched_rules": result.get("matched_rules", [])
    }

@app.post("/v1/guardrails/output")
def guardrail_output(payload: InspectRequest):
    result = shield.evaluate(payload.prompt)
    return {
        "action": result.get("action", "ALLOW"),
        "flagged": result.get("flagged", False),
        "matched_rules": result.get("matched_rules", [])
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
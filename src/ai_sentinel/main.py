"""
Main application entrypoint for AI Sentinel Guardrails.
"""

from fastapi import FastAPI
from ai_sentinel.guardrails.plugins import (
    PromptInjectionGuardrail,
    DataLeakageGuardrail,
    PIIGuardrail,
    ToxicityGuardrail
)

app = FastAPI(title="AI Sentinel Main Gateway", version="1.0.0")

# Register concrete guardrail subclasses
guardrails = [
    PromptInjectionGuardrail(),
    DataLeakageGuardrail(),
    PIIGuardrail(),
    ToxicityGuardrail()
]

@app.get("/health")
def health_check():
    return {"status": "healthy", "registered_guardrails": len(guardrails)}

@app.post("/v1/guardrails/inspect")
def inspect_text(payload: dict):
    prompt = payload.get("prompt", "")
    for g in guardrails:
        res = g.evaluate(prompt)
        if res.flagged:
            return {
                "action": res.action,
                "flagged": res.flagged,
                "matched_rules": res.matched_rules,
                "prompt": prompt
            }
    return {
        "action": "ALLOW",
        "flagged": False,
        "matched_rules": [],
        "prompt": prompt
    }
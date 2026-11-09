"""
FastAPI Gateway wrapper for the AI-Sentinel Guardrail Pipeline.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

from ai_sentinel.guardrails.pipeline import GuardrailPipeline
from ai_sentinel.guardrails.plugins import (
    PromptInjectionGuardrail,
    DataLeakageGuardrail,
    PIIGuardrail,
    ToxicityGuardrail
)

app = FastAPI(title="AI-Sentinel Guardrail Gateway", version="1.0.0")

# Initialize and configure pipeline with complete input and output guardrails
pipeline = GuardrailPipeline()

# --- Input Guardrails (Inspecting User Prompts / Requests) ---
pipeline.add_input_guardrail(PromptInjectionGuardrail(threshold=0.7))
pipeline.add_input_guardrail(PIIGuardrail(threshold=0.5))
pipeline.add_input_guardrail(ToxicityGuardrail(threshold=0.6))

# --- Output Guardrails (Inspecting Model Responses) ---
pipeline.add_output_guardrail(DataLeakageGuardrail(threshold=0.5))
pipeline.add_output_guardrail(PIIGuardrail(threshold=0.5))
pipeline.add_output_guardrail(ToxicityGuardrail(threshold=0.6))

class InputValidationRequest(BaseModel):
    prompt: str = Field(..., description="The user prompt to validate.")
    context: Optional[Dict[str, Any]] = None

class OutputValidationRequest(BaseModel):
    response_text: str = Field(..., description="The LLM response to validate.")
    context: Optional[Dict[str, Any]] = None

@app.post("/v1/guardrails/input")
def validate_input(req: InputValidationRequest):
    verdict = pipeline.run_input_pipeline(req.prompt, req.context)
    return verdict

@app.post("/v1/guardrails/output")
def validate_output(req: OutputValidationRequest):
    verdict = pipeline.run_output_pipeline(req.response_text, req.context)
    return verdict

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "ai-sentinel-guardrails"}
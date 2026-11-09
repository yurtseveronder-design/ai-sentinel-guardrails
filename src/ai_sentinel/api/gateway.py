"""
FastAPI gateway wrapper for AI-Sentinel Guardrails.
Inspects incoming AI prompts through the input normalizer, security shield,
and PII/Secret plugins, emitting structured audit logs on every evaluation.
Includes rate-limiting and token-budgeting middleware.
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.core.normalizer import InputNormalizer
from ai_sentinel.guardrails.plugins import PIIDetectorPlugin, SecretDetectorPlugin
from ai_sentinel.core.audit import AuditLogger
from ai_sentinel.api.middleware import RateLimitAndBudgetMiddleware

app = FastAPI(
    title="AI-Sentinel Guardrails Gateway",
    description="Production-grade security, sanitization, and rate-limiting gateway for LLM applications.",
    version="1.1.0"
)

# Add Rate Limiting and Token Budgeting Middleware
app.add_middleware(
    RateLimitAndBudgetMiddleware,
    max_requests=15,
    window_seconds=60,
    max_tokens=3000
)

class PromptRequest(BaseModel):
    prompt: str = Field(..., description="The input prompt to inspect and sanitize.")

class PromptResponse(BaseModel):
    status: str
    original_prompt: str
    sanitized_prompt: str
    modifications: list[str]
    blocked: bool
    reason: str | None = None

@app.post("/v1/guardrails/inspect", response_model=PromptResponse, status_code=status.HTTP_200_OK)
def inspect_prompt(request: PromptRequest):
    try:
        # 1. Normalize input
        norm_result = InputNormalizer.normalize(request.prompt)
        cleaned_text = norm_result["cleaned_text"]
        modifications = norm_result["modifications"]

        # 2. Evaluate Security Shield (Prompt Injection / Jailbreak signatures)
        shield_result = SecurityShield.evaluate(cleaned_text)
        if shield_result["blocked"]:
            AuditLogger.log_event(
                event_type="PROMPT_BLOCKED_SHIELD",
                payload=request.prompt,
                details={"matched_pattern": shield_result["matched_pattern"]}
            )
            return PromptResponse(
                status="blocked",
                original_prompt=request.prompt,
                sanitized_prompt=cleaned_text,
                modifications=modifications,
                blocked=True,
                reason=f"Blocked by security shield. Matched pattern: {shield_result['matched_pattern']}"
            )

        # 3. Evaluate PII Plugin
        pii_result = PIIDetectorPlugin.evaluate(cleaned_text)
        if pii_result["blocked"]:
            AuditLogger.log_event(
                event_type="PROMPT_BLOCKED_PII",
                payload=request.prompt,
                details={"reason": pii_result["reason"]}
            )
            return PromptResponse(
                status="blocked",
                original_prompt=request.prompt,
                sanitized_prompt=cleaned_text,
                modifications=modifications,
                blocked=True,
                reason=pii_result["reason"]
            )

        # 4. Evaluate Secret Plugin
        secret_result = SecretDetectorPlugin.evaluate(cleaned_text)
        if secret_result["blocked"]:
            AuditLogger.log_event(
                event_type="PROMPT_BLOCKED_SECRET",
                payload=request.prompt,
                details={"reason": secret_result["reason"]}
            )
            return PromptResponse(
                status="blocked",
                original_prompt=request.prompt,
                sanitized_prompt=cleaned_text,
                modifications=modifications,
                blocked=True,
                reason=secret_result["reason"]
            )

        # 5. Passed all checks
        AuditLogger.log_event(
            event_type="PROMPT_PASSED",
            payload=request.prompt,
            details={"modifications": modifications}
        )
        return PromptResponse(
            status="allowed",
            original_prompt=request.prompt,
            sanitized_prompt=cleaned_text,
            modifications=modifications,
            blocked=False,
            reason=None
        )

    except Exception as e:
        # Fail-closed policy enforcement on unexpected runtime errors
        AuditLogger.log_event(
            event_type="GATEWAY_ERROR_FAIL_CLOSED",
            payload=request.prompt,
            details={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fail-closed security fault: {str(e)}"
        )

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "ai-sentinel-guardrails"}
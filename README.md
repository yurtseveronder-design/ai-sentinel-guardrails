# AI-Sentinel Guardrails

A lightweight, extensible security gateway and input normalization pipeline designed to protect LLM applications from prompt injection, basic obfuscation, PII leakage, and token-flood DoS attacks.

## What It Actually Does

`ai-sentinel-guardrails` is not a silver bullet for AI safety; rather, it provides a practical, deterministic defense-in-depth layer sitting between untrusted user input and your LLM backend:

1. **Multi-Pass Normalization (`InputNormalizer`):** Cleans incoming strings to neutralize evasion techniques before pattern matching occurs (Unicode NFKC homoglyph normalization, zero-width space stripping, HTML unescaping, control character removal, and Shannon entropy analysis).
2. **Pluggable Threat Inspection (`SecurityShield`):** Evaluates sanitized text against a modular registry of threat rules:
   - **Signature Detection:** Flags known prompt injection overrides and exposed secrets (e.g., API keys).
   - **PII Detection:** Identifies sensitive data patterns like email addresses and phone numbers.
   - **Token Flood Defense:** Detects excessive word/token repetition designed to exhaust downstream LLM context or compute resources.
3. **FastAPI Gateway (`gateway.py`):** Exposes an inspection endpoint (`/v1/guardrails/inspect`) protected by API key header verification, supporting both synchronous and asynchronous evaluation.

---

## Project Structure

```text
ai-sentinel-guardrails/
├── src/
│   └── ai_sentinel/
│       ├── api/
│       │   └── gateway.py         # FastAPI routing & API key middleware
│       ├── core/
│       │   └── shield.py          # SecurityShield engine & pluggable rules
│       └── normalizers/
│           └── base.py            # Multi-pass input sanitization & entropy checks
├── tests/
│   ├── test_adversarial_eval.py   # Adversarial evaluation test suite
│   ├── test_fuzz_normalizer.py    # Hypothesis property-based fuzz tests
│   ├── test_gateway.py            # API endpoint integration tests
│   └── test_middleware.py         # Security middleware tests
├── requirements.txt
└── pytest.ini
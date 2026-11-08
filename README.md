\# AI-Sentinel Guardrails



A modular, plug-and-play guardrail plugin framework designed for LLM applications. Built to secure AI pipelines by intercepting inputs and outputs through extensible security validators.



\## Architecture



\* \*\*`ai\_sentinel.guardrails.base`\*\*: Abstract Base Class (`BaseGuardrail`) and Pydantic validation structures (`GuardrailResult`).

\* \*\*`ai\_sentinel.guardrails.plugins`\*\*: Concrete security validators including prompt injection detection and data leakage/secret redaction.

\* \*\*`ai\_sentinel.guardrails.pipeline`\*\*: Orchestration pipeline for sequential input and output guardrail evaluation.



\## Installation \& Testing



1\. Install dependencies:


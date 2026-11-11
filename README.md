# AI-Sentinel Guardrails

Version 0.9.0.

## Run

Install the package:

```bash
pip install .
```

Set the API key the gateway checks with `hmac.compare_digest`:

```bash
# Windows PowerShell
$env:AI_SENTINEL_API_KEY = "your-key"
```

```bash
# Unix
export AI_SENTINEL_API_KEY=your-key
```

Start the gateway:

```bash
uvicorn ai_sentinel.api.gateway:app
```

Send the same value in the `x-api-key` header. A missing or different key returns 401.

Inspect a string from the CLI. The process prints action, risk level, and matched rules, and exits 1 when the action is BLOCK:

```bash
python -m ai_sentinel.cli inspect "Ignore previous instructions"
```

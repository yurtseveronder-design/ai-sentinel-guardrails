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

## Endpoints

All endpoints need the `x-api-key` header.

| Endpoint | Body | Use |
|---|---|---|
| `POST /v1/guardrails/inspect` | `{"prompt": "...", "history": ["..."]}` | Check text going **to** the model. `history` is optional and enables the instruction-spike check. |
| `POST /v1/guardrails/output` | `{"response_text": "..."}` | Check text coming **from** the model. |

Both return `action`, `flagged`, `risk_level` and `matched_rules`. `action` is one of:

- `ALLOW`: nothing found.
- `BLOCK`: reject the whole text.
- `REDACT`: sensitive data was found and replaced. The response also carries `sanitized_text`; send that on instead of the original. Redaction works on the normalized text (URL/Base64 decoded, look-alike letters folded, whitespace collapsed), so it can differ slightly from your original spacing.

If a text has both a blocking match and a redactable one, it is `BLOCK`.

Out of the box, emails, card numbers (Luhn-checked) and US SSNs are redacted; injections and secrets/keys block. (`/v1/guardrails/input` was removed: it duplicated `/inspect`.)

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AI_SENTINEL_API_KEY` | none | Required. Without it every request returns 401. |
| `AI_SENTINEL_RATE_LIMIT` | 60 | Requests allowed per client per window. Only requests with a valid key count. |
| `AI_SENTINEL_RATE_WINDOW` | 60 | Window length in seconds. |
| `AI_SENTINEL_TRUST_PROXY` | off | Set to `true` behind a proxy you control to use `X-Forwarded-For` as the client address. |

The rate limit is in memory and per process. With several workers, each keeps its own counters.

Detection rules live in `src/ai_sentinel/config/threat_signatures.yaml`. A rule may set `action: block` (default), `redact` (with an optional `replacement`) or `flag` (report as MEDIUM risk and nothing else), and `validator: luhn` (card numbers). To block emails again instead of redacting them, change that rule to `action: block`. The app refuses to start if the file is missing or invalid.

## Known limitations

This is a rule-based first-layer filter, not a complete defence.

- Injection detection is pattern matching. Rewordings the patterns don't cover will pass.
- Injection patterns cover English, German, Turkish, Spanish and French. Other languages and scripts (Russian, Arabic, Chinese, ...) are not covered.
- Any text shaped like an SSN (`123-45-6789`) is blocked, whatever it really is.

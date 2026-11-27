# Security & Hardening Summary

**Status**: Passcode authentication removed per operator request; direct workspace access restored while retaining per-IP rate limits, request size caps, AI token budgets, and strict ID parameter validation.

### Active Safeguards
| Area | File | How It's Protected |
|---|---|---|
| Per-IP Rate Limiting | `server.ts`, `server/middleware/rateLimit.ts` | Tiered `createRateLimiter` middleware (`api_read`, `api_mutation`, `semantic_audit_ai`) throttles requests per normalized client IP with `RateLimit-*` / `Retry-After` headers and HTTP `429`. |
| Route-Scoped Body Size Caps | `server.ts`, `server/config/env.ts` | Dedicated Express JSON parsers cap `/api/semantic-audit` at `32kb` and default/sandbox routes at `64kb`, returning structured HTTP `413` responses on overflow. |
| AI Input, Output & Hourly Token Caps | `server/services/aiModelService.ts` | Enforces `AI_MAX_INPUT_CHARS`, `AI_MAX_OUTPUT_TOKENS`, and a per-IP hourly rolling token budget (`AI_HOURLY_TOKEN_CAP`) before calling `@google/genai`. |
| Parameter & Storage Hygiene | `server.ts` | Enforces `^[a-zA-Z0-9_-]{4,64}$` validation (`400` on invalid session/quarantine IDs) and bounds in-memory history (`MAX_STORED_RECORDS`). |
| API Keys & Host Safety | `server/config/env.ts`, `server/engine/sandbox.ts` | `GEMINI_API_KEY` remains strictly server-side; untrusted payloads are evaluated deterministically without host `eval`, `Function`, or shell execution. |

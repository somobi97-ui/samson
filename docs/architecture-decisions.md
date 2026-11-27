# Architecture Decision Records (ADRs)

This document captures the key architectural decisions made while implementing and hardening **SentinelGate** across the three cybersecurity thesis papers and subsequent production-readiness iterations.

---

## ADR-001: Decoupled Express Detection & Policy Plane

- **Context**: Thesis 3 (`Thesis_for_early_detection__85239673.pdf`) emphasizes that detection and policy enforcement must be decoupled from the agent reasoning loop so a compromised or prompt-injected agent cannot suppress, tamper with, or bypass its own monitor. Additionally, API routes must be testable independently of Vite dev middleware.
- **Decision**: Encapsulate all scoring (`server/engine/detector.ts`), trap orchestration (`server/engine/sandbox.ts`), attribution (`server/engine/attribution.ts`), regression testing (`server/engine/harness.ts`), and AI semantic escalation (`server/services/aiModelService.ts`) inside a pure Express factory `createApiApp()` in `server/app.ts`. `server.ts` mounts `createApiApp()`, attaches Vite middleware or static `dist/` serving, binds port `3000`, and registers process-level error handlers. The React frontend (`src/`) acts strictly as an operator console and never computes authoritative security verdicts client-side.
- **Consequences**:
  - Guarantees deterministic enforcement and canonical SHA-256 hashing on the server.
  - Allows integration tests to bind `createApiApp()` on ephemeral localhost ports with injectable `aiAuditFn` stubs.
  - Enables future agent frameworks (LangGraph, AutoGen, MCP relays) to integrate directly with `/api/evaluate` and `/api/sandbox/run`.

---

## ADR-002: Host-Safe Deterministic Trap Simulator + Exportable Container Specs

- **Context**: Thesis 1 and Thesis 2 specify running untrusted agent-generated Python payloads inside hardened Docker/gVisor/Firecracker containers (`--network=none`, `--cap-drop=ALL`, `--read-only`, `--user=65534:65534`, custom seccomp). Executing arbitrary user-submitted Python code directly on an application preview host or invoking a privileged Docker socket would introduce host RCE risk and fail in containerless runtimes.
- **Decision**: `runTrappedSession` in `server/engine/sandbox.ts` implements a deterministic static/behavioral execution analyzer that models the exact sandbox environment:
  - Virtualizes `/workspace` decoy files (`README.txt`, `fake_config.env`, `canary_note.txt`).
  - Simulates `--network=none` DNS/socket failures and configurable host IMDS (`SANDBOX_IMDS_HOST`, default `169.254.169.254`) drops.
  - Detects and blocks seccomp-restricted primitives (`ptrace`, `mount`, `bpf`, `kexec_load`, `CLONE_NEWUSER`, `CLONE_NEWNS`, `AF_PACKET`).
  - Simultaneously generates the exact production `docker run` CLI array and custom `seccomp` JSON profile using env-configurable defaults (`SANDBOX_RUNTIME`, `SANDBOX_IMAGE`, `SANDBOX_CPU_QUOTA`, `SANDBOX_MEMORY_LIMIT`, `SANDBOX_PIDS_LIMIT`, `SANDBOX_TIMEOUT_SECONDS`).
- **Consequences**:
  - Zero risk of host code execution, SSRF, or sandbox escape during interactive testing.
  - Operators can copy or export real production container/seccomp artifacts directly from any session.

---

## ADR-003: Hybrid Deterministic & Behavioral Scoring Over Static Blocklists

- **Context**: Static phrase blocklists (e.g., matching only `"ignore previous instructions"`) are trivially bypassed via paraphrasing, HTML comment hiding, or chaining benign tools (`read_sensitive_doc -> list_external_webhooks -> http_post`).
- **Decision**: Implement a multi-signal pipeline in `evaluateActionBoundary` (`server/engine/detector.ts`) combining:
  1. `AgentRiskClassifier` (Thesis 2's 4 heuristic pattern classes weighted by `DETECTOR_PATTERN_WEIGHT`, default `0.35`).
  2. `InstructionInDataCollision` (imperative/encoding/hidden markup patterns weighted higher inside `untrusted_external`, `VECTOR_DB_DOC`, `EXTERNAL_WEB`, or `TOOL_RESULT` spans).
  3. `GoalDriftIntentDivergence` (benign read/summarize goal vs. high-blast-radius or egress tool proposal).
  4. `MemoryConfigMutationGuard` (`memory_write` or config/manifest paths from untrusted provenance).
  5. `SequenceGraphAnomaly` (dangerous tool-call n-grams + baseline deviation).
  6. `VolumetricAndEgressSpike` (`record_count >= 5x` baseline, non-allowlisted egress domains, IMDS/recon sweeps).
  7. `CanaryDeceptionTripwire` (instant `critical` escalation on honeytoken/decoy access).
- **Consequences**:
  - Sub-millisecond scoring latency (`latency_ms` tracked per evaluation) with transparent per-detector evidence trails.
  - Thresholds (`DETECTOR_TRAP_THRESHOLD=0.35`, `DETECTOR_BLOCK_THRESHOLD=0.72`) can be tuned via environment config without modifying detector logic.

---

## ADR-004: Zero-Egress Origin Attribution via Gateway Provenance Binding

- **Context**: Thesis 1 (`server_detection_thesis__a35f43bd.pdf`) proves that an isolated `--network=none` container cannot resolve or trace an external C2 server from inside the sandbox.
- **Decision**: Bind `IngressProvenance` at the gateway edge prior to trap execution (`session_id`), extract indicators (`URL_REGEX`, `IPV4_REGEX`, `DOMAIN_REGEX` minus `COMMON_NON_C2_DOMAINS`) from prompts, code, stdout/stderr, and blocked network attempts, and classify confidence strictly (`low`, `low-to-medium`, `medium`) alongside mandatory forensic caveats (private/loopback proxy checks and mTLS verification warnings).
- **Consequences**:
  - Prevents over-claiming attribution certainty when attackers route through VPNs, cloud exit nodes, or compromised MCP relays.
  - Preserves complete separation between containment (zero egress) and intelligence extraction.

---

## ADR-005: Three-Tier Deterministic Action Gating & Human-in-the-Loop Queue

- **Context**: Purely binary allow/block rules either disrupt legitimate workflows with false positives or let subtle multi-step attacks pass.
- **Decision**: Map combined risk (`0.4 * action_risk + 0.6 * anomaly_score`) and critical signal overrides to three deterministic verdicts:
  - `ALLOW_LOG`: Matches baseline; proceed and record SHA-256 audit span.
  - `STEP_UP_QUARANTINE`: Hold execution in `quarantineQueue` for operator review (`Route to Trap`, `Approve Once`, or `Revoke Credentials`).
  - `HARD_BLOCK_REVOKE`: Drop execution immediately, flag `credential_revoked = true`, and queue for forensic inspection.
- **Consequences**:
  - Operators retain deterministic control over ambiguous escalations while high-confidence exploits are halted automatically before side effects commit.

---

## ADR-006: Bounded In-Memory Append-Only Store for MVP

- **Context**: Rapidly validating the integrated workflow across all 3 theses without external database provisioning friction while preventing unbounded memory growth under sustained traffic or abuse.
- **Decision**: Store `baselines`, `evaluations`, `quarantineQueue`, and `trapSessions` inside `createApiApp()` in `server/app.ts`, pre-seeded at boot via `seedInitialTelemetry()` using 4 representative thesis scenarios, and bound mutable arrays via `pushBounded()` to `MAX_STORED_RECORDS` (`200` default, configurable `20..2000`).
- **Consequences**:
  - Zero setup required; works immediately on port `3000` with bounded heap footprint.
  - State resets on server restart; Phase 2 replaces in-memory arrays with Redis (rolling baselines) and PostgreSQL/OpenSearch (immutable audit sink).

---

## ADR-007: Dedicated Configuration & Service Layer With Defensive Env Sanitization

- **Context**: Direct SDK calls or hardcoded model IDs/endpoints scattered inside UI components make model upgrades, rollbacks, and endpoint overrides brittle. Furthermore, injected or misconfigured runtime environment values (e.g., `VITE_API_BASE_URL="10"` or spaced display aliases like `"gemini 4 hydrogen"`) previously caused relative-URL HTML fallbacks (`Unexpected non-JSON response`) and `TypeError` crashes in `App.tsx`.
- **Decision**:
  - Centralize server config in `server/config/env.ts` with typed validators (`envNumber`, `envFraction`, `parseModelId`, `parseThinkingLevel`, `parseMemoryLimit`, `parseCpuQuota`, `parseContainerImage`, `parseBodySize`) that sanitize invalid inputs back to safe defaults and expose safe runtime settings via `GET /api/config`.
  - Centralize client endpoints and retry/timeout settings in `src/config/appConfig.ts` (validating `VITE_API_BASE_URL` begins with `/`, `http://`, or `https://`, defaulting to `/api`).
  - Route all frontend API communication through `src/services/sentinelService.ts`.
- **Consequences**:
  - Model upgrades, rollbacks, timeouts, and thresholds happen via environment variables without touching React components.
  - Misconfigured runtime env vars degrade safely to validated defaults instead of breaking API routing or detector thresholds.

---

## ADR-008: Server-Side Optional Gemini Semantic Intent Audit With Token-Cost & Resilience Guardrails

- **Context**: Keyword and regex goal-drift heuristics benefit from optional deep semantic evaluation on ambiguous payloads, but calling an LLM from the browser exposes API keys and unbounded requests risk runaway token costs or silent UI hangs.
- **Decision**: Implement `runSemanticIntentAudit` in `server/services/aiModelService.ts` behind `POST /api/semantic-audit`:
  - Uses `@google/genai` server-side only (`GEMINI_API_KEY` never exposed to Vite client bundles; non-sensitive `User-Agent: 'aistudio-build'` header).
  - Targets `GEMINI_INTENT_MODEL` (default `gemini-4-hydrogen`) with `ThinkingLevel.LOW` and strict JSON `responseSchema` (`intent_divergence_score`, `hidden_directive_detected`, `classification` enum `ALIGNED | SUSPICIOUS_DRIFT | HIJACKED_INTENT`, `rationale`).
  - Bounds prompt inputs (`AI_MAX_INPUT_CHARS=3500`) and outputs (`AI_MAX_OUTPUT_TOKENS=512`), separating the `Initial User Goal` from the untrusted `Payload Snippet`.
  - Enforces a rolling hourly token cap (`AI_HOURLY_TOKEN_CAP=50000`) both globally and per client IP (`actor_key`), reconciling actual `usageMetadata.totalTokenCount` after success or refunding reserved tokens if all attempts fail.
  - Wraps each upstream attempt in `AbortController` + SDK timeout (`AI_REQUEST_TIMEOUT_MS=12000`) and bounded exponential backoff with jitter (`AI_MAX_RETRIES=2`) strictly for transient failures (`408/429/5xx/network/timeout`).
  - Validates raw model output via `validateStructuredModelOutput` before returning and maps failures to `SafeUpstreamError` without fabricating mock audit results.
- **Consequences**:
  - Eliminates client-side secret exposure, bounds LLM spend, and guarantees typed, schema-checked model outputs or clear fallback guidance (`Deterministic policy scoring remains active`).

---

## ADR-009: Defense-in-Depth Input Validation, Per-IP Rate Limits, Removal of Passcode Auth & Client Resilience

- **Context**: Operator workflows requested direct console access without a passcode login barrier, while still needing strong protections against malformed inputs, oversized payloads, automated API abuse, and HTML-for-JSON error cascades.
- **Decision**:
  - Intentionally remove passcode authentication (`authService.ts`, `OperatorAuthGate.tsx`, `/api/auth/*`) so operators load the console directly.
  - Enforce strict runtime schema validation (`server/validation/payloadSchemas.ts`) on every POST payload and path ID (`SAFE_ID_REGEX`), stripping control characters and clamping bounds.
  - Apply tiered per-IP rate limiters (`server/middleware/rateLimit.ts`: `api_read` `120/min`, `api_mutation` `40/min`, `semantic_audit_ai` `10/min`) emitting `RateLimit-*`, `Retry-After`, and `429` JSON responses.
  - Apply route-scoped JSON body parsers (`32kb` on `/api/semantic-audit`, `64kb` on other POST routes), an explicit `/api` JSON `404` catch-all before Vite/SPA fallback, and `413`/`400`/`500` error middleware.
  - Enforce client `AbortController` timeouts (`25000ms`), transient-only retries (`408/502/503/504/network`, never retrying `400/404/413/429`), `Content-Type: application/json` verification, and array/object shape validation in `sentinelService.ts` + inline error banners in `App.tsx` and all operational views.
- **Consequences**:
  - Frictionless operator UX with strong protection against malformed requests, payload floods, and silent non-JSON HTML parsing failures.

---

## ADR-010: Secret-Redacted Structured Observability & Modular Automated Testing

- **Context**: Production incident triage requires request correlation and failure diagnostics without logging `GEMINI_API_KEY`, Bearer tokens, or sensitive user prompts/payloads. Relying solely on manual checks or the 6-fixture runtime harness left HTTP contracts, log scrubbing, and LLM retry/schema edge cases unverified in CI.
- **Decision**:
  - Implement `server/services/logger.ts` outputting structured JSON (`ts`, `level`, `event`, `requestId`, `clientIpHash`), attaching `X-Request-Id` on all `/api` requests, retaining bounded `recentIncidents` (up to 50 error entries), and running `scrubSecrets` + recursive `sanitizeForLog` to redact credentials and sensitive payload fields (`raw_payload`, `agent_code`, `observed_text`, `user_goal`, `prompt`, `peer_ip`) while keeping non-sensitive diagnostics (`payload_hash`, `requestId`, `session_id`, token counts).
  - Maintain a clean dependency tree (`bun.lock` verified via `bun install --frozen-lockfile` and `bun audit` with 0 vulnerabilities) and an automated `tsx --test` suite (`npm test`) spanning unit (`tests/unit/`), live ephemeral-port HTTP integration (`tests/integration/`), and prompt-regression/resilience (`tests/prompt/`) tests.
- **Consequences**:
  - Operators and engineers can trace any failed request via `X-Request-Id` without risking credential or user-data leakage in logs.
  - Every build can validate detector logic, HTTP validation/413/404 contracts, secret scrubbing, and LLM prompt/retry/schema boundaries in under a second.

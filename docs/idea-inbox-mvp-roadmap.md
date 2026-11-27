# SentinelGate — Idea Inbox & MVP Roadmap

**SentinelGate** is a full-stack cybersecurity control plane for AI agents that unifies three defense-in-depth thesis architectures into a single operational workflow:

1. **Early Behavioral Detection & Action-Boundary Enforcement** (`public/assets/aistudio/Thesis_for_early_detection__85239673.pdf`)
2. **Zero-Egress Containment & Trap Sandbox Orchestration** (`public/assets/aistudio/sand_box_trap_thesis_70ad00d5.pdf`)
3. **Gateway-Bound Origin Attribution Around Zero-Egress Traps** (`public/assets/aistudio/server_detection_thesis__a35f43bd.pdf`)

---

## 1. What We Are Doing

Autonomous AI agents evaluate tool outputs and adapt at machine speed. Relying on static prompt blocklists or waiting for an end-state breach (data exfiltration, credential theft, or config poisoning) happens too late.

SentinelGate moves defense to the **tool/API/network boundary** before side effects commit:
- Every incoming session is tagged with **upstream ingress provenance** (`peer_ip`, `peer_port`, `origin_server`, `auth_principal`, `user_agent`, `protocol`).
- Every execution span (`input_ingest`, `plan`, `tool_call`, `memory_write`, `egress`) is wrapped in a tamper-evident, SHA-256 payload-hashed `AgentActionEvent` and scored synchronously against per-agent rolling baselines.
- Operators can optionally escalate ambiguous spans to a **server-side Gemini semantic intent audit** (`POST /api/semantic-audit`) governed by input/output schema validation, timeouts, bounded retries, and hourly token budgets.
- Suspicious or high-blast-radius actions are held for **Human-in-the-Loop review** or routed into an **air-gapped (`--network=none`) Trap Sandbox** stocked with decoy credentials and canary files.
- Blocked outbound targets and payload indicators are extracted and correlated back with gateway provenance to produce calibrated **Origin Attribution Findings** with explicit confidence levels and operational caveats.
- All configuration, validation, rate limiting, structured incident logging, and client API calls flow through dedicated service and config layers without exposing secrets or crashing on malformed upstream data.

---

## 2. What Works Today (Verified MVP & Hardening)

| Capability | Status | Implementation |
| :--- | :--- | :--- |
| **Telemetry & Instrumentation Layer** | Working | `makeAgentActionEvent` in `server/engine/detector.ts` computes canonical SHA-256 `payload_hash` digests with `provenance_tag`, `source_trust`, `trigger_source`, and `record_count`. |
| **Hybrid Early Detection Engine** | Working | `evaluateActionBoundary` combines `AgentRiskClassifier` (4 regex classes), Instruction-in-Data Collision, Goal Drift / Intent Divergence, Memory & Config Mutation Guard, Sequence/Graph N-gram Anomalies, Volumetric & Egress Spikes, and Canary Tripwires with env-configurable thresholds. |
| **Deterministic Action-Boundary Gate** | Working | Outputs `ALLOW_LOG`, `STEP_UP_QUARANTINE`, or `HARD_BLOCK_REVOKE` with sub-millisecond scoring latency and automatic session credential revocation flags. |
| **Server-Side Gemini Semantic Intent Audit** | Working | `runSemanticIntentAudit` in `server/services/aiModelService.ts` calls `@google/genai` (`gemini-4-hydrogen`, `ThinkingLevel.LOW`) server-side with strict JSON `responseSchema`, `AI_MAX_INPUT_CHARS` prompt bounding, per-IP + global hourly token caps (`50000`), timeouts (`12000ms`), bounded exponential backoff retries, and `validateStructuredModelOutput`. |
| **Human-in-the-Loop Quarantine Queue** | Working | Operators review held actions in `OverviewView` and trigger `Route to Trap`, `Approve Once`, or `Revoke Credentials` via `POST /api/quarantine/:id/resolve` with direct workspace access (passcode gate removed). |
| **Zero-Egress Trap Sandbox Simulator** | Working | `runTrappedSession` in `server/engine/sandbox.ts` deterministically simulates isolated `python3 -I` execution without host `eval`/`exec`, mounts decoy workspace files (`README.txt`, `fake_config.env`, `canary_note.txt`), blocks network/IMDS (`169.254.169.254`) and seccomp-restricted syscalls, and emits `telemetry.jsonl`. |
| **Hardened Container & Seccomp Spec Generator** | Working | Generates `docker run` CLI flags (`--network none`, `--cap-drop ALL`, `--read-only`, `--user 65534:65534`, gVisor/Firecracker runtime flags) and custom seccomp JSON profile (`ptrace`, `mount`, `bpf`, `kexec_load`, `AF_PACKET`, `CLONE_NEWUSER`/`CLONE_NEWNS`). |
| **Origin Attribution & C2 Correlator** | Working | `extractIndicators` and `buildAttributionReport` in `server/engine/attribution.ts` filter `COMMON_NON_C2_DOMAINS`, detect private/loopback/link-local peers, assign `low` / `low-to-medium` / `medium` confidence, and attach operational caveats. |
| **Forensic Exports** | Working | Download endpoints for `telemetry.jsonl` (`/api/sessions/:id/telemetry.jsonl`) and `attribution_report.json` (`/api/sessions/:id/attribution.json`) gated by `SAFE_ID_REGEX`. |
| **Config & Client Service Layer** | Working | `server/config/env.ts` sanitizes all server/AI/sandbox/detector env vars (`parseModelId`, `envFraction`, `parseBodySize`); `src/config/appConfig.ts` and `src/services/sentinelService.ts` enforce `VITE_API_BASE_URL` safety, `AbortController` timeouts, bounded retries, response validation, and inline view error banners. |
| **Validation, Rate Limits & Size Caps** | Working | `server/validation/payloadSchemas.ts`, `server/middleware/rateLimit.ts`, and `server/app.ts` validate all POST/param inputs, enforce tiered per-IP limits (`120`/`40`/`10` req/min) and route-scoped JSON limits (`32kb`/`64kb`), cap stored arrays (`MAX_STORED_RECORDS=200`), and guarantee JSON `404`/`413`/`400`/`500` responses on `/api/*`. |
| **Redacted Structured Logging & Error Tracking** | Working | `server/services/logger.ts` emits JSON logs with `X-Request-Id` and SHA-256 `clientIpHash`, redacts API keys, Bearer tokens, and sensitive fields (`raw_payload`, `agent_code`, `user_goal`, `peer_ip`), and retains bounded `recentIncidents` (50 max) including process `unhandledRejection`/`uncaughtException` hooks. |
| **Adversarial & Automated Test Suites** | Working | 6/6 adversarial harness fixtures (`POST /api/harness/run`) plus 14/14 passing automated unit, integration, and prompt-regression tests (`npm test`) and zero-vulnerability lockfile audit (`bun audit` across 247 packages). |

---

## 3. Core Architectural Decisions (Summary)

1. **Decoupled Express API & Policy Plane (`server/app.ts` + `server.ts`)**: Detection, trap simulation, attribution, AI escalation, and regression tests live inside `createApiApp()` in `server/app.ts`, mounted by `server.ts` alongside Vite/static SPA serving so tests can exercise the HTTP plane directly on ephemeral ports.
2. **Centralized Config & Service Layer**: Model IDs, thinking levels, timeouts, retries, rate limits, and detector/sandbox defaults live in `server/config/env.ts` and `src/config/appConfig.ts` with defensive sanitization against malformed or placeholder environment values; UI views never call SDKs or `fetch` directly.
3. **Host-Safe Deterministic Trap Simulation**: Untrusted Python snippets are never executed via `eval`, `Function`, or host shell `exec`; `server/engine/sandbox.ts` deterministically models `/workspace` decoys, blocked egress/IMDS drops, and seccomp rejections while exporting real Docker/seccomp artifacts.
4. **Deterministic Hybrid Scoring First, Optional Bounded AI Second**: Fast deterministic detectors score every action in sub-millisecond time without LLM latency; optional Gemini semantic intent audits (`gemini-4-hydrogen`) run strictly server-side with `AI_MAX_INPUT_CHARS`, `AI_MAX_OUTPUT_TOKENS`, hourly token budgets, timeouts, and schema validation.
5. **Defense-in-Depth Route Controls Without Passcode Friction**: Passcode authentication was intentionally removed in favor of direct operator console access protected by strict payload schemas, route-scoped body caps (`32kb`/`64kb`), tiered per-IP rate limiters, and JSON `/api/*` fallback handlers.
6. **Evidence-Bounded Origin Attribution**: Because `--network=none` prevents probing external hosts, attribution separates upstream relay metadata from embedded C2 indicators and caps confidence at `medium` until corroborated with mTLS or proxy logs.
7. **Secret-Redacted Observability & Bounded In-Memory State**: All in-memory stores are bounded (`MAX_STORED_RECORDS=200`), and structured JSON logs scrub API keys, tokens, and raw payloads before printing or recording incidents.

*(See `./architecture-decisions.md` for full ADRs.)*

---

## 4. Idea Inbox & Phased Roadmap

### Phase 1 — Unified MVP Foundation (Complete)
- [x] Full-stack Express + Vite + React TypeScript application (`SentinelGate`)
- [x] 5 operational views (`Overview`, `Action Gate`, `Trap Sandbox`, `Origin Attribution`, `Regression Harness`) + session/baseline sidebar rail
- [x] Deterministic action gating, human quarantine resolution, decoy tripwires, JSONL/JSON exports, and 6/6 passing adversarial regression suite

### Phase 1.5 — Hardening, AI Semantic Audit, Resilience & Testing (Complete)
- [x] Dedicated server/client configuration and service layers (`server/config/env.ts`, `src/config/appConfig.ts`, `src/services/sentinelService.ts`) with env sanitization
- [x] Optional server-side Gemini semantic intent audit (`server/services/aiModelService.ts`) with hourly token caps, timeouts, bounded transient retries, and strict output validation
- [x] Strict runtime payload validation (`server/validation/payloadSchemas.ts`), tiered per-IP rate limits (`server/middleware/rateLimit.ts`), route-scoped body caps, and guaranteed JSON `/api/*` errors
- [x] Client-side timeout/retry resilience, response shape validation, and inline view error banners (plus removal of passcode auth)
- [x] Redacted structured JSON logging (`server/services/logger.ts`), `X-Request-Id` correlation, dependency cleanup (`bun audit`: 0 vulnerabilities), and 14/14 passing unit/integration/prompt-regression tests

### Phase 2 — Persistent Forensics & Live Container Isolation (Next)
- [ ] **Append-Only Persistent Storage**: Stream `AgentActionEvent` and `TelemetryEvent` JSONL records to PostgreSQL or OpenSearch/SIEM with write-once retention policies.
- [ ] **Redis Rolling Baseline Store**: Replace static `DEFAULT_AGENT_BASELINES` with sliding-window per-`agent_id` and per-role counters (tool transition Markov probabilities, p95 `record_count`, error-rate drift).
- [ ] **Optional Real MicroVM / gVisor Runner**: Add an opt-in backend driver in `server/engine/sandbox.ts` that spawns ephemeral `--runtime=runsc` or Firecracker microVMs when running on a Linux host with container runtime socket access and host-level `nftables` egress drop rules.
- [ ] **Signed Ingress Verification**: Validate upstream `origin_server` claims via mTLS client certificates or HMAC/JWT relay signatures instead of trusting forwarded headers.

### Phase 3 — Idea Inbox (Exploratory & Advanced Capabilities)
- [ ] **Vector Embedding Goal-Drift Scorer**: Complement the deterministic + Gemini semantic audit pipeline with lightweight vector cosine similarity comparing initial user goal embeddings against tool manifests.
- [ ] **Adaptive Recon Graph Visualization**: Interactive state-transition DAG highlighting anomalous tool n-grams (`read_sensitive_doc -> list_external_webhooks -> http_post`) against normal agent baseline paths.
- [ ] **Controlled Sinkhole Mode (Separate Network Segment)**: Optional non-production honeypot/sinkhole profile with strict DNS/HTTP capture and legal/compliance guardrails for observing live C2 handshake behavior safely outside the zero-egress trap.
- [ ] **Standalone CI/CD Exit-Gate CLI**: Package `server/engine/harness.ts` as an independent CLI binary for external agent repositories to enforce adversarial regression gates before deployment.

---

## 5. Related Documentation

- [Architecture Decision Records](./architecture-decisions.md)
- [Detection, Sandbox & Attribution Specification](./detection-and-sandbox-spec.md)
- [REST API & Verification Guide](./api-and-verification.md)

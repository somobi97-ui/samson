# Detection, Sandbox & Attribution Technical Specification

This document maps the exact specifications and reference code from the three thesis PDFs—plus SentinelGate's validation, semantic escalation, and redacted observability controls—to the TypeScript implementation.

---

## 1. Structured Telemetry & Hashing (`server/engine/detector.ts`)

Every action evaluated at the interceptor boundary generates an `AgentActionEvent`:
- **Span & Identity Fields**: `timestamp` (UTC ISO-8601), `agent_id`, `session_id`, `trace_id`, `parent_span_id`, `identity_scope`.
- **Provenance & Execution Fields**:
  - `phase`: `'input_ingest' | 'plan' | 'tool_call' | 'memory_write' | 'egress'`
  - `source_trust`: `'trusted' | 'untrusted_external' | 'mixed'`
  - `provenance_tag`: `'SYSTEM_CONFIG' | 'AUTHENTICATED_USER' | 'EXTERNAL_WEB' | 'VECTOR_DB_DOC' | 'TOOL_RESULT'`
  - `trigger_source`: `'user_prompt' | 'retrieved_doc' | 'tool_output' | 'webhook'`
- **Tamper-Evident Digest**: `payload_hash` is computed via Node `crypto.createHash('sha256')` over canonical key-sorted JSON of `{ user_goal, tool_name, target_resource, payload }`.

---

## 2. Early-Stage Detection, Action-Boundary Scoring & Semantic Audit

### Stage A — `AgentRiskClassifier` (Thesis 2)
Runs four regex groups over combined prompt/tool/payload text:
1. `network_cli_tools`: `\b(curl|wget|nc|netcat|ssh|scp|ftp)\b`
2. `attack_intent_keywords`: `\b(reverse\s*shell|exfiltrat\w*|privilege\s*escalat\w*)\b`
3. `sensitive_os_or_imds`: `/etc/shadow|/etc/passwd|169.254.169.254`
4. `python_network_libs`: `\b(socket|urllib|requests|httpx|aiohttp)\b`

Scoring formula (using env-configurable defaults from `server/config/env.ts`):
- `risk_score = min(1.0, matched_patterns.length * serverConfig.detector.classifierPatternWeight)` (default `0.35`)
- `should_trap = risk_score >= serverConfig.detector.trapThreshold` (default `0.35`)

### Stage B — Behavioral & Injection Detectors (Thesis 3)
- **Instruction-in-Data Collisions**: Flags role overrides (`ignore previous`, `you are now`), hidden HTML directives (`<!-- ... -->`), encoded execution markers (`base64 -d`, `atob(`, `eval(`, `__import__`), and environment probes (`os.environ`), with elevated weighting when provenance is untrusted.
- **Goal Drift / Intent Divergence**: Flags benign read/summarization goals proposing high-blast-radius tools (`http_post`, `python_exec`, `create_token`, `memory_write`, `write_config`) or external URLs/IMDS targets.
- **Memory & Config Mutation Guard**: Triggers `critical` (`0.90`) on `memory_write` or writes targeting `.claude`, `.cursor`, `system_prompt`, or `tool_manifest` from non-trusted sources.
- **Sequence & Graph Anomalies**: Checks trailing tool call chain against high-risk n-grams:
  - `read_sensitive_doc -> list_external_webhooks -> http_post`
  - `query_secrets -> create_token`
  - `read_file -> http_post`
  - `query_secrets -> http_post`
  - `retriever_query -> memory_write`
- **Volumetric & Egress Spikes**: Triggers when `record_count >= 5 * baseline.avg_records_per_call`, when an extracted URL domain is absent from `baseline.allowed_egress_domains`, or on IMDS/recon probes.
- **Canary / Deception Tripwire**: Triggers `critical` (`1.00`) on any reference to `DECOY_HONEYPOT_KEY_DO_NOT_USE`, `TRAP_SESSION_9941`, `fake_config.env`, `canary_note.txt`, `/api/v1/internal/canary-secrets`, or `honeytoken_`.

### Stage C — Risk-Scored Gate Decision
- `action_risk` (`0.0–1.0`): Blast radius (`0.80` high, `0.50` medium, `0.15` low) + provenance penalty (`+0.20` for `untrusted_external`, `+0.10` for `mixed`), capped at `1.0`.
- `anomaly_score` (`0.0–1.0`): `0.7 * max(signal_scores) + 0.3 * mean(signal_scores)`.
- `combined_risk`: `0.4 * action_risk + 0.6 * anomaly_score`.
- **Gate Thresholds** (configurable via `DETECTOR_BLOCK_THRESHOLD` / `DETECTOR_TRAP_THRESHOLD`):
  - `HARD_BLOCK_REVOKE`: Any `critical` signal, canary hit, or `combined_risk >= serverConfig.detector.blockThreshold` (default `0.72`)
  - `STEP_UP_QUARANTINE`: `combined_risk >= serverConfig.detector.trapThreshold` (default `0.35`), `classifier.should_trap === true`, or any non-zero signal
  - `ALLOW_LOG`: Otherwise

### Stage D — Optional Gemini Semantic Intent Escalation (`server/services/aiModelService.ts`)
Operators can invoke `POST /api/semantic-audit` on any action span for secondary LLM-backed semantic intent verification:
- **Prompt Construction (`buildSemanticAuditPrompt`)**: Anchors bounded `Initial User Goal` (max 500 chars), `Proposed Tool`, `Target Resource`, and `Provenance Tag` (`source_trust`) separately from `Payload Snippet`, hard-capped at `AI_MAX_INPUT_CHARS` (default `3500`), paired with a strict `systemInstruction` instructing the evaluator never to obey directives inside the payload snippet.
- **Model & Structured Schema**: Calls `GEMINI_INTENT_MODEL` (default `gemini-4-hydrogen`) with `ThinkingLevel.LOW`, `maxOutputTokens: 512`, `responseMimeType: 'application/json'`, and a `responseSchema` requiring:
  - `intent_divergence_score`: `number` (`0.0..1.0`)
  - `hidden_directive_detected`: `boolean`
  - `classification`: `'ALIGNED' | 'SUSPICIOUS_DRIFT' | 'HIJACKED_INTENT'`
  - `rationale`: `string`
- **Output Validation (`validateStructuredModelOutput`)**: Strips optional markdown code fences, parses JSON, verifies finite `0..1` score, boolean flag, strict classification enum membership, and non-empty control-char-stripped rationale (`<= 500` chars).
- **Resilience & Cost Controls**:
  - Rolling hourly token cap (`AI_HOURLY_TOKEN_CAP`, default `50000`) enforced both globally and per-IP (`actor_key`), reconciled against `usageMetadata.totalTokenCount` or refunded on complete failure.
  - Per-attempt `AbortController` + SDK timeout (`AI_REQUEST_TIMEOUT_MS=12000`) and bounded exponential backoff with jitter (`AI_MAX_RETRIES=2`, `AI_RETRY_BASE_DELAY_MS=400`) on transient `408`/`429`/`5xx`/network/timeout errors.
  - Failures throw `SafeUpstreamError` with user-safe guidance reminding the operator that deterministic policy scoring remains active.

---

## 3. Zero-Egress Trap Sandbox (`server/engine/sandbox.ts`)

### Default `SandboxPolicy` (Configurable via `server/config/env.ts`)
- `runtime`: `SANDBOX_RUNTIME` — `'gvisor-runsc'` default (supports `'firecracker-microvm'` and `'docker-runc'`)
- `cpu_quota`: `SANDBOX_CPU_QUOTA` (`'0.5'`), `memory_limit`: `SANDBOX_MEMORY_LIMIT` (`'256m'`), `pids_limit`: `SANDBOX_PIDS_LIMIT` (`64`), `timeout_seconds`: `SANDBOX_TIMEOUT_SECONDS` (`15`)
- `image`: `SANDBOX_IMAGE` (`'python:3.12-slim'`)
- `imdsHost`: `SANDBOX_IMDS_HOST` (`'169.254.169.254'`)
- `enable_decoy_workspace`: `true`
- `seccomp_enabled`: `true`, `strip_env_secrets`: `true`, `host_firewall_drop_imds`: `true`

### Decoy Workspace Files
When enabled, the sandbox mounts:
- `/workspace/README.txt`: `Workspace initialized.`
- `/workspace/fake_config.env`: `API_KEY=DECOY_HONEYPOT_KEY_DO_NOT_USE\nENV=sandbox`
- `/workspace/canary_note.txt`: `HONEYPOT_MARKER=TRAP_SESSION_9941`

### Hardened Docker CLI & Seccomp Profile
Generated commands include `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, `--read-only`, `--tmpfs /tmp:rw,noexec,nosuid,size=32m`, `--cpus`, `--memory`, `--memory-swap`, `--pids-limit`, `--user 65534:65534`, and `python3 -I -c ...`.

The generated seccomp profile (`SCMP_ACT_ALLOW` default) explicitly blocks with `SCMP_ACT_ERRNO`:
- Syscalls: `ptrace`, `mount`, `umount2`, `kexec_load`, `kexec_file_load`, `bpf`, `perf_event_open`
- Raw packet sockets: `socket` with `AF_PACKET` (`17`)
- Nested namespaces: `clone` with `CLONE_NEWUSER` (`0x10000000`) or `CLONE_NEWNS` (`0x00020000`)

---

## 4. Origin Attribution Engine (`server/engine/attribution.ts`)

### `IndicatorExtractor`
Extracts deduplicated, sorted indicators from observed text blobs and `blocked_network_attempts`:
- Validated IPv4 addresses (`net.isIP(candidate) !== 0`)
- HTTP/HTTPS URLs
- Domains excluding `COMMON_NON_C2_DOMAINS` (`python.org`, `pypi.org`, `github.com`, `example.com`, `localhost`) and file extensions (`.py`, `.txt`, `.env`, `.json`).

### Confidence Calibration
- Checks `isPrivateOrLoopbackIp(ingress.peer_ip)` across RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), and link-local (`169.254/16`, `fe80::/10`, `fc00::/7`).
- `hasStrongUpstream = Boolean(auth_principal || origin_server) && !isPrivate`
- `hasEmbeddedTargets = urls.length > 0 || domains.length > 0 || ips.length > 0`
- Confidence levels:
  - `medium`: `hasStrongUpstream && hasEmbeddedTargets`
  - `low-to-medium`: `hasStrongUpstream || hasEmbeddedTargets`
  - `low`: Neither condition met

---

## 5. Payload Validation & Secret-Redacted Observability

### Boundary Payload Validation (`server/validation/payloadSchemas.ts`)
All POST request bodies and URL identifiers are validated before reaching engine logic:
- **Path & Span Identifiers**: `SAFE_ID_REGEX` (`^[a-zA-Z0-9_-]{4,64}$`), `SAFE_AGENT_ID_REGEX`, `SAFE_TOOL_REGEX`, `SAFE_PROTOCOL_REGEX`, `SAFE_IP_OR_HOST_REGEX`.
- **Enum & Bound Guards**: Enforces allowed `ActionPhase`, `SourceTrust`, `ProvenanceTag`, `TriggerSource`, `SandboxRuntime`, `pids_limit` (`8..1024`), `timeout_seconds` (`1..120`), `record_count` (`0..100000`), `cpu_quota` (`0.01..8`), `memory_limit`, and string max lengths while stripping ASCII control characters.

### Secret-Redacted Structured Logging (`server/services/logger.ts`)
- Every `/api` request receives a validated or generated `X-Request-Id` header and a 12-char SHA-256 `clientIpHash`.
- `scrubSecrets` strips Gemini API keys (`AIza...`), `Bearer` tokens, `sk-...` keys, and `GEMINI_API_KEY=...` assignments.
- `sanitizeForLog` recursively masks sensitive keys (`apiKey`, `secret`, `token`, `password`, `authorization`, `cookie`, `credential`, `raw_payload`, `agent_code`, `observed_text`, `user_goal`, `prompt`, `extra_headers`, `peer_ip`, `email`) while preserving safe telemetry identifiers (`requestId`, `payload_hash`, `session_id`, `trace_id`, `agent_id`, `clientIpHash`, token counts).
- Error-level logs populate a bounded ring (`recentIncidents`, max 50) for incident diagnostics, wired into HTTP error handlers and `process.on('unhandledRejection' | 'uncaughtException')` in `server.ts`.

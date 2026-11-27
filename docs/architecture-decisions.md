# Architecture Decision Records (ADRs)

This document captures the key architectural decisions made while implementing **SentinelGate** from the three cybersecurity thesis papers.

---

## ADR-001: Decoupled Express Detection & Policy Plane

- **Context**: Thesis 3 (`Thesis_for_early_detection__85239673.pdf`) emphasizes that detection and policy enforcement must be decoupled from the agent reasoning loop so a compromised or prompt-injected agent cannot suppress, tamper with, or bypass its own monitor.
- **Decision**: Implement all scoring (`server/engine/detector.ts`), trap orchestration (`server/engine/sandbox.ts`), attribution (`server/engine/attribution.ts`), and regression testing (`server/engine/harness.ts`) behind a dedicated Express server (`server.ts`) exposing typed REST endpoints under `/api/*`. The React frontend (`src/`) acts strictly as an operator console and never computes authoritative security verdicts client-side.
- **Consequences**:
  - Guarantees deterministic enforcement and canonical SHA-256 hashing on the server.
  - Allows future agent frameworks (LangGraph, AutoGen, MCP relays) to integrate directly with `/api/evaluate` and `/api/sandbox/run` as inline middleware.

---

## ADR-002: Host-Safe Deterministic Trap Simulator + Exportable Container Specs

- **Context**: Thesis 1 and Thesis 2 specify running untrusted agent-generated Python payloads inside hardened Docker/gVisor/Firecracker containers (`--network=none`, `--cap-drop=ALL`, `--read-only`, `--user=65534:65534`, custom seccomp). Executing arbitrary user-submitted Python code directly on an application preview host or invoking a privileged Docker socket would introduce host RCE risk and fail in containerless runtimes.
- **Decision**: `runTrappedSession` in `server/engine/sandbox.ts` implements a deterministic static/behavioral execution analyzer that models the exact sandbox environment:
  - Virtualizes `/workspace` decoy files (`README.txt`, `fake_config.env`, `canary_note.txt`).
  - Simulates `--network=none` DNS/socket failures and host IMDS (`169.254.169.254`) drops.
  - Detects and blocks seccomp-restricted primitives (`ptrace`, `mount`, `bpf`, `kexec_load`, `CLONE_NEWUSER`, `CLONE_NEWNS`, `AF_PACKET`).
  - Simultaneously generates the exact production `docker run` CLI array and custom `seccomp` JSON profile for deployment on container-enabled hosts.
- **Consequences**:
  - Zero risk of host code execution, SSRF, or sandbox escape during interactive testing.
  - Operators can copy or export real production container/seccomp artifacts directly from any session.

---

## ADR-003: Hybrid Deterministic & Behavioral Scoring Over Static Blocklists

- **Context**: Static phrase blocklists (e.g., matching only `"ignore previous instructions"`) are trivially bypassed via paraphrasing, HTML comment hiding, or chaining benign tools (`read_sensitive_doc -> list_external_webhooks -> http_post`).
- **Decision**: Implement a multi-signal pipeline in `evaluateActionBoundary` (`server/engine/detector.ts`) combining:
  1. `AgentRiskClassifier` (Thesis 2's 4 heuristic pattern classes).
  2. `InstructionInDataCollision` (imperative/encoding/hidden markup patterns weighted higher inside `untrusted_external`, `VECTOR_DB_DOC`, `EXTERNAL_WEB`, or `TOOL_RESULT` spans).
  3. `GoalDriftIntentDivergence` (benign read/summarize goal vs. high-blast-radius or egress tool proposal).
  4. `MemoryConfigMutationGuard` (`memory_write` or config/manifest paths from untrusted provenance).
  5. `SequenceGraphAnomaly` (dangerous tool-call n-grams + baseline deviation).
  6. `VolumetricAndEgressSpike` (`record_count >= 5x` baseline, non-allowlisted egress domains, IMDS/recon sweeps).
  7. `CanaryDeceptionTripwire` (instant `critical` escalation on honeytoken/decoy access).
- **Consequences**:
  - Sub-millisecond scoring latency (`latency_ms` tracked per evaluation) with transparent per-detector evidence trails.
  - Easily extensible to incorporate ML/embedding classifiers as an additional signal without changing the gating contract.

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

## ADR-006: In-Memory Append-Only Store for MVP (With Clear Persistence Path)

- **Context**: Rapidly validating the integrated workflow across all 3 theses without external database provisioning friction.
- **Decision**: Store `baselines`, `evaluations`, `quarantineQueue`, and `trapSessions` in server memory in `server.ts`, pre-seeded at boot via `seedInitialTelemetry()` using 4 representative thesis scenarios.
- **Consequences**:
  - Zero setup required; works immediately on port `3000`.
  - State resets on server restart; Phase 2 replaces in-memory arrays with Redis (rolling baselines) and PostgreSQL/OpenSearch (immutable audit sink).

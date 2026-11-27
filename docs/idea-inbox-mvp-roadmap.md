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
- Suspicious or high-blast-radius actions are held for **Human-in-the-Loop review** or routed into an **air-gapped (`--network=none`) Trap Sandbox** stocked with decoy credentials and canary files.
- Blocked outbound targets and payload indicators are extracted and correlated back with gateway provenance to produce calibrated **Origin Attribution Findings** with explicit confidence levels and operational caveats.

---

## 2. What Works Today (Verified MVP)

| Capability | Status | Implementation |
| :--- | :--- | :--- |
| **Telemetry & Instrumentation Layer** | Working | `makeAgentActionEvent` in `server/engine/detector.ts` computes canonical SHA-256 `payload_hash` digests with `provenance_tag`, `source_trust`, `trigger_source`, and `record_count`. |
| **Hybrid Early Detection Engine** | Working | `evaluateActionBoundary` combines `AgentRiskClassifier` (4 regex classes, `0.35` threshold), Instruction-in-Data Collision, Goal Drift / Intent Divergence, Memory & Config Mutation Guard, Sequence/Graph N-gram Anomalies, Volumetric & Egress Spikes, and Canary Tripwires. |
| **Deterministic Action-Boundary Gate** | Working | Outputs `ALLOW_LOG`, `STEP_UP_QUARANTINE`, or `HARD_BLOCK_REVOKE` with sub-millisecond scoring latency and automatic session credential revocation flags. |
| **Human-in-the-Loop Quarantine Queue** | Working | Operators can review held actions in `OverviewView` and trigger `Route to Trap`, `Approve Once`, or `Revoke Credentials` via `POST /api/quarantine/:id/resolve`. |
| **Zero-Egress Trap Sandbox Simulator** | Working | `runTrappedSession` in `server/engine/sandbox.ts` simulates isolated `python3 -I` execution without host `eval`/`exec`, mounts decoy workspace files (`README.txt`, `fake_config.env`, `canary_note.txt`), blocks network/IMDS (`169.254.169.254`) and seccomp-restricted syscalls, and emits `telemetry.jsonl`. |
| **Hardened Container & Seccomp Spec Generator** | Working | Generates exact `docker run` CLI flags (`--network none`, `--cap-drop ALL`, `--read-only`, `--user 65534:65534`, gVisor/Firecracker runtime flags) and custom seccomp JSON profile (`ptrace`, `mount`, `bpf`, `kexec_load`, `AF_PACKET`, `CLONE_NEWUSER`/`CLONE_NEWNS`). |
| **Origin Attribution & C2 Correlator** | Working | `extractIndicators` and `buildAttributionReport` in `server/engine/attribution.ts` filter `COMMON_NON_C2_DOMAINS`, detect private/loopback/link-local peers, assign `low` / `low-to-medium` / `medium` confidence, and attach operational caveats. |
| **Forensic Exports** | Working | Direct download endpoints for `telemetry.jsonl` (`/api/sessions/:id/telemetry.jsonl`) and `attribution_report.json` (`/api/sessions/:id/attribution.json`). |
| **Adversarial & Regression Harness** | Working | 6 built-in test fixtures in `server/engine/harness.ts` verified passing 6/6 (`fix-01` through `fix-06`) via `POST /api/harness/run`. |

---

## 3. Core Architectural Decisions (Summary)

1. **Decoupled Detection & Policy Plane**: All detection, baseline comparison, and gate enforcement live on the Express server (`server.ts` + `server/engine/*`), isolated from any agent reasoning loop so an agent cannot modify or bypass its own monitor.
2. **Host-Safe Deterministic Trap Simulation**: Untrusted agent Python snippets are never executed via `eval`, `Function`, or host shell `exec`. Instead, `server/engine/sandbox.ts` deterministically models the isolated `/workspace` filesystem, blocked egress exceptions, seccomp `EPERM`/`SIGSYS` rejections, and timeout limits while emitting production-ready Docker/seccomp specs.
3. **Deterministic + Behavioral Hybrid Scoring First**: Fast regex, structural, graph transition, and baseline-ratio checks execute in milliseconds without LLM-in-the-loop latency or self-reporting bias.
4. **Evidence-Bounded Origin Attribution**: Because `--network=none` prevents probing external hosts, attribution explicitly separates **upstream relay metadata** from **embedded C2 indicators** and caps confidence at `medium` until corroborated with mTLS or reverse-proxy logs.
5. **In-Memory Append-Only Store for MVP**: Sessions, evaluations, baselines, and quarantine items reside in server memory seeded with realistic thesis scenarios, keeping the MVP zero-dependency and immediately runnable on port `3000`.

*(See `./architecture-decisions.md` for detailed ADRs.)*

---

## 4. Idea Inbox & Phased Roadmap

### Phase 1 — Unified MVP Foundation (Complete)
- [x] Full-stack Express + Vite + React TypeScript application (`SentinelGate`)
- [x] 5 operational views (`Overview`, `Action Gate`, `Trap Sandbox`, `Origin Attribution`, `Regression Harness`) + session/baseline sidebar rail
- [x] Deterministic action gating, human quarantine resolution, decoy tripwires, JSONL/JSON exports, and 6/6 passing adversarial regression suite

### Phase 2 — Persistent Forensics & Live Container Isolation (Next)
- [ ] **Append-Only Persistent Storage**: Stream `AgentActionEvent` and `TelemetryEvent` JSONL records to PostgreSQL or OpenSearch/SIEM with write-once retention policies.
- [ ] **Redis Rolling Baseline Store**: Replace static `DEFAULT_AGENT_BASELINES` with sliding-window per-`agent_id` and per-role counters (tool transition Markov probabilities, p95 `record_count`, error-rate drift).
- [ ] **Optional Real MicroVM / gVisor Runner**: Add an opt-in backend driver in `server/engine/sandbox.ts` that spawns ephemeral `--runtime=runsc` or Firecracker microVMs when running on a Linux host with container runtime socket access and host-level `nftables` egress drop rules.
- [ ] **Signed Ingress Verification**: Validate upstream `origin_server` claims via mTLS client certificates or HMAC/JWT relay signatures instead of trusting forwarded headers.

### Phase 3 — Idea Inbox (Exploratory & Advanced Capabilities)
- [ ] **Semantic Embedding Goal-Drift Scorer**: Pair the deterministic keyword-category intent check with lightweight vector cosine similarity (e.g., via server-side embedding or Gemini API classification) comparing initial user goal embeddings against proposed tool-call semantics.
- [ ] **Adaptive Recon Graph Visualization**: Interactive state-transition DAG highlighting anomalous tool n-grams (`read_sensitive_doc -> list_external_webhooks -> http_post`) against normal agent baseline paths.
- [ ] **Controlled Sinkhole Mode (Separate Network Segment)**: Optional non-production honeypot/sinkhole profile with strict DNS/HTTP capture and legal/compliance guardrails for observing live C2 handshake behavior safely outside the zero-egress trap.
- [ ] **CI/CD Gate CLI**: Export `server/engine/harness.ts` as a standalone CLI runner so prompt, model, or tool-manifest pull requests must pass all adversarial regression fixtures before deployment.

---

## 5. Related Documentation

- [Architecture Decision Records](./architecture-decisions.md)
- [Detection, Sandbox & Attribution Specification](./detection-and-sandbox-spec.md)
- [REST API & Verification Guide](./api-and-verification.md)

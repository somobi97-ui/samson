import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import type {
  ActionGateEvaluation,
  ActionPhase,
  AgentBaseline,
  BlockedNetworkAttempt,
  IngressProvenance,
  ProvenanceTag,
  QuarantineQueueItem,
  SandboxPolicy,
  SourceTrust,
  TrapSessionRecord,
  TriggerSource,
} from './src/types/security.ts';
import { buildAttributionReport } from './server/engine/attribution.ts';
import { evaluateActionBoundary } from './server/engine/detector.ts';
import {
  ADVERSARIAL_HARNESS_SCENARIOS,
  DEFAULT_AGENT_BASELINES,
  runAdversarialHarness,
} from './server/engine/harness.ts';
import { DEFAULT_SANDBOX_POLICY, runTrappedSession } from './server/engine/sandbox.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VALID_PHASES = new Set<ActionPhase>(['input_ingest', 'plan', 'tool_call', 'memory_write', 'egress']);
const VALID_TRUST = new Set<SourceTrust>(['trusted', 'untrusted_external', 'mixed']);
const VALID_PROVENANCE = new Set<ProvenanceTag>([
  'SYSTEM_CONFIG',
  'AUTHENTICATED_USER',
  'EXTERNAL_WEB',
  'VECTOR_DB_DOC',
  'TOOL_RESULT',
]);
const VALID_TRIGGERS = new Set<TriggerSource>([
  'user_prompt',
  'retrieved_doc',
  'tool_output',
  'webhook',
]);

function asCleanString(val: unknown, fallback = '', maxLen = 10000): string {
  if (typeof val !== 'string') return fallback;
  return val.slice(0, maxLen);
}

function asCleanNumber(val: unknown, fallback: number, min = 0, max = 1000000): number {
  const num = Number(val);
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function parseIngress(raw: unknown): IngressProvenance {
  const obj = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const portRaw = obj.peer_port;
  const parsedPort =
    portRaw === null || portRaw === undefined || portRaw === ''
      ? null
      : asCleanNumber(portRaw, 443, 1, 65535);

  const extraHeaders: Record<string, string> = {};
  if (obj.extra_headers && typeof obj.extra_headers === 'object' && !Array.isArray(obj.extra_headers)) {
    for (const [k, v] of Object.entries(obj.extra_headers as Record<string, unknown>)) {
      if (typeof v === 'string') {
        extraHeaders[k.slice(0, 64)] = v.slice(0, 256);
      }
    }
  }

  return {
    peer_ip: asCleanString(obj.peer_ip, '198.51.100.42', 64).trim() || '198.51.100.42',
    peer_port: parsedPort,
    origin_server: obj.origin_server ? asCleanString(obj.origin_server, '', 255).trim() || null : null,
    auth_principal: obj.auth_principal ? asCleanString(obj.auth_principal, '', 255).trim() || null : null,
    user_agent: obj.user_agent ? asCleanString(obj.user_agent, '', 255).trim() || null : null,
    protocol: asCleanString(obj.protocol, 'https', 16).trim() || 'https',
    extra_headers: extraHeaders,
  };
}

// In-memory append-only forensic store seeded from the 3 thesis reference scenarios
const baselines: AgentBaseline[] = [...DEFAULT_AGENT_BASELINES];
const evaluations: ActionGateEvaluation[] = [];
const quarantineQueue: QuarantineQueueItem[] = [];
const trapSessions: TrapSessionRecord[] = [];

function seedInitialTelemetry() {
  const seedIndices = [1, 0, 2, 5]; // Canary Exfiltration, Indirect Injection, IMDS Recon, Benign Baseline
  for (const idx of seedIndices) {
    const scenario = ADVERSARIAL_HARNESS_SCENARIOS[idx];
    const baseline = baselines.find((b) => b.agent_id === scenario.agent_id) ?? baselines[0];
    const evaluation = evaluateActionBoundary({
      agent_id: scenario.agent_id,
      session_id: `sess-${scenario.id}`,
      trace_id: `trace-${scenario.id}`,
      user_goal: scenario.user_goal,
      phase: scenario.phase,
      source_trust: scenario.source_trust,
      provenance_tag: scenario.provenance_tag,
      trigger_source: scenario.trigger_source,
      tool_name: scenario.tool_name,
      target_resource: scenario.target_resource,
      record_count: scenario.record_count,
      prior_tools: scenario.prior_tools,
      raw_payload: scenario.raw_payload,
      baseline,
    });
    evaluations.unshift(evaluation);

    if (evaluation.decision !== 'ALLOW_LOG') {
      const trap = runTrappedSession({
        agent_id: scenario.agent_id,
        reason: `matched=${evaluation.classifier.matched_patterns.join(',') || evaluation.signals.map((s) => s.detector).join(',')}`,
        ingress: scenario.ingress,
        prompt: scenario.user_goal,
        agent_code: scenario.agent_code,
      });
      trapSessions.unshift(trap);

      quarantineQueue.unshift({
        id: `quar-${scenario.id}`,
        created_at: evaluation.event.timestamp,
        status: idx === 0 ? 'pending_review' : 'routed_to_trap',
        user_goal: scenario.user_goal,
        raw_payload: scenario.raw_payload,
        ingress: scenario.ingress,
        evaluation,
        linked_trap_session_id: idx === 0 ? undefined : trap.session_id,
      });
    }
  }
}

seedInitialTelemetry();

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '512kb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.get('/api/state', (_req, res) => {
    res.json({
      baselines,
      evaluations: evaluations.slice(0, 50),
      quarantineQueue: quarantineQueue.slice(0, 50),
      trapSessions: trapSessions.slice(0, 50),
      scenarios: ADVERSARIAL_HARNESS_SCENARIOS,
      defaultPolicy: DEFAULT_SANDBOX_POLICY,
    });
  });

  app.post('/api/evaluate', (req, res) => {
    const body = req.body && typeof req.body === 'object' ? (req.body as Record<string, unknown>) : {};
    const agent_id = asCleanString(body.agent_id, 'agent-triage-01', 128);
    const baseline = baselines.find((b) => b.agent_id === agent_id) ?? baselines[0];

    const phase = VALID_PHASES.has(body.phase as ActionPhase)
      ? (body.phase as ActionPhase)
      : 'tool_call';
    const source_trust = VALID_TRUST.has(body.source_trust as SourceTrust)
      ? (body.source_trust as SourceTrust)
      : 'untrusted_external';
    const provenance_tag = VALID_PROVENANCE.has(body.provenance_tag as ProvenanceTag)
      ? (body.provenance_tag as ProvenanceTag)
      : 'TOOL_RESULT';
    const trigger_source = VALID_TRIGGERS.has(body.trigger_source as TriggerSource)
      ? (body.trigger_source as TriggerSource)
      : 'tool_output';

    const prior_tools = Array.isArray(body.prior_tools)
      ? body.prior_tools.filter((t): t is string => typeof t === 'string').slice(0, 12)
      : [];

    const sessionId = asCleanString(body.session_id, `sess-${Date.now().toString(36)}`, 64);
    const traceId = asCleanString(body.trace_id, `trace-${Math.random().toString(36).slice(2, 10)}`, 64);
    const user_goal = asCleanString(body.user_goal, 'Summarize workspace document', 2000);
    const tool_name = asCleanString(body.tool_name, 'python_exec', 128);
    const target_resource = asCleanString(body.target_resource, '/workspace', 512);
    const record_count = asCleanNumber(body.record_count, 1, 0, 100000);
    const raw_payload = asCleanString(body.raw_payload, '', 16000);
    const ingress = parseIngress(body.ingress);

    const evaluation = evaluateActionBoundary({
      agent_id,
      session_id: sessionId,
      trace_id: traceId,
      user_goal,
      phase,
      source_trust,
      provenance_tag,
      trigger_source,
      tool_name,
      target_resource,
      record_count,
      prior_tools,
      raw_payload,
      baseline,
    });

    evaluations.unshift(evaluation);

    let queueItem: QuarantineQueueItem | null = null;
    if (evaluation.decision !== 'ALLOW_LOG') {
      queueItem = {
        id: `quar-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
        created_at: evaluation.event.timestamp,
        status: 'pending_review',
        user_goal,
        raw_payload,
        ingress,
        evaluation,
      };
      quarantineQueue.unshift(queueItem);
    }

    res.json({ evaluation, queueItem });
  });

  app.post('/api/quarantine/:id/resolve', (req, res) => {
    const id = asCleanString(req.params.id, '', 128);
    const item = quarantineQueue.find((q) => q.id === id);
    if (!item) {
      return res.status(404).json({ error: 'Quarantine item not found' });
    }

    const body = req.body && typeof req.body === 'object' ? (req.body as Record<string, unknown>) : {};
    const action = asCleanString(body.action, '', 32);
    const note = asCleanString(body.note, '', 500);

    if (action === 'approve_once') {
      item.status = 'approved_once';
      item.operator_note = note || 'Released after human operator verification';
      return res.json({ item });
    }

    if (action === 'revoke') {
      item.status = 'revoked';
      item.evaluation.credential_revoked = true;
      item.operator_note = note || 'Session credentials revoked and tool bindings isolated';
      return res.json({ item });
    }

    if (action === 'route_to_trap') {
      const code =
        asCleanString(body.agent_code, '', 16000) ||
        `# Routed from Action Gate (${item.evaluation.event.tool_name ?? 'unknown'})\nimport urllib.request\ntry:\n    urllib.request.urlopen("${item.evaluation.event.target_resource ?? 'https://example.com'}", timeout=2)\nexcept Exception as exc:\n    print("Blocked outbound attempt:", type(exc).__name__, exc)`;

      const trapSession = runTrappedSession({
        agent_id: item.evaluation.event.agent_id,
        reason: `action_gate_escalation:${item.evaluation.signals.map((s) => s.detector).join(',') || 'policy_hold'}`,
        ingress: item.ingress,
        prompt: `${item.user_goal}\n${item.raw_payload}`,
        agent_code: code,
      });
      trapSessions.unshift(trapSession);
      item.status = 'routed_to_trap';
      item.linked_trap_session_id = trapSession.session_id;
      item.operator_note = note || `Quarantined inside ${trapSession.session_id}`;
      return res.json({ item, trapSession });
    }

    return res.status(400).json({ error: 'Invalid resolution action' });
  });

  app.post('/api/sandbox/run', (req, res) => {
    const body = req.body && typeof req.body === 'object' ? (req.body as Record<string, unknown>) : {};
    const agent_id = asCleanString(body.agent_id, 'agent-devops-02', 128);
    const reason = asCleanString(body.reason, 'manual_trap_investigation', 256);
    const prompt = asCleanString(body.prompt, '', 4000);
    const agent_code = asCleanString(body.agent_code, '', 24000);
    const ingress = parseIngress(body.ingress);

    const rawPolicy = body.policy && typeof body.policy === 'object' ? (body.policy as Record<string, unknown>) : {};
    const runtimeVal = asCleanString(rawPolicy.runtime, 'gvisor-runsc', 32);
    const runtime: SandboxPolicy['runtime'] =
      runtimeVal === 'firecracker-microvm' || runtimeVal === 'docker-runc'
        ? runtimeVal
        : 'gvisor-runsc';

    const policy: Partial<SandboxPolicy> = {
      cpu_quota: asCleanString(rawPolicy.cpu_quota, DEFAULT_SANDBOX_POLICY.cpu_quota, 16),
      memory_limit: asCleanString(rawPolicy.memory_limit, DEFAULT_SANDBOX_POLICY.memory_limit, 16),
      pids_limit: asCleanNumber(rawPolicy.pids_limit, DEFAULT_SANDBOX_POLICY.pids_limit, 8, 1024),
      timeout_seconds: asCleanNumber(rawPolicy.timeout_seconds, DEFAULT_SANDBOX_POLICY.timeout_seconds, 1, 120),
      image: asCleanString(rawPolicy.image, DEFAULT_SANDBOX_POLICY.image, 128),
      enable_decoy_workspace:
        typeof rawPolicy.enable_decoy_workspace === 'boolean'
          ? rawPolicy.enable_decoy_workspace
          : true,
      runtime,
      seccomp_enabled:
        typeof rawPolicy.seccomp_enabled === 'boolean' ? rawPolicy.seccomp_enabled : true,
      strip_env_secrets:
        typeof rawPolicy.strip_env_secrets === 'boolean' ? rawPolicy.strip_env_secrets : true,
      host_firewall_drop_imds:
        typeof rawPolicy.host_firewall_drop_imds === 'boolean'
          ? rawPolicy.host_firewall_drop_imds
          : true,
    };

    const session = runTrappedSession({
      agent_id,
      reason,
      ingress,
      prompt,
      agent_code,
      policy,
    });

    trapSessions.unshift(session);
    res.json({ session });
  });

  app.post('/api/attribution/analyze', (req, res) => {
    const body = req.body && typeof req.body === 'object' ? (req.body as Record<string, unknown>) : {};
    const session_id = asCleanString(body.session_id, `attr-${Date.now().toString(36)}`, 64);
    const ingress = parseIngress(body.ingress);
    const observed_texts = Array.isArray(body.observed_texts)
      ? body.observed_texts.filter((t): t is string => typeof t === 'string').slice(0, 20)
      : [asCleanString(body.text, '', 16000)];

    const blocked_network_attempts: BlockedNetworkAttempt[] = Array.isArray(
      body.blocked_network_attempts,
    )
      ? body.blocked_network_attempts
          .filter((a): a is Record<string, unknown> => Boolean(a && typeof a === 'object'))
          .slice(0, 20)
          .map((a) => ({
            type: asCleanString(a.type, 'blocked_url_reference', 64),
            target_url: a.target_url ? asCleanString(a.target_url, '', 512) : undefined,
            target_host: a.target_host ? asCleanString(a.target_host, '', 255) : undefined,
            reason: asCleanString(a.reason, 'Blocked by --network=none', 256),
          }))
      : [];

    const finding = buildAttributionReport({
      session_id,
      ingress,
      observed_texts,
      blocked_network_attempts,
    });

    res.json({ finding });
  });

  app.post('/api/harness/run', (_req, res) => {
    const results = runAdversarialHarness(baselines);
    res.json({ results });
  });

  app.get('/api/sessions/:id/telemetry.jsonl', (req, res) => {
    const session = trapSessions.find((s) => s.session_id === req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const lines = session.telemetry.map((evt) => JSON.stringify(evt)).join('\n') + '\n';
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${session.session_id}_telemetry.jsonl"`,
    );
    res.send(lines);
  });

  app.get('/api/sessions/:id/attribution.json', (req, res) => {
    const session = trapSessions.find((s) => s.session_id === req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${session.session_id}_attribution_report.json"`,
    );
    res.send(JSON.stringify(session.attribution, null, 2));
  });

  const isProd = process.env.NODE_ENV === 'production';
  const distPath = path.resolve(__dirname, 'dist');

  if (!isProd || !fs.existsSync(distPath)) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelGate security platform listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();

import crypto from 'crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import type {
  ActionGateEvaluation,
  AgentBaseline,
  QuarantineQueueItem,
  SemanticAuditResult,
  TrapSessionRecord,
} from '../src/types/security.ts';
import { getPublicRuntimeConfig, serverConfig } from './config/env.ts';
import { buildAttributionReport } from './engine/attribution.ts';
import { evaluateActionBoundary } from './engine/detector.ts';
import {
  ADVERSARIAL_HARNESS_SCENARIOS,
  DEFAULT_AGENT_BASELINES,
  runAdversarialHarness,
} from './engine/harness.ts';
import { DEFAULT_SANDBOX_POLICY, runTrappedSession } from './engine/sandbox.ts';
import { createRateLimiter } from './middleware/rateLimit.ts';
import {
  runSemanticIntentAudit,
  type SemanticIntentAuditInput,
} from './services/aiModelService.ts';
import { hashIdentifier, logger } from './services/logger.ts';
import {
  SAFE_ID_REGEX,
  validateAttributionPayload,
  validateEvaluatePayload,
  validateQuarantineResolvePayload,
  validateSandboxPayload,
  validateSemanticAuditPayload,
} from './validation/payloadSchemas.ts';

export interface RequestWithId extends Request {
  requestId?: string;
}

export interface CreateApiAppOptions {
  aiAuditFn?: (input: SemanticIntentAuditInput) => Promise<SemanticAuditResult>;
}

function pushBounded<T>(arr: T[], item: T): void {
  arr.unshift(item);
  if (arr.length > serverConfig.limits.maxStoredRecords) {
    arr.length = serverConfig.limits.maxStoredRecords;
  }
}

export function createApiApp(options?: CreateApiAppOptions) {
  const app = express();
  app.set('trust proxy', 1);

  const runAudit = options?.aiAuditFn ?? runSemanticIntentAudit;

  const baselines: AgentBaseline[] = [...DEFAULT_AGENT_BASELINES];
  const evaluations: ActionGateEvaluation[] = [];
  const quarantineQueue: QuarantineQueueItem[] = [];
  const trapSessions: TrapSessionRecord[] = [];

  function seedInitialTelemetry() {
    const seedIndices = [1, 0, 2, 5];
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
      pushBounded(evaluations, evaluation);

      if (evaluation.decision !== 'ALLOW_LOG') {
        const trap = runTrappedSession({
          agent_id: scenario.agent_id,
          reason: `matched=${evaluation.classifier.matched_patterns.join(',') || evaluation.signals.map((s) => s.detector).join(',')}`,
          ingress: scenario.ingress,
          prompt: scenario.user_goal,
          agent_code: scenario.agent_code,
        });
        pushBounded(trapSessions, trap);

        pushBounded(quarantineQueue, {
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

  // Attach correlation ID and structured HTTP request logging for /api routes
  app.use('/api', (req: RequestWithId, res: Response, next: NextFunction) => {
    const incomingId = req.header('x-request-id');
    const requestId =
      incomingId && SAFE_ID_REGEX.test(incomingId)
        ? incomingId
        : `req-${crypto.randomUUID().slice(0, 12)}`;
    req.requestId = requestId;
    res.setHeader('X-Request-Id', requestId);

    const startedAt = performance.now();
    const clientIp = (req.ip || req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
    const clientIpHash = hashIdentifier(clientIp);

    res.on('finish', () => {
      const durationMs = Number((performance.now() - startedAt).toFixed(2));
      const meta = {
        requestId,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs,
        clientIpHash,
      };
      if (res.statusCode >= 500) {
        logger.error('http.request.error', meta);
      } else if (res.statusCode >= 400 && req.path !== '/health') {
        logger.warn('http.request.rejected', meta);
      } else if (req.path !== '/health') {
        logger.info('http.request', meta);
      }
    });

    next();
  });

  // Route-scoped JSON body parsers enforcing strict payload size caps
  const defaultJsonParser = express.json({ limit: serverConfig.limits.maxDefaultBodySize });
  const aiJsonParser = express.json({ limit: serverConfig.limits.maxAiBodySize });
  const sandboxJsonParser = express.json({ limit: serverConfig.limits.maxSandboxBodySize });

  // Tiered per-IP rate limiters
  const generalLimiter = createRateLimiter({
    name: 'api_read',
    windowMs: serverConfig.limits.rateWindowMs,
    maxRequests: serverConfig.limits.generalMax,
  });
  const mutationLimiter = createRateLimiter({
    name: 'api_mutation',
    windowMs: serverConfig.limits.rateWindowMs,
    maxRequests: serverConfig.limits.mutationMax,
  });
  const aiLimiter = createRateLimiter({
    name: 'semantic_audit_ai',
    windowMs: serverConfig.limits.rateWindowMs,
    maxRequests: serverConfig.limits.aiMax,
  });

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.get('/api/config', generalLimiter, (_req, res) => {
    res.json(getPublicRuntimeConfig());
  });

  app.get('/api/state', generalLimiter, (_req, res) => {
    res.json({
      baselines,
      evaluations: evaluations.slice(0, 50),
      quarantineQueue: quarantineQueue.slice(0, 50),
      trapSessions: trapSessions.slice(0, 50),
      scenarios: ADVERSARIAL_HARNESS_SCENARIOS,
      defaultPolicy: DEFAULT_SANDBOX_POLICY,
      runtimeConfig: getPublicRuntimeConfig(),
    });
  });

  app.post('/api/evaluate', mutationLimiter, defaultJsonParser, (req: RequestWithId, res) => {
    const validated = validateEvaluatePayload(req.body);
    if (!validated.ok) {
      return res.status(400).json({ error: validated.error });
    }

    const input = validated.data;
    const baseline = baselines.find((b) => b.agent_id === input.agent_id) ?? baselines[0];

    const evaluation = evaluateActionBoundary({
      agent_id: input.agent_id,
      session_id: input.session_id,
      trace_id: input.trace_id,
      user_goal: input.user_goal,
      phase: input.phase,
      source_trust: input.source_trust,
      provenance_tag: input.provenance_tag,
      trigger_source: input.trigger_source,
      tool_name: input.tool_name,
      target_resource: input.target_resource,
      record_count: input.record_count,
      prior_tools: input.prior_tools,
      raw_payload: input.raw_payload,
      baseline,
    });

    pushBounded(evaluations, evaluation);

    let queueItem: QuarantineQueueItem | null = null;
    if (evaluation.decision !== 'ALLOW_LOG') {
      queueItem = {
        id: `quar-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
        created_at: evaluation.event.timestamp,
        status: 'pending_review',
        user_goal: input.user_goal,
        raw_payload: input.raw_payload,
        ingress: input.ingress,
        evaluation,
      };
      pushBounded(quarantineQueue, queueItem);
    }

    logger.info('action_gate.evaluated', {
      requestId: req.requestId,
      agent_id: evaluation.event.agent_id,
      session_id: evaluation.event.session_id,
      trace_id: evaluation.event.trace_id,
      payload_hash: evaluation.event.payload_hash,
      decision: evaluation.decision,
      combined_risk: evaluation.combined_risk,
    });

    return res.json({ evaluation, queueItem });
  });

  app.post(
    '/api/quarantine/:id/resolve',
    mutationLimiter,
    defaultJsonParser,
    (req: RequestWithId, res) => {
      const id = typeof req.params.id === 'string' ? req.params.id.slice(0, 64) : '';
      if (!SAFE_ID_REGEX.test(id)) {
        return res.status(400).json({ error: 'Invalid quarantine item ID format.' });
      }
      const item = quarantineQueue.find((q) => q.id === id);
      if (!item) {
        return res.status(404).json({ error: 'Quarantine item not found' });
      }

      const validated = validateQuarantineResolvePayload(req.body);
      if (!validated.ok) {
        return res.status(400).json({ error: validated.error });
      }
      const { action, note, agent_code } = validated.data;

      if (action === 'approve_once') {
        item.status = 'approved_once';
        item.operator_note = note || 'Released after human operator verification';
        logger.info('quarantine.resolved', { requestId: req.requestId, id, action });
        return res.json({ item });
      }

      if (action === 'revoke') {
        item.status = 'revoked';
        item.evaluation.credential_revoked = true;
        item.operator_note = note || 'Session credentials revoked and tool bindings isolated';
        logger.info('quarantine.resolved', { requestId: req.requestId, id, action });
        return res.json({ item });
      }

      const code =
        agent_code ||
        `# Routed from Action Gate (${item.evaluation.event.tool_name ?? 'unknown'})\nimport urllib.request\ntry:\n    urllib.request.urlopen("${item.evaluation.event.target_resource ?? 'https://example.com'}", timeout=2)\nexcept Exception as exc:\n    print("Blocked outbound attempt:", type(exc).__name__, exc)`;

      const trapSession = runTrappedSession({
        agent_id: item.evaluation.event.agent_id,
        reason: `action_gate_escalation:${item.evaluation.signals.map((s) => s.detector).join(',') || 'policy_hold'}`,
        ingress: item.ingress,
        prompt: `${item.user_goal}\n${item.raw_payload}`,
        agent_code: code,
      });
      pushBounded(trapSessions, trapSession);
      item.status = 'routed_to_trap';
      item.linked_trap_session_id = trapSession.session_id;
      item.operator_note = note || `Quarantined inside ${trapSession.session_id}`;

      logger.info('quarantine.resolved', {
        requestId: req.requestId,
        id,
        action,
        session_id: trapSession.session_id,
      });

      return res.json({ item, trapSession });
    },
  );

  app.post('/api/sandbox/run', mutationLimiter, sandboxJsonParser, (req: RequestWithId, res) => {
    const validated = validateSandboxPayload(req.body, DEFAULT_SANDBOX_POLICY);
    if (!validated.ok) {
      return res.status(400).json({ error: validated.error });
    }

    const session = runTrappedSession(validated.data);
    pushBounded(trapSessions, session);

    logger.info('sandbox.executed', {
      requestId: req.requestId,
      session_id: session.session_id,
      agent_id: session.agent_id,
      runtime: session.policy.runtime,
      canary_hits_count: session.execution.canary_hits.length,
      blocked_attempts_count: session.execution.blocked_attempts.length,
    });

    return res.json({ session });
  });

  app.post(
    '/api/attribution/analyze',
    mutationLimiter,
    defaultJsonParser,
    (req: RequestWithId, res) => {
      const validated = validateAttributionPayload(req.body);
      if (!validated.ok) {
        return res.status(400).json({ error: validated.error });
      }

      const finding = buildAttributionReport(validated.data);

      logger.info('attribution.analyzed', {
        requestId: req.requestId,
        session_id: finding.session_id,
        confidence: finding.confidence,
        extracted_urls_count: finding.extracted_urls.length,
        extracted_domains_count: finding.extracted_domains.length,
      });

      return res.json({ finding });
    },
  );

  app.post('/api/harness/run', mutationLimiter, (req: RequestWithId, res) => {
    const results = runAdversarialHarness(baselines);
    const passed = results.filter((r) => r.passed).length;

    logger.info('harness.executed', {
      requestId: req.requestId,
      total: results.length,
      passed,
    });

    res.json({ results });
  });

  app.post('/api/semantic-audit', aiLimiter, aiJsonParser, async (req: RequestWithId, res) => {
    const validated = validateSemanticAuditPayload(req.body, serverConfig.ai.maxInputChars);
    if (!validated.ok) {
      return res.status(400).json({ error: validated.error });
    }

    try {
      const clientIp = (req.ip || req.socket.remoteAddress || 'unknown').replace(/^::ffff:/, '');
      const audit = await runAudit({
        ...validated.data,
        actor_key: `ip:${clientIp}`,
        request_id: req.requestId,
      });
      return res.json({ audit });
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 502;
      const message =
        err instanceof Error && status < 500
          ? err.message
          : err instanceof Error && err.name === 'SafeUpstreamError'
            ? err.message
            : 'Semantic audit service is temporarily unavailable. Deterministic policy evaluation remains active.';
      return res.status(status).json({ error: message });
    }
  });

  app.get('/api/sessions/:id/telemetry.jsonl', generalLimiter, (req, res) => {
    const id = typeof req.params.id === 'string' ? req.params.id.slice(0, 64) : '';
    if (!SAFE_ID_REGEX.test(id)) {
      return res.status(400).json({ error: 'Invalid session ID format' });
    }
    const session = trapSessions.find((s) => s.session_id === id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    const lines = session.telemetry.map((evt) => JSON.stringify(evt)).join('\n') + '\n';
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${session.session_id}_telemetry.jsonl"`,
    );
    return res.send(lines);
  });

  app.get('/api/sessions/:id/attribution.json', generalLimiter, (req, res) => {
    const id = typeof req.params.id === 'string' ? req.params.id.slice(0, 64) : '';
    if (!SAFE_ID_REGEX.test(id)) {
      return res.status(400).json({ error: 'Invalid session ID format' });
    }
    const session = trapSessions.find((s) => s.session_id === id);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${session.session_id}_attribution_report.json"`,
    );
    return res.send(JSON.stringify(session.attribution, null, 2));
  });

  // Return JSON 404 for unknown /api routes so SPA fallback never serves HTML to API clients
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  // Consistent error handler for oversized JSON payloads (413), malformed JSON (400), or unexpected errors
  app.use((err: unknown, req: RequestWithId, res: Response, _next: NextFunction) => {
    const errObj = err as { type?: string; status?: number };
    if (errObj?.type === 'entity.too.large' || errObj?.status === 413) {
      logger.warn('http.payload.too_large', { requestId: req.requestId, path: req.path });
      res.status(413).json({ error: 'Request payload exceeds maximum allowed size limit.' });
      return;
    }
    if (errObj?.type === 'entity.parse.failed' || errObj?.status === 400) {
      logger.warn('http.payload.malformed_json', { requestId: req.requestId, path: req.path });
      res.status(400).json({ error: 'Malformed JSON request body.' });
      return;
    }
    logger.error('http.unhandled_error', { requestId: req.requestId, path: req.path }, err);
    res.status(500).json({ error: 'Internal server error.' });
  });

  return app;
}

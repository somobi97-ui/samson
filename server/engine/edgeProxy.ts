import net from 'net';
import type {
  ActionGateEvaluation,
  AgentBaseline,
  EdgeInspectionRecord,
  IngressProvenance,
  QuarantineQueueItem,
  TrapSessionRecord,
} from '../../src/types/security.ts';
import { serverConfig } from '../config/env.ts';
import { hashIdentifier } from '../services/logger.ts';
import { buildAttributionReport } from './attribution.ts';
import { evaluateActionBoundary } from './detector.ts';
import { runTrappedSession } from './sandbox.ts';

function isDisallowedIpAddress(ip: string): boolean {
  const cleaned = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!net.isIP(cleaned)) return false;

  if (net.isIPv4(cleaned)) {
    const parts = cleaned.split('.').map(Number);
    if (parts[0] === 0 || parts[0] === 10 || parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    return false;
  }

  return (
    cleaned === '::1' ||
    cleaned === '::' ||
    cleaned.startsWith('fe80:') ||
    cleaned.startsWith('fc') ||
    cleaned.startsWith('fd') ||
    cleaned.startsWith('::ffff:127.') ||
    cleaned.startsWith('::ffff:10.') ||
    cleaned.startsWith('::ffff:169.254.') ||
    cleaned.startsWith('::ffff:192.168.')
  );
}

export function validateUpstreamUrl(
  rawUrl: string | undefined,
  allowlist: string[] = serverConfig.edge.allowedUpstreams,
): { ok: true; url: URL } | { ok: false; host: string | null; reason: string } {
  if (!rawUrl || !rawUrl.trim()) {
    return { ok: false, host: null, reason: 'No upstream URL specified.' };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { ok: false, host: null, reason: 'Malformed upstream URL.' };
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return {
      ok: false,
      host: parsed.hostname.toLowerCase(),
      reason: `Disallowed upstream protocol "${parsed.protocol}".`,
    };
  }

  const host = parsed.hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    isDisallowedIpAddress(host)
  ) {
    return {
      ok: false,
      host,
      reason: `Blocked private, loopback, or metadata host "${host}".`,
    };
  }

  const allowed = allowlist.some(
    (entry) => host === entry || host.endsWith(`.${entry}`),
  );
  if (!allowed) {
    return {
      ok: false,
      host,
      reason: `Host "${host}" is not in EDGE_ALLOWED_UPSTREAMS.`,
    };
  }

  return { ok: true, url: parsed };
}

export function extractEdgeIngress(
  headers: Record<string, string | string[] | undefined>,
  fallbackPeerIp: string,
): IngressProvenance {
  const headerStr = (name: string): string | null => {
    const val = headers[name.toLowerCase()];
    if (Array.isArray(val)) return val[0]?.slice(0, 255) ?? null;
    return typeof val === 'string' && val.trim() ? val.trim().slice(0, 255) : null;
  };

  const rawFwd = headerStr('x-forwarded-for');
  const peerIp = (rawFwd ? rawFwd.split(',')[0].trim() : fallbackPeerIp).replace(/^::ffff:/, '');
  const authHeader = headerStr('authorization');
  const authPrincipal = authHeader
    ? `bearer-sha256:${hashIdentifier(authHeader)}`
    : headerStr('x-auth-principal');

  return {
    peer_ip: peerIp || '198.51.100.42',
    peer_port: 443,
    origin_server: headerStr('x-origin-server') ?? headerStr('host'),
    auth_principal: authPrincipal,
    user_agent: headerStr('user-agent'),
    protocol: headerStr('x-forwarded-proto') ?? 'https',
    extra_headers: {},
  };
}

export async function inspectAndRouteEdgeRequest(params: {
  method: string;
  path: string;
  agent_id: string;
  user_goal: string;
  tool_name: string;
  upstream_url?: string;
  raw_payload: string;
  ingress: IngressProvenance;
  forward: boolean;
  baseline: AgentBaseline;
  recordEvaluation: (ev: ActionGateEvaluation) => void;
  recordQuarantine: (item: QuarantineQueueItem) => void;
  recordTrapSession: (session: TrapSessionRecord) => void;
}): Promise<{ statusCode: number; record: EdgeInspectionRecord }> {
  const upstreamCheck = validateUpstreamUrl(params.upstream_url);
  const targetResource = params.upstream_url?.trim() || params.path;
  const sessionId = `edge-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

  const evaluation = evaluateActionBoundary({
    agent_id: params.agent_id,
    session_id: sessionId,
    trace_id: `trace-${sessionId}`,
    user_goal: params.user_goal,
    phase: params.upstream_url ? 'egress' : 'tool_call',
    source_trust: 'untrusted_external',
    provenance_tag: 'EXTERNAL_WEB',
    trigger_source: 'webhook',
    tool_name: params.tool_name,
    target_resource: targetResource,
    record_count: 1,
    prior_tools: [],
    raw_payload: params.raw_payload,
    baseline: params.baseline,
  });

  params.recordEvaluation(evaluation);

  const inspectionId = `insp-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const timestamp = new Date().toISOString();

  if (evaluation.decision === 'HARD_BLOCK_REVOKE') {
    const attribution = buildAttributionReport({
      session_id: sessionId,
      ingress: params.ingress,
      observed_texts: [params.user_goal, targetResource, params.raw_payload],
      blocked_network_attempts: [
        {
          type: 'edge_transit_block',
          target_url: params.upstream_url,
          reason: 'Dropped in transit by inline edge gate (HARD_BLOCK_REVOKE).',
        },
      ],
    });

    params.recordQuarantine({
      id: `quar-${inspectionId}`,
      created_at: timestamp,
      status: 'revoked',
      user_goal: params.user_goal,
      raw_payload: params.raw_payload,
      ingress: params.ingress,
      evaluation,
      operator_note: 'Blocked in transit at inline edge gateway.',
    });

    return {
      statusCode: 403,
      record: {
        inspection_id: inspectionId,
        timestamp,
        method: params.method,
        path: params.path,
        upstream_host: upstreamCheck.ok ? upstreamCheck.url.hostname : upstreamCheck.host,
        upstream_allowed: upstreamCheck.ok,
        forwarded: false,
        upstream_status: null,
        edge_action: 'BLOCKED_IN_TRANSIT',
        evaluation,
        attribution,
      },
    };
  }

  if (evaluation.decision === 'STEP_UP_QUARANTINE' || (params.upstream_url && !upstreamCheck.ok)) {
    const trapSession = runTrappedSession({
      agent_id: params.agent_id,
      reason: `edge_transit_reroute:${evaluation.signals.map((s) => s.detector).join(',') || 'unallowlisted_upstream'}`,
      ingress: params.ingress,
      prompt: `${params.user_goal}\n${params.raw_payload}`,
      agent_code: `import urllib.request\ntry:\n    urllib.request.urlopen("${targetResource.replace(/"/g, '')}", timeout=2)\nexcept Exception as exc:\n    print("Edge trap blocked:", type(exc).__name__, exc)`,
    });
    params.recordTrapSession(trapSession);
    params.recordQuarantine({
      id: `quar-${inspectionId}`,
      created_at: timestamp,
      status: 'routed_to_trap',
      user_goal: params.user_goal,
      raw_payload: params.raw_payload,
      ingress: params.ingress,
      evaluation,
      linked_trap_session_id: trapSession.session_id,
      operator_note: 'Rerouted in transit to zero-egress trap sandbox.',
    });

    return {
      statusCode: 202,
      record: {
        inspection_id: inspectionId,
        timestamp,
        method: params.method,
        path: params.path,
        upstream_host: upstreamCheck.ok ? upstreamCheck.url.hostname : upstreamCheck.host,
        upstream_allowed: upstreamCheck.ok,
        forwarded: false,
        upstream_status: null,
        edge_action: 'REROUTED_TO_TRAP',
        evaluation,
        linked_trap_session_id: trapSession.session_id,
        attribution: trapSession.attribution,
      },
    };
  }

  let forwarded = false;
  let upstreamStatus: number | null = null;
  if (params.forward && upstreamCheck.ok) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), serverConfig.edge.forwardTimeoutMs);
    try {
      const upstreamRes = await fetch(upstreamCheck.url.toString(), {
        method: params.method === 'GET' ? 'GET' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: params.method === 'GET' ? undefined : params.raw_payload,
        signal: controller.signal,
      });
      forwarded = true;
      upstreamStatus = upstreamRes.status;
    } catch {
      forwarded = false;
      upstreamStatus = 502;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    statusCode: 200,
    record: {
      inspection_id: inspectionId,
      timestamp,
      method: params.method,
      path: params.path,
      upstream_host: upstreamCheck.ok ? upstreamCheck.url.hostname : upstreamCheck.host,
      upstream_allowed: upstreamCheck.ok,
      forwarded,
      upstream_status: upstreamStatus,
      edge_action: 'FORWARD_UPSTREAM',
      evaluation,
    },
  };
}

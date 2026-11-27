import crypto from 'crypto';
import type {
  AgentBaseline,
  EndpointActivityEvent,
  EndpointAgentRecord,
  EndpointContainmentMode,
} from '../../src/types/security.ts';
import { evaluateActionBoundary } from './detector.ts';

export function buildSeededEndpoints(): {
  endpoints: EndpointAgentRecord[];
  events: EndpointActivityEvent[];
} {
  const now = Date.now();
  const endpoints: EndpointAgentRecord[] = [
    {
      endpoint_id: 'ep-macbook-sec-01',
      hostname: 'eng-workstation-01.local',
      platform: 'darwin',
      pid: 41820,
      version: '1.0.0',
      mode: 'enforce_contain',
      watch_paths: ['/Users/operator/workspace', '/tmp/agent-scratch'],
      status: 'online',
      last_heartbeat: new Date(now - 12_000).toISOString(),
      local_alerts_count: 1,
      contained_actions_count: 1,
    },
    {
      endpoint_id: 'ep-linux-runner-02',
      hostname: 'build-node-eu-02.internal',
      platform: 'linux',
      pid: 9314,
      version: '1.0.0',
      mode: 'monitor',
      watch_paths: ['/srv/mcp-runner/workspace', '/etc/sentinelgate'],
      status: 'online',
      last_heartbeat: new Date(now - 24_000).toISOString(),
      local_alerts_count: 0,
      contained_actions_count: 0,
    },
  ];

  const events: EndpointActivityEvent[] = [
    {
      event_id: 'ep-evt-seed-01',
      endpoint_id: 'ep-macbook-sec-01',
      hostname: 'eng-workstation-01.local',
      timestamp: new Date(now - 45_000).toISOString(),
      kind: 'file_access',
      subject: '/Users/operator/workspace/fake_config.env',
      detail: 'Local child python process attempted to read canary secret manifest and invoke curl.',
      decision: 'HARD_BLOCK_REVOKE',
      combined_risk: 0.92,
      containment_action: 'quarantined_file',
      payload_hash: crypto
        .createHash('sha256')
        .update('ep-evt-seed-01-canary')
        .digest('hex'),
    },
  ];

  return { endpoints, events };
}

export function evaluateEndpointActivity(params: {
  endpoint: EndpointAgentRecord;
  kind: EndpointActivityEvent['kind'];
  subject: string;
  detail: string;
  baseline: AgentBaseline;
}): {
  event: EndpointActivityEvent;
  local_directive: 'allow' | 'quarantine_file' | 'block_process' | 'revoke_local_token';
} {
  const isFileKind = params.kind === 'file_access' || params.kind === 'canary_touch';
  const sensitivePath =
    /(\.env|\.ssh\/id_|id_rsa|\/etc\/shadow|\/etc\/passwd|fake_config\.env|canary_note\.txt|credentials\.json|\.claude|\.cursor)/i.test(
      params.subject,
    );

  const evaluation = evaluateActionBoundary({
    agent_id: params.baseline.agent_id,
    session_id: `ep-${params.endpoint.endpoint_id}`,
    trace_id: `ept-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    user_goal: 'Authorized local endpoint activity within configured workspace',
    phase:
      params.kind === 'network_probe'
        ? 'egress'
        : isFileKind
          ? 'tool_call'
          : 'tool_call',
    source_trust: sensitivePath ? 'untrusted_external' : 'mixed',
    provenance_tag: 'TOOL_RESULT',
    trigger_source: 'tool_output',
    tool_name:
      params.kind === 'network_probe'
        ? 'http_post'
        : params.kind === 'process_spawn'
          ? 'shell_exec'
          : sensitivePath
            ? 'read_sensitive_doc'
            : 'read_file',
    target_resource: params.subject,
    record_count: sensitivePath ? 25 : 1,
    prior_tools: sensitivePath ? ['read_sensitive_doc'] : [],
    raw_payload: `${params.subject}\n${params.detail}`,
    baseline: params.baseline,
  });

  let containment_action: EndpointActivityEvent['containment_action'] = 'logged';
  let local_directive: 'allow' | 'quarantine_file' | 'block_process' | 'revoke_local_token' =
    'allow';

  if (
    params.endpoint.mode === 'enforce_contain' &&
    evaluation.decision !== 'ALLOW_LOG'
  ) {
    if (params.kind === 'canary_touch' || evaluation.decision === 'HARD_BLOCK_REVOKE') {
      containment_action = isFileKind ? 'quarantined_file' : 'revoked_local_token';
      local_directive = isFileKind ? 'quarantine_file' : 'revoke_local_token';
    } else {
      containment_action = isFileKind ? 'quarantined_file' : 'blocked_process';
      local_directive = isFileKind ? 'quarantine_file' : 'block_process';
    }
  }

  const event: EndpointActivityEvent = {
    event_id: `ep-evt-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    endpoint_id: params.endpoint.endpoint_id,
    hostname: params.endpoint.hostname,
    timestamp: new Date().toISOString(),
    kind: params.kind,
    subject: params.subject,
    detail: params.detail,
    decision: evaluation.decision,
    combined_risk: evaluation.combined_risk,
    containment_action,
    payload_hash: evaluation.event.payload_hash,
  };

  return { event, local_directive };
}

export function normalizeEndpointMode(mode: unknown): EndpointContainmentMode {
  return mode === 'enforce_contain' ? 'enforce_contain' : 'monitor';
}

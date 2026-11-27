import type {
  ActionPhase,
  BlockedNetworkAttempt,
  IngressProvenance,
  ProvenanceTag,
  SandboxPolicy,
  SandboxRuntime,
  SemanticAuditResult,
  SourceTrust,
  TriggerSource,
} from '../../src/types/security.ts';

export type ValidationResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

const VALID_PHASES = new Set<ActionPhase>([
  'input_ingest',
  'plan',
  'tool_call',
  'memory_write',
  'egress',
]);
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
const VALID_RUNTIMES = new Set<SandboxRuntime>([
  'gvisor-runsc',
  'firecracker-microvm',
  'docker-runc',
]);
const VALID_CLASSIFICATIONS = new Set<SemanticAuditResult['classification']>([
  'ALIGNED',
  'SUSPICIOUS_DRIFT',
  'HIJACKED_INTENT',
]);

export const SAFE_ID_REGEX = /^[a-zA-Z0-9_-]{4,64}$/;
const SAFE_AGENT_ID_REGEX = /^[a-zA-Z0-9._-]{2,64}$/;
const SAFE_TOOL_REGEX = /^[a-zA-Z0-9._:-]{1,64}$/;
const SAFE_PROTOCOL_REGEX = /^[a-zA-Z0-9+.-]{2,16}$/;
const SAFE_IP_OR_HOST_REGEX = /^[a-zA-Z0-9.:_-]{2,64}$/;
const SAFE_CPU_QUOTA_REGEX = /^\d+(\.\d{1,2})?$/;
const SAFE_MEMORY_LIMIT_REGEX = /^\d+[kmg]$/i;
const SAFE_IMAGE_REGEX = /^[a-zA-Z0-9._/-]+(:[a-zA-Z0-9._-]+)?$/;

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return Boolean(val) && typeof val === 'object' && !Array.isArray(val);
}

function stripControlChars(input: string): string {
  return input.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

function readRequiredString(
  obj: Record<string, unknown>,
  field: string,
  minLen: number,
  maxLen: number,
): ValidationResult<string> {
  const raw = obj[field];
  if (typeof raw !== 'string') {
    return { ok: false, error: `Field "${field}" must be a string.` };
  }
  const cleaned = stripControlChars(raw).trim();
  if (cleaned.length < minLen || cleaned.length > maxLen) {
    return {
      ok: false,
      error: `Field "${field}" must be between ${minLen} and ${maxLen} characters.`,
    };
  }
  return { ok: true, data: cleaned };
}

function readOptionalString(
  obj: Record<string, unknown>,
  field: string,
  fallback: string,
  maxLen: number,
): ValidationResult<string> {
  const raw = obj[field];
  if (raw === undefined || raw === null) {
    return { ok: true, data: fallback };
  }
  if (typeof raw !== 'string') {
    return { ok: false, error: `Field "${field}" must be a string when provided.` };
  }
  const cleaned = stripControlChars(raw).slice(0, maxLen);
  return { ok: true, data: cleaned };
}

function readBoundedInt(
  raw: unknown,
  field: string,
  fallback: number,
  min: number,
  max: number,
): ValidationResult<number> {
  if (raw === undefined || raw === null || raw === '') {
    return { ok: true, data: fallback };
  }
  const num = Number(raw);
  if (!Number.isFinite(num) || !Number.isInteger(num) || num < min || num > max) {
    return {
      ok: false,
      error: `Field "${field}" must be an integer between ${min} and ${max}.`,
    };
  }
  return { ok: true, data: num };
}

export function validateIngressPayload(raw: unknown): ValidationResult<IngressProvenance> {
  if (raw === undefined || raw === null) {
    return {
      ok: true,
      data: {
        peer_ip: '198.51.100.42',
        peer_port: 443,
        origin_server: null,
        auth_principal: null,
        user_agent: null,
        protocol: 'https',
        extra_headers: {},
      },
    };
  }
  if (!isPlainObject(raw)) {
    return { ok: false, error: 'Field "ingress" must be an object.' };
  }

  let peer_ip = '198.51.100.42';
  if (raw.peer_ip !== undefined && raw.peer_ip !== null && raw.peer_ip !== '') {
    if (typeof raw.peer_ip !== 'string') {
      return { ok: false, error: 'Field "ingress.peer_ip" must be a string.' };
    }
    const candidate = stripControlChars(raw.peer_ip).trim();
    if (!SAFE_IP_OR_HOST_REGEX.test(candidate)) {
      return { ok: false, error: 'Field "ingress.peer_ip" contains invalid characters or length.' };
    }
    peer_ip = candidate;
  }

  let peer_port: number | null = null;
  if (raw.peer_port !== undefined && raw.peer_port !== null && raw.peer_port !== '') {
    const portRes = readBoundedInt(raw.peer_port, 'ingress.peer_port', 443, 1, 65535);
    if (!portRes.ok) return portRes;
    peer_port = portRes.data;
  }

  const originRes = readOptionalString(raw, 'origin_server', '', 255);
  if (!originRes.ok) return originRes;
  const authRes = readOptionalString(raw, 'auth_principal', '', 255);
  if (!authRes.ok) return authRes;
  const uaRes = readOptionalString(raw, 'user_agent', '', 255);
  if (!uaRes.ok) return uaRes;

  let protocol = 'https';
  if (raw.protocol !== undefined && raw.protocol !== null && raw.protocol !== '') {
    if (typeof raw.protocol !== 'string' || !SAFE_PROTOCOL_REGEX.test(raw.protocol.trim())) {
      return { ok: false, error: 'Field "ingress.protocol" must be a valid protocol identifier.' };
    }
    protocol = raw.protocol.trim().toLowerCase();
  }

  const extra_headers: Record<string, string> = {};
  if (raw.extra_headers !== undefined) {
    if (!isPlainObject(raw.extra_headers)) {
      return { ok: false, error: 'Field "ingress.extra_headers" must be an object.' };
    }
    const entries = Object.entries(raw.extra_headers);
    if (entries.length > 20) {
      return { ok: false, error: 'Field "ingress.extra_headers" may contain at most 20 entries.' };
    }
    for (const [k, v] of entries) {
      if (typeof v !== 'string') {
        return { ok: false, error: `Header "${k}" in "ingress.extra_headers" must be a string.` };
      }
      extra_headers[stripControlChars(k).slice(0, 64)] = stripControlChars(v).slice(0, 256);
    }
  }

  return {
    ok: true,
    data: {
      peer_ip,
      peer_port,
      origin_server: originRes.data.trim() || null,
      auth_principal: authRes.data.trim() || null,
      user_agent: uaRes.data.trim() || null,
      protocol,
      extra_headers,
    },
  };
}

export interface ValidatedEvaluateInput {
  agent_id: string;
  session_id: string;
  trace_id: string;
  user_goal: string;
  phase: ActionPhase;
  source_trust: SourceTrust;
  provenance_tag: ProvenanceTag;
  trigger_source: TriggerSource;
  tool_name: string;
  target_resource: string;
  record_count: number;
  prior_tools: string[];
  raw_payload: string;
  ingress: IngressProvenance;
}

export function validateEvaluatePayload(body: unknown): ValidationResult<ValidatedEvaluateInput> {
  if (!isPlainObject(body)) {
    return { ok: false, error: 'Request body must be a JSON object.' };
  }

  const agentRes = readOptionalString(body, 'agent_id', 'agent-triage-01', 64);
  if (!agentRes.ok) return agentRes;
  const agent_id = agentRes.data.trim() || 'agent-triage-01';
  if (!SAFE_AGENT_ID_REGEX.test(agent_id)) {
    return { ok: false, error: 'Field "agent_id" must be 2-64 alphanumeric/._- characters.' };
  }

  const goalRes = readRequiredString(body, 'user_goal', 1, 2000);
  if (!goalRes.ok) return goalRes;

  const toolRes = readRequiredString(body, 'tool_name', 1, 64);
  if (!toolRes.ok) return toolRes;
  if (!SAFE_TOOL_REGEX.test(toolRes.data)) {
    return { ok: false, error: 'Field "tool_name" contains invalid characters.' };
  }

  const phaseRaw = body.phase ?? 'tool_call';
  if (typeof phaseRaw !== 'string' || !VALID_PHASES.has(phaseRaw as ActionPhase)) {
    return { ok: false, error: 'Field "phase" must be a valid execution phase.' };
  }

  const trustRaw = body.source_trust ?? 'untrusted_external';
  if (typeof trustRaw !== 'string' || !VALID_TRUST.has(trustRaw as SourceTrust)) {
    return { ok: false, error: 'Field "source_trust" must be trusted, untrusted_external, or mixed.' };
  }

  const provRaw = body.provenance_tag ?? 'TOOL_RESULT';
  if (typeof provRaw !== 'string' || !VALID_PROVENANCE.has(provRaw as ProvenanceTag)) {
    return { ok: false, error: 'Field "provenance_tag" must be a supported provenance tag.' };
  }

  const trigRaw = body.trigger_source ?? 'tool_output';
  if (typeof trigRaw !== 'string' || !VALID_TRIGGERS.has(trigRaw as TriggerSource)) {
    return { ok: false, error: 'Field "trigger_source" must be a supported trigger source.' };
  }

  const targetRes = readOptionalString(body, 'target_resource', '/workspace', 512);
  if (!targetRes.ok) return targetRes;

  const recordRes = readBoundedInt(body.record_count, 'record_count', 1, 0, 100000);
  if (!recordRes.ok) return recordRes;

  let prior_tools: string[] = [];
  if (body.prior_tools !== undefined) {
    if (!Array.isArray(body.prior_tools)) {
      return { ok: false, error: 'Field "prior_tools" must be an array of strings.' };
    }
    if (body.prior_tools.length > 20) {
      return { ok: false, error: 'Field "prior_tools" may contain at most 20 items.' };
    }
    for (const item of body.prior_tools) {
      if (typeof item !== 'string' || !SAFE_TOOL_REGEX.test(item.trim())) {
        return { ok: false, error: 'Each entry in "prior_tools" must be a valid tool name.' };
      }
      prior_tools.push(item.trim());
    }
  }

  const payloadRes = readOptionalString(body, 'raw_payload', '', 16000);
  if (!payloadRes.ok) return payloadRes;

  const sessionRes = readOptionalString(
    body,
    'session_id',
    `sess-${Date.now().toString(36)}`,
    64,
  );
  if (!sessionRes.ok) return sessionRes;
  const session_id = sessionRes.data.trim() || `sess-${Date.now().toString(36)}`;
  if (!SAFE_ID_REGEX.test(session_id)) {
    return { ok: false, error: 'Field "session_id" must match [a-zA-Z0-9_-]{4,64}.' };
  }

  const traceRes = readOptionalString(
    body,
    'trace_id',
    `trace-${Math.random().toString(36).slice(2, 10)}`,
    64,
  );
  if (!traceRes.ok) return traceRes;
  const trace_id = traceRes.data.trim() || `trace-${Math.random().toString(36).slice(2, 10)}`;
  if (!SAFE_ID_REGEX.test(trace_id)) {
    return { ok: false, error: 'Field "trace_id" must match [a-zA-Z0-9_-]{4,64}.' };
  }

  const ingressRes = validateIngressPayload(body.ingress);
  if (!ingressRes.ok) return ingressRes;

  return {
    ok: true,
    data: {
      agent_id,
      session_id,
      trace_id,
      user_goal: goalRes.data,
      phase: phaseRaw as ActionPhase,
      source_trust: trustRaw as SourceTrust,
      provenance_tag: provRaw as ProvenanceTag,
      trigger_source: trigRaw as TriggerSource,
      tool_name: toolRes.data,
      target_resource: targetRes.data.trim() || '/workspace',
      record_count: recordRes.data,
      prior_tools,
      raw_payload: payloadRes.data,
      ingress: ingressRes.data,
    },
  };
}

export interface ValidatedQuarantineResolveInput {
  action: 'approve_once' | 'revoke' | 'route_to_trap';
  note: string;
  agent_code: string;
}

export function validateQuarantineResolvePayload(
  body: unknown,
): ValidationResult<ValidatedQuarantineResolveInput> {
  if (!isPlainObject(body)) {
    return { ok: false, error: 'Request body must be a JSON object.' };
  }
  const action = body.action;
  if (action !== 'approve_once' && action !== 'revoke' && action !== 'route_to_trap') {
    return {
      ok: false,
      error: 'Field "action" must be approve_once, revoke, or route_to_trap.',
    };
  }
  const noteRes = readOptionalString(body, 'note', '', 500);
  if (!noteRes.ok) return noteRes;
  const codeRes = readOptionalString(body, 'agent_code', '', 16000);
  if (!codeRes.ok) return codeRes;

  return {
    ok: true,
    data: {
      action,
      note: noteRes.data.trim(),
      agent_code: codeRes.data,
    },
  };
}

export interface ValidatedSandboxInput {
  agent_id: string;
  reason: string;
  prompt: string;
  agent_code: string;
  ingress: IngressProvenance;
  policy: Partial<SandboxPolicy>;
}

export function validateSandboxPayload(
  body: unknown,
  defaultPolicy: SandboxPolicy,
): ValidationResult<ValidatedSandboxInput> {
  if (!isPlainObject(body)) {
    return { ok: false, error: 'Request body must be a JSON object.' };
  }

  const agentRes = readOptionalString(body, 'agent_id', 'agent-devops-02', 64);
  if (!agentRes.ok) return agentRes;
  const agent_id = agentRes.data.trim() || 'agent-devops-02';
  if (!SAFE_AGENT_ID_REGEX.test(agent_id)) {
    return { ok: false, error: 'Field "agent_id" must be 2-64 alphanumeric/._- characters.' };
  }

  const reasonRes = readOptionalString(body, 'reason', 'manual_trap_investigation', 256);
  if (!reasonRes.ok) return reasonRes;
  const promptRes = readOptionalString(body, 'prompt', '', 4000);
  if (!promptRes.ok) return promptRes;
  const codeRes = readOptionalString(body, 'agent_code', '', 24000);
  if (!codeRes.ok) return codeRes;

  if (!promptRes.data.trim() && !codeRes.data.trim()) {
    return { ok: false, error: 'Provide either "prompt" or "agent_code" to run in the trap sandbox.' };
  }

  const ingressRes = validateIngressPayload(body.ingress);
  if (!ingressRes.ok) return ingressRes;

  const rawPolicy = body.policy === undefined ? {} : body.policy;
  if (!isPlainObject(rawPolicy)) {
    return { ok: false, error: 'Field "policy" must be an object when provided.' };
  }

  const runtimeVal = rawPolicy.runtime ?? defaultPolicy.runtime;
  if (typeof runtimeVal !== 'string' || !VALID_RUNTIMES.has(runtimeVal as SandboxRuntime)) {
    return { ok: false, error: 'Field "policy.runtime" must be gvisor-runsc, firecracker-microvm, or docker-runc.' };
  }

  const cpuQuotaVal = rawPolicy.cpu_quota ?? defaultPolicy.cpu_quota;
  if (
    typeof cpuQuotaVal !== 'string' ||
    !SAFE_CPU_QUOTA_REGEX.test(cpuQuotaVal.trim()) ||
    Number(cpuQuotaVal) <= 0 ||
    Number(cpuQuotaVal) > 8
  ) {
    return { ok: false, error: 'Field "policy.cpu_quota" must be a numeric quota between 0.01 and 8.' };
  }

  const memVal = rawPolicy.memory_limit ?? defaultPolicy.memory_limit;
  if (typeof memVal !== 'string' || !SAFE_MEMORY_LIMIT_REGEX.test(memVal.trim())) {
    return { ok: false, error: 'Field "policy.memory_limit" must specify a size with unit (e.g. 256m, 1g).' };
  }

  const pidsRes = readBoundedInt(rawPolicy.pids_limit, 'policy.pids_limit', defaultPolicy.pids_limit, 8, 1024);
  if (!pidsRes.ok) return pidsRes;

  const timeoutRes = readBoundedInt(
    rawPolicy.timeout_seconds,
    'policy.timeout_seconds',
    defaultPolicy.timeout_seconds,
    1,
    120,
  );
  if (!timeoutRes.ok) return timeoutRes;

  const imageVal = rawPolicy.image ?? defaultPolicy.image;
  if (
    typeof imageVal !== 'string' ||
    !SAFE_IMAGE_REGEX.test(imageVal.trim()) ||
    /^\d+$/.test(imageVal.trim())
  ) {
    return { ok: false, error: 'Field "policy.image" must be a valid container image reference.' };
  }

  for (const boolKey of [
    'enable_decoy_workspace',
    'seccomp_enabled',
    'strip_env_secrets',
    'host_firewall_drop_imds',
  ] as const) {
    if (rawPolicy[boolKey] !== undefined && typeof rawPolicy[boolKey] !== 'boolean') {
      return { ok: false, error: `Field "policy.${boolKey}" must be a boolean.` };
    }
  }

  return {
    ok: true,
    data: {
      agent_id,
      reason: reasonRes.data.trim() || 'manual_trap_investigation',
      prompt: promptRes.data,
      agent_code: codeRes.data,
      ingress: ingressRes.data,
      policy: {
        runtime: runtimeVal as SandboxRuntime,
        cpu_quota: cpuQuotaVal.trim(),
        memory_limit: memVal.trim().toLowerCase(),
        pids_limit: pidsRes.data,
        timeout_seconds: timeoutRes.data,
        image: imageVal.trim(),
        enable_decoy_workspace:
          typeof rawPolicy.enable_decoy_workspace === 'boolean'
            ? rawPolicy.enable_decoy_workspace
            : true,
        seccomp_enabled:
          typeof rawPolicy.seccomp_enabled === 'boolean' ? rawPolicy.seccomp_enabled : true,
        strip_env_secrets:
          typeof rawPolicy.strip_env_secrets === 'boolean' ? rawPolicy.strip_env_secrets : true,
        host_firewall_drop_imds:
          typeof rawPolicy.host_firewall_drop_imds === 'boolean'
            ? rawPolicy.host_firewall_drop_imds
            : true,
      },
    },
  };
}

export interface ValidatedAttributionInput {
  session_id: string;
  ingress: IngressProvenance;
  observed_texts: string[];
  blocked_network_attempts: BlockedNetworkAttempt[];
}

export function validateAttributionPayload(
  body: unknown,
): ValidationResult<ValidatedAttributionInput> {
  if (!isPlainObject(body)) {
    return { ok: false, error: 'Request body must be a JSON object.' };
  }

  const sessionRes = readOptionalString(
    body,
    'session_id',
    `attr-${Date.now().toString(36)}`,
    64,
  );
  if (!sessionRes.ok) return sessionRes;
  const session_id = sessionRes.data.trim() || `attr-${Date.now().toString(36)}`;
  if (!SAFE_ID_REGEX.test(session_id)) {
    return { ok: false, error: 'Field "session_id" must match [a-zA-Z0-9_-]{4,64}.' };
  }

  const ingressRes = validateIngressPayload(body.ingress);
  if (!ingressRes.ok) return ingressRes;

  let observed_texts: string[] = [];
  if (body.observed_texts !== undefined) {
    if (!Array.isArray(body.observed_texts)) {
      return { ok: false, error: 'Field "observed_texts" must be an array of strings.' };
    }
    if (body.observed_texts.length > 20) {
      return { ok: false, error: 'Field "observed_texts" may contain at most 20 items.' };
    }
    for (const item of body.observed_texts) {
      if (typeof item !== 'string') {
        return { ok: false, error: 'Each entry in "observed_texts" must be a string.' };
      }
      observed_texts.push(stripControlChars(item).slice(0, 8000));
    }
  } else if (body.text !== undefined) {
    if (typeof body.text !== 'string') {
      return { ok: false, error: 'Field "text" must be a string.' };
    }
    observed_texts = [stripControlChars(body.text).slice(0, 16000)];
  }

  if (observed_texts.every((t) => t.trim().length === 0)) {
    return { ok: false, error: 'Provide non-empty artifact text in "observed_texts" for attribution analysis.' };
  }

  const blocked_network_attempts: BlockedNetworkAttempt[] = [];
  if (body.blocked_network_attempts !== undefined) {
    if (!Array.isArray(body.blocked_network_attempts)) {
      return { ok: false, error: 'Field "blocked_network_attempts" must be an array.' };
    }
    if (body.blocked_network_attempts.length > 20) {
      return { ok: false, error: 'Field "blocked_network_attempts" may contain at most 20 items.' };
    }
    for (const attempt of body.blocked_network_attempts) {
      if (!isPlainObject(attempt)) {
        return { ok: false, error: 'Each blocked network attempt must be an object.' };
      }
      blocked_network_attempts.push({
        type:
          typeof attempt.type === 'string'
            ? stripControlChars(attempt.type).slice(0, 64)
            : 'blocked_url_reference',
        target_url:
          typeof attempt.target_url === 'string'
            ? stripControlChars(attempt.target_url).slice(0, 512)
            : undefined,
        target_host:
          typeof attempt.target_host === 'string'
            ? stripControlChars(attempt.target_host).slice(0, 255)
            : undefined,
        reason:
          typeof attempt.reason === 'string'
            ? stripControlChars(attempt.reason).slice(0, 256)
            : 'Blocked by --network=none',
      });
    }
  }

  return {
    ok: true,
    data: {
      session_id,
      ingress: ingressRes.data,
      observed_texts,
      blocked_network_attempts,
    },
  };
}

export interface ValidatedSemanticAuditInput {
  user_goal: string;
  tool_name: string;
  target_resource: string;
  provenance_tag: ProvenanceTag;
  source_trust: SourceTrust;
  raw_payload: string;
}

export function validateSemanticAuditPayload(
  body: unknown,
  maxInputChars: number,
): ValidationResult<ValidatedSemanticAuditInput> {
  if (!isPlainObject(body)) {
    return { ok: false, error: 'Request body must be a JSON object.' };
  }

  const goalRes = readRequiredString(body, 'user_goal', 1, 500);
  if (!goalRes.ok) return goalRes;

  const toolRes = readRequiredString(body, 'tool_name', 1, 64);
  if (!toolRes.ok) return toolRes;
  if (!SAFE_TOOL_REGEX.test(toolRes.data)) {
    return { ok: false, error: 'Field "tool_name" contains invalid characters.' };
  }

  const provRaw = body.provenance_tag ?? 'TOOL_RESULT';
  if (typeof provRaw !== 'string' || !VALID_PROVENANCE.has(provRaw as ProvenanceTag)) {
    return { ok: false, error: 'Field "provenance_tag" must be a supported provenance tag.' };
  }

  const trustRaw = body.source_trust ?? 'untrusted_external';
  if (typeof trustRaw !== 'string' || !VALID_TRUST.has(trustRaw as SourceTrust)) {
    return { ok: false, error: 'Field "source_trust" must be trusted, untrusted_external, or mixed.' };
  }

  const targetRes = readOptionalString(body, 'target_resource', '', 256);
  if (!targetRes.ok) return targetRes;

  const payloadRes = readOptionalString(body, 'raw_payload', '', maxInputChars);
  if (!payloadRes.ok) return payloadRes;

  return {
    ok: true,
    data: {
      user_goal: goalRes.data,
      tool_name: toolRes.data,
      target_resource: targetRes.data.trim(),
      provenance_tag: provRaw as ProvenanceTag,
      source_trust: trustRaw as SourceTrust,
      raw_payload: payloadRes.data,
    },
  };
}

export interface ValidatedModelAuditFields {
  intent_divergence_score: number;
  hidden_directive_detected: boolean;
  classification: SemanticAuditResult['classification'];
  rationale: string;
}

export function validateStructuredModelOutput(
  rawText: string,
): ValidationResult<ValidatedModelAuditFields> {
  const cleanedText = rawText
    .trim()
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();

  if (!cleanedText) {
    return { ok: false, error: 'Model returned an empty response.' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(cleanedText);
  } catch {
    return { ok: false, error: 'Model output was not valid JSON.' };
  }

  if (!isPlainObject(parsed)) {
    return { ok: false, error: 'Model output must be a JSON object.' };
  }

  const score = parsed.intent_divergence_score;
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 1) {
    return {
      ok: false,
      error: 'Model output field "intent_divergence_score" must be a finite number between 0 and 1.',
    };
  }

  if (typeof parsed.hidden_directive_detected !== 'boolean') {
    return {
      ok: false,
      error: 'Model output field "hidden_directive_detected" must be a boolean.',
    };
  }

  if (
    typeof parsed.classification !== 'string' ||
    !VALID_CLASSIFICATIONS.has(parsed.classification as SemanticAuditResult['classification'])
  ) {
    return {
      ok: false,
      error: 'Model output field "classification" must be ALIGNED, SUSPICIOUS_DRIFT, or HIJACKED_INTENT.',
    };
  }

  if (typeof parsed.rationale !== 'string') {
    return { ok: false, error: 'Model output field "rationale" must be a string.' };
  }
  const cleanRationale = stripControlChars(parsed.rationale).trim().slice(0, 500);
  if (!cleanRationale) {
    return { ok: false, error: 'Model output field "rationale" must not be empty.' };
  }

  return {
    ok: true,
    data: {
      intent_divergence_score: Number(score.toFixed(2)),
      hidden_directive_detected: parsed.hidden_directive_detected,
      classification: parsed.classification as SemanticAuditResult['classification'],
      rationale: cleanRationale,
    },
  };
}

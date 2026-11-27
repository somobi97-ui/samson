import { appConfig } from '../config/appConfig';
import type {
  ActionGateEvaluation,
  ActionPhase,
  AgentBaseline,
  AttributionFinding,
  HarnessScenario,
  HarnessTestResult,
  IngressProvenance,
  ProvenanceTag,
  PublicRuntimeConfig,
  QuarantineQueueItem,
  SandboxPolicy,
  SemanticAuditResult,
  SourceTrust,
  TrapSessionRecord,
  TriggerSource,
} from '../types/security';

export interface PlatformStatePayload {
  baselines: AgentBaseline[];
  evaluations: ActionGateEvaluation[];
  quarantineQueue: QuarantineQueueItem[];
  trapSessions: TrapSessionRecord[];
  scenarios: HarnessScenario[];
  defaultPolicy: SandboxPolicy;
  runtimeConfig: PublicRuntimeConfig;
}

export interface EvaluateActionRequest {
  agent_id: string;
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

export interface SemanticAuditRequest {
  user_goal: string;
  tool_name: string;
  target_resource: string;
  provenance_tag: ProvenanceTag;
  source_trust: SourceTrust;
  raw_payload: string;
}

const VALID_CLASSIFICATIONS = new Set<SemanticAuditResult['classification']>([
  'ALIGNED',
  'SUSPICIOUS_DRIFT',
  'HIJACKED_INTENT',
]);

class ApiRequestError extends Error {
  status?: number;
  transient: boolean;

  constructor(message: string, status?: number, transient = false) {
    super(message);
    this.name = 'ApiRequestError';
    this.status = status;
    this.transient = transient;
  }
}

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return Boolean(val) && typeof val === 'object' && !Array.isArray(val);
}

function isTransientStatus(status: number): boolean {
  return status === 408 || status === 502 || status === 503 || status === 504;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toUserSafeMessage(err: unknown): string {
  if (err instanceof ApiRequestError) {
    return err.message;
  }
  if (err instanceof Error) {
    if (err.name === 'AbortError') {
      return 'The request timed out waiting for the server. Please try again.';
    }
    if (err instanceof TypeError) {
      return 'Unable to reach the security backend. Check your connection and try again.';
    }
    return err.message || 'An unexpected error occurred.';
  }
  return 'An unexpected error occurred. Please try again.';
}

async function requestJson<T>(
  url: string,
  init?: RequestInit,
  options?: { retryable?: boolean },
): Promise<T> {
  const retryable = options?.retryable ?? true;
  const maxAttempts = retryable ? 1 + appConfig.maxRetries : 1;
  let lastError: unknown;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), appConfig.requestTimeoutMs);

    try {
      const res = await fetch(url, {
        ...init,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...(init?.headers ?? {}),
        },
      });

      const contentType = res.headers.get('content-type') ?? '';
      if (!res.ok) {
        const errData = contentType.includes('application/json')
          ? await res.json().catch(() => ({}))
          : {};
        const serverMsg =
          errData &&
          typeof errData === 'object' &&
          'error' in errData &&
          typeof errData.error === 'string'
            ? errData.error
            : res.status >= 500
              ? 'The security service encountered a temporary upstream error. Please try again.'
              : `Request could not be completed (status ${res.status}).`;

        throw new ApiRequestError(serverMsg, res.status, isTransientStatus(res.status));
      }

      if (!contentType.includes('application/json')) {
        throw new ApiRequestError(
          'Received an unexpected non-JSON response from the security backend.',
          502,
          true,
        );
      }

      try {
        return (await res.json()) as T;
      } catch {
        throw new ApiRequestError(
          'Received malformed JSON data from the security backend.',
          502,
          true,
        );
      }
    } catch (err) {
      lastError = err;
      const isTimeoutOrNetwork =
        (err instanceof Error && (err.name === 'AbortError' || err instanceof TypeError)) ||
        (err instanceof ApiRequestError && err.transient);

      const canRetry = retryable && attempt < maxAttempts - 1 && isTimeoutOrNetwork;
      if (!canRetry) {
        throw new Error(toUserSafeMessage(err));
      }

      const jitterMs = Math.floor(Math.random() * 120);
      const backoffMs = appConfig.retryBaseDelayMs * Math.pow(2, attempt) + jitterMs;
      await sleep(backoffMs);
    } finally {
      clearTimeout(timeout);
    }
  }

  throw new Error(toUserSafeMessage(lastError));
}

async function downloadFile(url: string, filename: string): Promise<void> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), appConfig.requestTimeoutMs);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
    });

    if (!res.ok) {
      const contentType = res.headers.get('content-type') ?? '';
      const errData = contentType.includes('application/json')
        ? await res.json().catch(() => ({}))
        : {};
      const msg =
        errData && typeof errData === 'object' && 'error' in errData && typeof errData.error === 'string'
          ? errData.error
          : `Export could not be completed (status ${res.status}).`;
      throw new Error(msg);
    }

    const blob = await res.blob();
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
  } catch (err) {
    throw new Error(toUserSafeMessage(err));
  } finally {
    clearTimeout(timeout);
  }
}

function validatePlatformState(raw: unknown): PlatformStatePayload {
  if (
    !isPlainObject(raw) ||
    !Array.isArray(raw.baselines) ||
    !Array.isArray(raw.evaluations) ||
    !Array.isArray(raw.quarantineQueue) ||
    !Array.isArray(raw.trapSessions) ||
    !Array.isArray(raw.scenarios) ||
    !isPlainObject(raw.defaultPolicy) ||
    !isPlainObject(raw.runtimeConfig)
  ) {
    throw new Error('Security backend returned an incomplete state payload.');
  }
  return raw as unknown as PlatformStatePayload;
}

function validateSemanticAuditResponse(raw: unknown): { audit: SemanticAuditResult } {
  if (!isPlainObject(raw) || !isPlainObject(raw.audit)) {
    throw new Error('Semantic audit returned an unexpected response format.');
  }
  const a = raw.audit;
  if (
    typeof a.model_id !== 'string' ||
    typeof a.thinking_level !== 'string' ||
    typeof a.intent_divergence_score !== 'number' ||
    !Number.isFinite(a.intent_divergence_score) ||
    a.intent_divergence_score < 0 ||
    a.intent_divergence_score > 1 ||
    typeof a.hidden_directive_detected !== 'boolean' ||
    typeof a.classification !== 'string' ||
    !VALID_CLASSIFICATIONS.has(a.classification as SemanticAuditResult['classification']) ||
    typeof a.rationale !== 'string' ||
    a.rationale.trim().length === 0 ||
    typeof a.latency_ms !== 'number' ||
    !Number.isFinite(a.latency_ms)
  ) {
    throw new Error('Semantic audit output failed structured validation.');
  }
  return raw as unknown as { audit: SemanticAuditResult };
}

export const sentinelService = {
  async fetchState(): Promise<PlatformStatePayload> {
    const raw = await requestJson<unknown>(appConfig.endpoints.state);
    return validatePlatformState(raw);
  },

  fetchRuntimeConfig(): Promise<PublicRuntimeConfig> {
    return requestJson<PublicRuntimeConfig>(appConfig.endpoints.config);
  },

  async evaluateAction(
    payload: EvaluateActionRequest,
  ): Promise<{ evaluation: ActionGateEvaluation; queueItem: QuarantineQueueItem | null }> {
    const raw = await requestJson<unknown>(appConfig.endpoints.evaluate, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (!isPlainObject(raw) || !isPlainObject(raw.evaluation)) {
      throw new Error('Action boundary evaluator returned an unexpected response.');
    }
    return raw as { evaluation: ActionGateEvaluation; queueItem: QuarantineQueueItem | null };
  },

  async resolveQuarantine(
    id: string,
    action: 'route_to_trap' | 'approve_once' | 'revoke',
  ): Promise<{ item: QuarantineQueueItem; trapSession?: TrapSessionRecord }> {
    const raw = await requestJson<unknown>(
      appConfig.endpoints.quarantineResolve(id),
      {
        method: 'POST',
        body: JSON.stringify({ action }),
      },
      { retryable: false },
    );
    if (!isPlainObject(raw) || !isPlainObject(raw.item)) {
      throw new Error('Quarantine resolution returned an unexpected response.');
    }
    return raw as { item: QuarantineQueueItem; trapSession?: TrapSessionRecord };
  },

  async runSandbox(params: {
    agent_id: string;
    reason: string;
    prompt: string;
    agent_code: string;
    ingress: IngressProvenance;
    policy: SandboxPolicy;
  }): Promise<{ session: TrapSessionRecord }> {
    const raw = await requestJson<unknown>(appConfig.endpoints.sandboxRun, {
      method: 'POST',
      body: JSON.stringify(params),
    });
    if (!isPlainObject(raw) || !isPlainObject(raw.session)) {
      throw new Error('Trap sandbox returned an unexpected session payload.');
    }
    return raw as { session: TrapSessionRecord };
  },

  async analyzeAttribution(params: {
    session_id: string;
    ingress: IngressProvenance;
    observed_texts: string[];
  }): Promise<{ finding: AttributionFinding }> {
    const raw = await requestJson<unknown>(appConfig.endpoints.attributionAnalyze, {
      method: 'POST',
      body: JSON.stringify(params),
    });
    if (!isPlainObject(raw) || !isPlainObject(raw.finding)) {
      throw new Error('Attribution correlator returned an unexpected report payload.');
    }
    return raw as { finding: AttributionFinding };
  },

  async runHarness(): Promise<{ results: HarnessTestResult[] }> {
    const raw = await requestJson<unknown>(appConfig.endpoints.harnessRun, {
      method: 'POST',
    });
    if (!isPlainObject(raw) || !Array.isArray(raw.results)) {
      throw new Error('Regression harness returned an unexpected result set.');
    }
    return raw as { results: HarnessTestResult[] };
  },

  async runSemanticAudit(payload: SemanticAuditRequest): Promise<{ audit: SemanticAuditResult }> {
    const raw = await requestJson<unknown>(appConfig.endpoints.semanticAudit, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    return validateSemanticAuditResponse(raw);
  },

  downloadSessionTelemetry(sessionId: string): Promise<void> {
    return downloadFile(
      appConfig.endpoints.sessionTelemetry(sessionId),
      `${sessionId}_telemetry.jsonl`,
    );
  },

  downloadSessionAttribution(sessionId: string): Promise<void> {
    return downloadFile(
      appConfig.endpoints.sessionAttribution(sessionId),
      `${sessionId}_attribution_report.json`,
    );
  },
};

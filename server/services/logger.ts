import crypto from 'crypto';

export type LogLevel = 'info' | 'warn' | 'error';

export interface StructuredLogEntry {
  ts: string;
  level: LogLevel;
  event: string;
  requestId?: string;
  [key: string]: unknown;
}

const SAFE_EXACT_KEYS = new Set([
  'payload_hash',
  'hourlyTokenCap',
  'maxOutputTokens',
  'maxAiOutputTokens',
  'actualTotalTokens',
  'estimatedTokens',
  'tokenCount',
  'clientIpHash',
  'requestId',
  'session_id',
  'trace_id',
  'agent_id',
  'prompt_length',
]);

const SENSITIVE_KEY_PATTERN =
  /api.?key|secret|token|password|passcode|authorization|cookie|credential|raw_payload|agent_code|observed_text|user_goal|prompt|extra_headers|peer_ip|email/i;

const MAX_INCIDENTS = 50;
const recentIncidents: StructuredLogEntry[] = [];

export function hashIdentifier(raw: string | undefined | null): string {
  if (!raw) return 'unknown';
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 12);
}

export function scrubSecrets(input: string, maxLen = 300): string {
  return input
    .replace(/AIza[0-9A-Za-z_-]{10,}/g, '[REDACTED_API_KEY]')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED_TOKEN]')
    .replace(/sk-[A-Za-z0-9]{12,}/g, '[REDACTED_KEY]')
    .replace(/(GEMINI_API_KEY\s*=\s*)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/[\r\n]+/g, ' ')
    .slice(0, maxLen);
}

export function sanitizeForLog(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[TRUNCATED]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return scrubSecrets(value, 300);
  if (typeof value === 'number' || typeof value === 'boolean') return value;

  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeForLog(item, depth + 1));
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (!SAFE_EXACT_KEYS.has(k) && SENSITIVE_KEY_PATTERN.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = sanitizeForLog(v, depth + 1);
      }
    }
    return out;
  }

  return String(value);
}

function formatErrorMeta(err: unknown): Record<string, unknown> | undefined {
  if (!err) return undefined;
  if (err instanceof Error) {
    const extra = err as Error & { statusCode?: number; status?: number; code?: string };
    return {
      errorName: err.name,
      errorMessage: scrubSecrets(err.message, 240),
      ...(typeof extra.statusCode === 'number' ? { statusCode: extra.statusCode } : {}),
      ...(typeof extra.status === 'number' ? { status: extra.status } : {}),
      ...(typeof extra.code === 'string' ? { errorCode: extra.code } : {}),
    };
  }
  return { errorMessage: scrubSecrets(String(err), 240) };
}

function emit(level: LogLevel, event: string, meta?: Record<string, unknown>, err?: unknown): void {
  const sanitizedMeta = meta ? (sanitizeForLog(meta) as Record<string, unknown>) : {};
  const errorMeta = formatErrorMeta(err);
  const entry: StructuredLogEntry = {
    ts: new Date().toISOString(),
    level,
    event,
    ...sanitizedMeta,
    ...(errorMeta ?? {}),
  };

  if (level === 'error') {
    recentIncidents.unshift(entry);
    if (recentIncidents.length > MAX_INCIDENTS) {
      recentIncidents.length = MAX_INCIDENTS;
    }
  }

  if (process.env.LOG_SILENT === 'true') {
    return;
  }

  const line = JSON.stringify(entry);
  if (level === 'error') {
    console.error(line);
  } else if (level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export const logger = {
  info(event: string, meta?: Record<string, unknown>): void {
    emit('info', event, meta);
  },
  warn(event: string, meta?: Record<string, unknown>): void {
    emit('warn', event, meta);
  },
  error(event: string, meta?: Record<string, unknown>, err?: unknown): void {
    emit('error', event, meta, err);
  },
  getRecentIncidents(): StructuredLogEntry[] {
    return [...recentIncidents];
  },
  clearIncidents(): void {
    recentIncidents.length = 0;
  },
};

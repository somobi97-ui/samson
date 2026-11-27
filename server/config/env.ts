import { ThinkingLevel } from '@google/genai';
import type { SandboxPolicy, SandboxRuntime } from '../../src/types/security.ts';

function envString(key: string, fallback: string): string {
  const val = process.env[key];
  return typeof val === 'string' && val.trim().length > 0 ? val.trim() : fallback;
}

function envNumber(key: string, fallback: number, min: number, max: number): number {
  const raw = process.env[key];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function envFraction(key: string, fallback: number, min: number, max: number): number {
  const raw = process.env[key];
  if (raw === undefined || raw.trim() === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) return fallback;
  return parsed;
}

function parseSandboxRuntime(raw: string): SandboxRuntime {
  if (raw === 'firecracker-microvm' || raw === 'docker-runc' || raw === 'gvisor-runsc') {
    return raw;
  }
  return 'gvisor-runsc';
}

function parseThinkingLevel(raw: string): { level: ThinkingLevel; label: string } {
  const normalized = raw.trim().toUpperCase();
  if (normalized === 'MEDIUM') return { level: ThinkingLevel.MEDIUM, label: 'MEDIUM' };
  if (normalized === 'HIGH') return { level: ThinkingLevel.HIGH, label: 'HIGH' };
  return { level: ThinkingLevel.LOW, label: 'LOW' };
}

function parseModelId(raw: string, fallback: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return fallback;
  const alias = trimmed.toLowerCase();
  if (alias === 'gemini 4 hydrogen' || alias === 'gemini hydrogen' || alias === 'gemini flash' || alias === 'gemini 4 flash') {
    return 'gemini-4-hydrogen';
  }
  if (alias === 'gemini 4 neon' || alias === 'gemini neon' || alias === 'gemini 4') {
    return 'gemini-4-neon';
  }
  if (alias === 'gemini 4 carbon' || alias === 'gemini carbon') {
    return 'gemini-4-carbon';
  }
  if (/^[a-zA-Z0-9._-]+$/.test(trimmed) && !/^\d+$/.test(trimmed)) {
    return trimmed;
  }
  return fallback;
}

function parseMemoryLimit(raw: string, fallback: string): string {
  const trimmed = raw.trim();
  return /^\d+[kmg]$/i.test(trimmed) ? trimmed.toLowerCase() : fallback;
}

function parseCpuQuota(raw: string, fallback: string): string {
  const num = Number(raw.trim());
  if (!Number.isFinite(num) || num <= 0 || num > 8) return fallback;
  return String(num);
}

function parseContainerImage(raw: string, fallback: string): string {
  const trimmed = raw.trim();
  if (!trimmed || /^\d+$/.test(trimmed)) return fallback;
  return /^[a-zA-Z0-9._/-]+(:[a-zA-Z0-9._-]+)?$/.test(trimmed) ? trimmed : fallback;
}

function parseBodySize(raw: string, fallback: string): string {
  const trimmed = raw.trim();
  return /^\d+(?:kb|mb)$/i.test(trimmed) ? trimmed.toLowerCase() : fallback;
}

const parsedThinking = parseThinkingLevel(envString('GEMINI_THINKING_LEVEL', 'LOW'));

const defaultSandboxPolicy: SandboxPolicy = {
  cpu_quota: parseCpuQuota(envString('SANDBOX_CPU_QUOTA', '0.5'), '0.5'),
  memory_limit: parseMemoryLimit(envString('SANDBOX_MEMORY_LIMIT', '256m'), '256m'),
  pids_limit: envNumber('SANDBOX_PIDS_LIMIT', 64, 8, 1024),
  timeout_seconds: envNumber('SANDBOX_TIMEOUT_SECONDS', 15, 1, 120),
  image: parseContainerImage(envString('SANDBOX_IMAGE', 'python:3.12-slim'), 'python:3.12-slim'),
  enable_decoy_workspace: true,
  runtime: parseSandboxRuntime(envString('SANDBOX_RUNTIME', 'gvisor-runsc')),
  seccomp_enabled: true,
  strip_env_secrets: true,
  host_firewall_drop_imds: true,
};

export const serverConfig = {
  port: envNumber('PORT', 3000, 1, 65535),
  limits: {
    rateWindowMs: envNumber('RATE_LIMIT_WINDOW_MS', 60_000, 5_000, 3_600_000),
    generalMax: envNumber('RATE_LIMIT_GENERAL_MAX', 120, 10, 5000),
    mutationMax: envNumber('RATE_LIMIT_MUTATION_MAX', 40, 5, 1000),
    aiMax: envNumber('RATE_LIMIT_AI_MAX', 10, 1, 200),
    maxDefaultBodySize: parseBodySize(envString('MAX_DEFAULT_BODY_SIZE', '64kb'), '64kb'),
    maxAiBodySize: parseBodySize(envString('MAX_AI_BODY_SIZE', '32kb'), '32kb'),
    maxSandboxBodySize: parseBodySize(envString('MAX_SANDBOX_BODY_SIZE', '64kb'), '64kb'),
    maxStoredRecords: envNumber('MAX_STORED_RECORDS', 200, 20, 2000),
  },
  ai: {
    intentModel: parseModelId(envString('GEMINI_INTENT_MODEL', 'gemini-4-hydrogen'), 'gemini-4-hydrogen'),
    thinkingLevel: parsedThinking.level,
    thinkingLevelLabel: parsedThinking.label,
    maxOutputTokens: envNumber('AI_MAX_OUTPUT_TOKENS', 512, 64, 2048),
    maxInputChars: envNumber('AI_MAX_INPUT_CHARS', 3500, 500, 12000),
    hourlyTokenCap: envNumber('AI_HOURLY_TOKEN_CAP', 50000, 1000, 1000000),
    requestTimeoutMs: envNumber('AI_REQUEST_TIMEOUT_MS', 12000, 2000, 60000),
    maxRetries: envNumber('AI_MAX_RETRIES', 2, 0, 3),
    retryBaseDelayMs: envNumber('AI_RETRY_BASE_DELAY_MS', 400, 100, 5000),
  },
  sandbox: {
    defaultPolicy: defaultSandboxPolicy,
    imdsHost: envString('SANDBOX_IMDS_HOST', '169.254.169.254'),
  },
  detector: {
    trapThreshold: envFraction('DETECTOR_TRAP_THRESHOLD', 0.35, 0.05, 0.95),
    blockThreshold: envFraction('DETECTOR_BLOCK_THRESHOLD', 0.72, 0.2, 0.99),
    classifierPatternWeight: envFraction('DETECTOR_PATTERN_WEIGHT', 0.35, 0.1, 1.0),
  },
};

export function getPublicRuntimeConfig() {
  return {
    intentModel: serverConfig.ai.intentModel,
    thinkingLevel: serverConfig.ai.thinkingLevelLabel,
    aiConfigured: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim().length > 0),
    detectorThresholds: {
      trapThreshold: serverConfig.detector.trapThreshold,
      blockThreshold: serverConfig.detector.blockThreshold,
    },
    defaultPolicy: serverConfig.sandbox.defaultPolicy,
    imdsHost: serverConfig.sandbox.imdsHost,
    limits: {
      aiMaxPerMinute: serverConfig.limits.aiMax,
      mutationMaxPerMinute: serverConfig.limits.mutationMax,
      maxAiInputChars: serverConfig.ai.maxInputChars,
      maxAiOutputTokens: serverConfig.ai.maxOutputTokens,
      hourlyTokenCap: serverConfig.ai.hourlyTokenCap,
    },
  };
}

import type { SandboxRuntime } from '../types/security';

const rawApiBase = import.meta.env.VITE_API_BASE_URL;
const trimmedApiBase =
  typeof rawApiBase === 'string' ? rawApiBase.trim().replace(/\/+$/, '') : '';
const isValidApiBase =
  trimmedApiBase.startsWith('/') ||
  trimmedApiBase.startsWith('http://') ||
  trimmedApiBase.startsWith('https://');
const apiBase = isValidApiBase && trimmedApiBase.length > 0 ? trimmedApiBase : '/api';

const rawTimeout = Number(import.meta.env.VITE_REQUEST_TIMEOUT_MS);
const requestTimeoutMs =
  Number.isFinite(rawTimeout) && rawTimeout >= 1000 ? rawTimeout : 25000;

const rawMaxRetries = Number(import.meta.env.VITE_MAX_RETRIES);
const maxRetries =
  Number.isFinite(rawMaxRetries) && rawMaxRetries >= 0 && rawMaxRetries <= 3
    ? Math.floor(rawMaxRetries)
    : 2;

const rawRetryBaseMs = Number(import.meta.env.VITE_RETRY_BASE_DELAY_MS);
const retryBaseDelayMs =
  Number.isFinite(rawRetryBaseMs) && rawRetryBaseMs >= 100 && rawRetryBaseMs <= 5000
    ? Math.floor(rawRetryBaseMs)
    : 400;

export const appConfig = {
  apiBase,
  requestTimeoutMs,
  maxRetries,
  retryBaseDelayMs,
  endpoints: {
    config: `${apiBase}/config`,
    state: `${apiBase}/state`,
    evaluate: `${apiBase}/evaluate`,
    quarantineResolve: (id: string) =>
      `${apiBase}/quarantine/${encodeURIComponent(id)}/resolve`,
    sandboxRun: `${apiBase}/sandbox/run`,
    attributionAnalyze: `${apiBase}/attribution/analyze`,
    harnessRun: `${apiBase}/harness/run`,
    semanticAudit: `${apiBase}/semantic-audit`,
    sessionTelemetry: (id: string) =>
      `${apiBase}/sessions/${encodeURIComponent(id)}/telemetry.jsonl`,
    sessionAttribution: (id: string) =>
      `${apiBase}/sessions/${encodeURIComponent(id)}/attribution.json`,
  },
  sandboxRuntimes: [
    { value: 'gvisor-runsc' as SandboxRuntime, label: 'gVisor (--runtime=runsc)' },
    { value: 'firecracker-microvm' as SandboxRuntime, label: 'Firecracker MicroVM (kata-fc)' },
    { value: 'docker-runc' as SandboxRuntime, label: 'Hardened Container (runc)' },
  ],
} as const;
